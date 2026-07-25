import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:at_cli_commons/at_cli_commons.dart';
import 'package:at_client/at_client.dart' show AtClient;
import 'package:at_client/src/secret_sharing/at_client_secret_sharing.dart';
import 'package:at_client/src/secret_sharing/enrollment_directory.dart';
import 'package:at_client/src/secret_sharing/key_package.dart';
import 'package:at_client/src/secret_sharing/key_package_registration.dart'
    show PersistedApkamKeys;
import 'package:at_client/src/secret_sharing/secret_store.dart';

/// The one application namespace every script in this demo uses. Change it
/// if you want to run a second, independent demo "app" against the same
/// atSign without its secrets crossing over with this one.
const String demoNamespace = 'jeremy.secretsharingdemo';

/// Where this demo keeps everything it needs to remember between runs of the
/// atomic bin/*.dart scripts: device identities, received secrets, and the
/// local stand-in for `enroll:listns` (see [FileEnrollmentDirectory]).
/// Never touches your real atServer storage - safe to delete any time
/// (see bin/99_reset_demo_state.dart).
Directory demoStateDir() => Directory('.demo_state');

File sharedDirectoryFile() => File('${demoStateDir().path}/directory.json');

/// Everything a bin/*.dart script needs after parsing its command line.
class DemoContext {
  final AtClient atClient;
  final String label;
  final Directory stateDir;
  final ArgResults args;

  DemoContext({
    required this.atClient,
    required this.label,
    required this.stateDir,
    required this.args,
  });
}

/// Builds the shared CLIBase parser (--atsign, --key-file, --root-server,
/// etc, all from at_cli_commons) plus the one option every script here adds:
/// --label, this process's short local name for "which device am I".
///
/// Two different --label values run against the *same* --atsign simulate
/// two devices (two separate APKAM keypairs / enrollments) of one atSign -
/// see the README for why this demo does that instead of enrolling a real
/// second device.
ArgParser demoArgParser({void Function(ArgParser parser)? extend}) {
  final parser = CLIBase.createArgsParser(
    namespace: demoNamespace,
    hide: CLIBase.hideableArgs,
  )..addOption(
      'label',
      abbr: 'L',
      mandatory: true,
      help: 'A short local name for this "device" (e.g. device-a, '
          'device-b). Reused across scripts to keep this device\'s '
          'identity (its X-Wing enc keypair / kpid) stable.',
    );
  extend?.call(parser);
  return parser;
}

/// Parses [args] with [parser] (or a fresh [demoArgParser] if none given),
/// connects to the real atServer for `--atsign`, and returns the resulting
/// [DemoContext]. Exits the process on a parse error or `--help`, matching
/// the at_client example scripts' own convention.
Future<DemoContext> bootstrap(List<String> args, {ArgParser? parser}) async {
  parser ??= demoArgParser();
  ArgResults parsed;
  try {
    parsed = parser.parse(args);
  } catch (e) {
    stderr.writeln(parser.usage);
    stderr.writeln(e);
    exit(1);
  }
  if (parsed['help'] == true) {
    print(parser.usage);
    exit(0);
  }

  final label = parsed['label'] as String;
  final rawAtsign = (parsed['atsign'] as String).toLowerCase();
  final atsignNorm = rawAtsign.startsWith('@') ? rawAtsign : '@$rawAtsign';
  final stateDir = Directory('${demoStateDir().path}/${atsignNorm}__$label')
    ..createSync(recursive: true);

  // at_cli_commons' default local storage path is keyed only by atsign +
  // namespace (see standardAtClientStoragePath) - it has no idea about
  // --label. Two --labels for the same --atsign would otherwise fight over
  // the same Hive lock file (this bit us running the two-terminal pull demo
  // - see 07_request_secret.dart). Give each --label its own storage dir
  // unless the caller already passed one explicitly.
  var cliArgs = args;
  if (!parsed.wasParsed('storage-dir')) {
    cliArgs = [...args, '--storage-dir', '${stateDir.path}/atclient_storage'];
  }
  final cliBase = await CLIBase.fromCommandLineArgs(cliArgs, parser: parser);

  return DemoContext(
    atClient: cliBase.atClient,
    label: label,
    stateDir: stateDir,
    args: parsed,
  );
}

/// This "device"'s persisted X-Wing enc keypair, so its kpid (mailbox
/// address) stays the same across separate atomic script runs instead of a
/// fresh keypair being minted every time (the mixin's `loadApkamKeys` /
/// `saveApkamKeys` callbacks it's wired to below).
class FileApkamKeys {
  final File _file;
  FileApkamKeys(this._file);

  Future<PersistedApkamKeys?> load() async {
    if (!_file.existsSync()) return null;
    final raw = jsonDecode(_file.readAsStringSync()) as Map;
    return PersistedApkamKeys(xWingSeed: raw['xWingSeed'] as String);
  }

  Future<void> save(PersistedApkamKeys keys) async {
    _file.parent.createSync(recursive: true);
    _file.writeAsStringSync(jsonEncode({'xWingSeed': keys.xWingSeed}));
  }
}

/// This "device"'s `SecretStore` contents, persisted to a local file so a
/// secret received by one script run is still there when a later script
/// (e.g. 06_push_to_namespace.dart) reads it back.
class FileSecretStorePersistence implements SecretStorePersistence {
  final File _file;
  FileSecretStorePersistence(this._file);

  @override
  Future<List<Secret>> load() async {
    if (!_file.existsSync()) return [];
    final raw = _file.readAsStringSync().trim();
    if (raw.isEmpty) return [];
    return (jsonDecode(raw) as List).map(Secret.fromJson).toList();
  }

  @override
  Future<void> save(List<Secret> secrets) async {
    _file.parent.createSync(recursive: true);
    _file.writeAsStringSync(JsonEncoder.withIndent('  ')
        .convert(secrets.map((s) => s.toJson()).toList()));
  }
}

/// Stand-in for the atServer's `enroll:listns` verb, which does not exist
/// server-side yet (the real `VerbEnrollmentDirectory` in the SDK is gated
/// behind that verb).
///
/// This keeps the same wire shape `enroll:listns` will eventually return -
/// a flat list of {enrollmentId, access, apkamPubKey, metadata.keyPackage} -
/// in a local JSON file that every 03_register_device.dart run appends an
/// entry to, and every send/push/request script reads back. Swap this for
/// `VerbEnrollmentDirectory` once the verb ships server-side; nothing else
/// in this demo would need to change.
///
/// One wrinkle specific to this demo: entries are keyed by kpid, not
/// enrollmentId, because two --labels here may share one real enrollment
/// (see [DemoContext.label]) - in production each is a separate enrollment.
/// Each entry also carries a `demoLabel` field purely so scripts can address
/// a peer by --label; that field is NOT part of the real enroll:listns wire
/// shape, just a local convenience.
class FileEnrollmentDirectory implements EnrollmentDirectory {
  final File _file;
  FileEnrollmentDirectory(this._file);

  List<Map<String, dynamic>> _readAll() {
    if (!_file.existsSync()) return [];
    final raw = _file.readAsStringSync().trim();
    if (raw.isEmpty) return [];
    return (jsonDecode(raw) as List).cast<Map<String, dynamic>>();
  }

  void _writeAll(List<Map<String, dynamic>> entries) {
    _file.parent.createSync(recursive: true);
    _file.writeAsStringSync(JsonEncoder.withIndent('  ').convert(entries));
  }

  /// Upserts [keyPackage] (keyed by its kpid) into the shared directory file
  /// under the given [demoLabel].
  void registerSelf(
    KeyPackage keyPackage, {
    required String demoLabel,
    String access = 'rw',
  }) {
    final entries = _readAll()
      ..removeWhere((e) => e['kpid'] == keyPackage.kpid);
    entries.add({
      'kpid': keyPackage.kpid,
      'demoLabel': demoLabel,
      'enrollmentId': keyPackage.enrollmentId,
      'access': access,
      'apkamPubKey': keyPackage.apkamId,
      'metadata': {'keyPackage': keyPackage.toJson()},
    });
    _writeAll(entries);
  }

  /// Looks up a previously-[registerSelf]'d device by its --label.
  KeyPackage? keyPackageForLabel(String demoLabel) {
    for (final e in _readAll()) {
      if (e['demoLabel'] != demoLabel) continue;
      final pkg = (e['metadata'] as Map?)?['keyPackage'];
      if (pkg == null) return null;
      return KeyPackage.fromPayload(
        pkg,
        enrollmentId: e['enrollmentId'] as String,
        apkamId: e['apkamPubKey'] as String?,
      );
    }
    return null;
  }

  @override
  Future<List<NamespaceMember>> listForNamespace(
    String namespace, {
    Set<String> excludeEnrollmentIds = const {},
  }) async {
    final members = <NamespaceMember>[];
    for (final e in _readAll()) {
      final enrollmentId = e['enrollmentId'] as String?;
      final access = e['access'] as String?;
      if (enrollmentId == null || access == null) continue;
      if (excludeEnrollmentIds.contains(enrollmentId)) continue;
      final pkg = (e['metadata'] as Map?)?['keyPackage'];
      KeyPackage? keyPackage;
      if (pkg != null) {
        keyPackage = KeyPackage.fromPayload(
          pkg,
          enrollmentId: enrollmentId,
          apkamId: e['apkamPubKey'] as String?,
        );
      }
      members.add(NamespaceMember(
        enrollmentId: enrollmentId,
        access: access,
        keyPackage: keyPackage,
      ));
    }
    return members;
  }
}

/// Wires a fresh [AtClientSecretSharing] for [ctx]: a persisted enc keypair
/// (stable kpid across runs), a persisted `SecretStore`, and the
/// [FileEnrollmentDirectory] stand-in in place of the not-yet-built
/// `enroll:listns` verb.
Future<AtClientSecretSharing> buildSharing(DemoContext ctx) async {
  final sharing = AtClientSecretSharing.forClient(
    ctx.atClient,
    persistence:
        FileSecretStorePersistence(File('${ctx.stateDir.path}/secrets.json')),
  );
  final apkamKeys =
      FileApkamKeys(File('${ctx.stateDir.path}/apkam_enc_keys.json'));
  sharing.loadApkamKeys = apkamKeys.load;
  sharing.saveApkamKeys = apkamKeys.save;
  sharing.directory = FileEnrollmentDirectory(sharedDirectoryFile());
  await sharing.secretStore.init();
  return sharing;
}

String prettyJson(Object? value) =>
    const JsonEncoder.withIndent('  ').convert(value);

/// Waits until this device's local commit log has nothing left to push to
/// the atServer.
///
/// Found by testing: each bin/*.dart run is a short-lived process that
/// exits right after its one logical action. If it exits before its
/// SyncService finishes pushing that action's commit, the *next* run for
/// this same --label resumes with that commit still "pending" and replays
/// it - harmless for an ordinary put, but for a delete performed by a
/// DIFFERENT device (e.g. device-b consuming and deleting an __ssenv
/// envelope device-a sent), device-a's own local queue has no idea about
/// that delete and can resurrect the envelope by re-pushing its original
/// put. Calling this before exit avoids leaving that race behind.
/// Best-effort: gives up after [timeout] rather than hanging a demo script.
Future<void> waitForSyncToSettle(
  AtClient atClient, {
  Duration timeout = const Duration(seconds: 10),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    if (await atClient.syncService.isInSync()) return;
    await Future.delayed(const Duration(milliseconds: 300));
  }
}
