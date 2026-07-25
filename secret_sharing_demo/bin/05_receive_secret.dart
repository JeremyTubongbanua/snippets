import 'dart:io';

import 'package:secret_sharing_demo/demo_support.dart';

/// Step 5 - talks to a REAL atServer.
///
///   dart run bin/05_receive_secret.dart -a @youratsign -L device-b -v
///
/// A single sweep of the atServer for envelopes addressed to this device:
/// verify the APKAM signature, decrypt, store, delete. Run
/// 04_send_secret.dart (to this --label) first, from another --label.
Future<void> main(List<String> args) async {
  final ctx = await bootstrap(args);
  final sharing = await buildSharing(ctx);
  await sharing.register();

  print('=== Sweeping the atServer for envelopes addressed to '
      '"${ctx.label}" (kpid ${sharing.kpid}) ===\n');

  final envSub = sharing.receivedEnvelopes.listen((e) => print(
      '  [envelope decrypted] from kpid ${e.fromKpid} '
      '(enrollment ${e.fromEnrollmentId}), kind=${e.payload['kind']}'));
  final secSub = sharing.receivedSecrets.listen((r) => print(
      '  [secret stored]      ${r.secret.namespace}:${r.secret.name} '
      '= ${r.secret.value} (from kpid ${r.fromKpid})'));

  final consumed = await sharing.sweepOnce(fromRemote: true);

  await envSub.cancel();
  await secSub.cancel();
  print('\nConsumed $consumed envelope(s) (each is deleted from the '
      'atServer immediately after being verified + decrypted).');

  print('\n--- "${ctx.label}"\'s full secret store after this sweep ---');
  final secrets = sharing.secretStore.listSecrets();
  if (secrets.isEmpty) {
    print('  (empty - nothing sent to this device yet)');
  } else {
    for (final s in secrets) {
      print('  ${s.namespace}:${s.name} = ${s.value} '
          '(version ${s.version}, created ${s.createdAt})');
    }
  }
  await waitForSyncToSettle(ctx.atClient);
  exit(0);
}
