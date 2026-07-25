import 'dart:io';

import 'package:at_client/src/secret_sharing/secret_store.dart' show Secret;
import 'package:secret_sharing_demo/demo_support.dart';

/// Step 4 - talks to a REAL atServer.
///
///   dart run bin/04_send_secret.dart -a @youratsign -L device-a \
///       --to device-b --name db-password --value hunter2 -v
///
/// Requires device-a and device-b to have both run
/// 03_register_device.dart first (same --atsign). Add -v/--verbose to also
/// see the SDK's own internal log line naming the exact at-key it wrote.
Future<void> main(List<String> args) async {
  final parser = demoArgParser(
    extend: (p) => p
      ..addOption('to', mandatory: true, help: 'The --label of the recipient device')
      ..addOption('name', mandatory: true, help: 'Secret name')
      ..addOption('value', mandatory: true, help: 'Secret value'),
  );
  final ctx = await bootstrap(args, parser: parser);
  final sharing = await buildSharing(ctx);
  await sharing.register(); // reloads this device's persisted identity

  final toLabel = ctx.args['to'] as String;
  final name = ctx.args['name'] as String;
  final value = ctx.args['value'] as String;

  print('=== "${ctx.label}" looking up "$toLabel" in the directory stand-in ===\n');
  final recipient =
      FileEnrollmentDirectory(sharedDirectoryFile()).keyPackageForLabel(toLabel);
  if (recipient == null) {
    stderr.writeln('No registered device found for --to "$toLabel".');
    stderr.writeln('Run: dart run bin/03_register_device.dart '
        '-a ${ctx.atClient.getCurrentAtSign()} -L $toLabel');
    exit(1);
  }
  print('Found it: kpid ${recipient.kpid}\n');

  print('--- Sealing "$name" to that kpid and writing it to the atServer ---');
  await sharing.shareSecretWith(
    recipient,
    Secret(namespace: demoNamespace, name: name, value: value),
  );
  print('Done. The at-key is named <uuid>.${recipient.kpid}.__ssenv.'
      '$demoNamespace${ctx.atClient.getCurrentAtSign()} - it is end-to-end '
      'sealed to "$toLabel" and APKAM-signed by "${ctx.label}"; the atServer '
      'stores and relays it but cannot read it.');

  print('\nNext: dart run bin/05_receive_secret.dart '
      '-a ${ctx.atClient.getCurrentAtSign()} -L $toLabel');
  await waitForSyncToSettle(ctx.atClient);
  exit(0);
}
