import 'dart:io';

import 'package:at_client/src/secret_sharing/secret_store.dart' show Secret;
import 'package:secret_sharing_demo/demo_support.dart';

/// Step 6 - talks to a REAL atServer.
///
///   dart run bin/06_push_to_namespace.dart -a @youratsign -L device-a \
///       --name rotated-key --value v2 -v
///
/// The "wow" feature: rotate/mint a secret once and it fans out to every
/// OTHER device registered for this namespace, without naming any of them -
/// this is pushSecretToNamespaceMembers, the same call a real crypto
/// provider would use to distribute a fresh content key to every device on
/// enrollment approval. Uses the directory stand-in to enumerate members
/// (see 03_register_device.dart); run it with at least two --labels
/// registered first.
Future<void> main(List<String> args) async {
  final parser = demoArgParser(
    extend: (p) => p
      ..addOption('name', mandatory: true, help: 'Secret name')
      ..addOption('value', mandatory: true, help: 'Secret value'),
  );
  final ctx = await bootstrap(args, parser: parser);
  final sharing = await buildSharing(ctx);
  await sharing.register();

  final name = ctx.args['name'] as String;
  final value = ctx.args['value'] as String;

  print('=== "${ctx.label}" pushing "$name" to every other device '
      'registered for "$demoNamespace" ===\n');
  final pushed = await sharing.pushSecretToNamespaceMembers(
    Secret(namespace: demoNamespace, name: name, value: value),
  );
  print('Pushed to $pushed device(s) (sealed once per recipient kpid; '
      '"${ctx.label}" itself was skipped).');

  if (pushed == 0) {
    print('\nNo other devices found. Register one with a different --label '
        'first: dart run bin/03_register_device.dart '
        '-a ${ctx.atClient.getCurrentAtSign()} -L <other-label>');
  } else {
    print('\nNext: sweep each recipient to see it arrive, e.g. '
        'dart run bin/05_receive_secret.dart '
        '-a ${ctx.atClient.getCurrentAtSign()} -L <other-label>');
  }
  await waitForSyncToSettle(ctx.atClient);
  exit(0);
}
