import 'dart:async';
import 'dart:io';

import 'package:secret_sharing_demo/demo_support.dart';

/// Step 7 - talks to a REAL atServer. Needs TWO terminals running at once.
///
/// Terminal 1 (the device that already holds the secret - answers requests):
///   dart run bin/07_request_secret.dart -a @youratsign -L device-a \
///       --role responder -v
///
/// Terminal 2 (the device asking for it):
///   dart run bin/07_request_secret.dart -a @youratsign -L device-b \
///       --role requester --name db-password
///
/// This is the pull side of the substrate: the requester broadcasts a
/// `kind:'request'` envelope to every device in the namespace; a listening
/// responder answers with an ordinary `kind:'secret'` envelope (no separate
/// "response" wire shape is needed - see PairwiseSecretSharing in the SDK).
Future<void> main(List<String> args) async {
  final parser = demoArgParser(
    extend: (p) => p
      ..addOption('role',
          allowed: ['requester', 'responder'], mandatory: true)
      ..addOption('name', help: 'Secret name to request (requester only)'),
  );
  final ctx = await bootstrap(args, parser: parser);
  final sharing = await buildSharing(ctx);
  await sharing.register();
  await sharing.startListening();

  final role = ctx.args['role'] as String;
  if (role == 'responder') {
    final held = sharing.secretStore
        .listSecrets(namespace: demoNamespace)
        .map((s) => s.name)
        .toList();
    print('=== "${ctx.label}" is listening and will answer pull requests '
        'for "$demoNamespace" ===');
    print('Currently holds: ${held.isEmpty ? "(nothing yet)" : held}');
    print('Press Ctrl+C to stop.\n');
    await Completer<void>().future; // idle until killed
  } else {
    final name = ctx.args['name'];
    if (name == null) {
      stderr.writeln('--name is required with --role requester');
      exit(1);
    }
    print('=== "${ctx.label}" requesting "$name" from "$demoNamespace" ===');
    print('(make sure a --role responder is already running in another '
        'terminal, holding this secret)\n');
    try {
      final secret = await sharing.requestSecret(demoNamespace, name as String);
      print('Got it: ${secret.namespace}:${secret.name} = ${secret.value}');
    } on TimeoutException {
      stderr.writeln('Timed out waiting for a reply. Is a responder running '
          'and does it actually hold "$name"?');
      exit(1);
    }
  }
  await waitForSyncToSettle(ctx.atClient);
  exit(0);
}
