import 'dart:io';

import 'package:secret_sharing_demo/demo_support.dart';

/// Step 3 - talks to a REAL atServer.
///
///   dart run bin/03_register_device.dart -a @youratsign -L device-a
///
/// Run this once per --label you want to demo with (e.g. device-a and
/// device-b), all with the same --atsign. Each --label gets its own X-Wing
/// enc keypair, persisted locally so re-running this (or a later script)
/// with the same --label reuses the same identity instead of minting a new
/// one.
///
/// Why two --labels under one atSign instead of two atSigns, or two real
/// enrollments of one atSign? This substrate is same-atSign/multi-device
/// sharing (see the README) - two atSigns wouldn't demo the right thing. Two
/// real enrollments would be more faithful, but that needs a live APKAM
/// enroll:request/approve round trip this demo doesn't set up (yet). Two
/// --labels sharing one enrollment is the honest middle ground: the crypto,
/// the atServer reads/writes, and the notification/sync plumbing below are
/// all real; only the "which enrollment owns this kpid" bookkeeping is
/// simulated.
Future<void> main(List<String> args) async {
  final ctx = await bootstrap(args);
  final sharing = await buildSharing(ctx);

  print('=== Registering "${ctx.label}" on ${ctx.atClient.getCurrentAtSign()} ===\n');
  final keyPackage = await sharing.register();

  print('Real atServer enrollmentId for this connection: ${sharing.enrollmentId}');
  print('kpid (this device\'s mailbox address):           ${sharing.kpid}');

  print('\n--- A real atServer write just happened: publishing the APKAM '
      'signing key peers use to verify envelopes from this device ---');
  print('at-key: ${sharing.publicSigningKeyUri}');

  print('\n--- KeyPackage ("business card") this device advertises ---');
  print(prettyJson(keyPackage.toJson()));

  print('\n--- Recording it in the local directory stand-in ---');
  print('(stands in for the atServer\'s enroll:listns verb, which has no '
      'server-side implementation yet - everything else here is real)');
  FileEnrollmentDirectory(sharedDirectoryFile())
      .registerSelf(keyPackage, demoLabel: ctx.label);
  print('Wrote ${sharedDirectoryFile().path}');

  print('\nNext: run this again with a different --label to register a '
      'second device, then 04_send_secret.dart to send between them.');
  await waitForSyncToSettle(ctx.atClient);
  exit(0);
}
