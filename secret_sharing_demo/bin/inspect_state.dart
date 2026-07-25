import 'dart:convert';
import 'dart:io';

import 'package:at_client/at_client.dart'
    show AtKey, AtKeyNotFoundException, EnrollmentConstants, GetRequestOptions;
import 'package:secret_sharing_demo/demo_support.dart';

/// Utility - talks to a REAL atServer, but only reads; never consumes or
/// deletes anything. Peek at what's actually sitting on the atServer for
/// --atsign right now: any unconsumed __ssenv envelopes (normally swept +
/// deleted within moments by 05_receive_secret.dart, so seeing one here
/// means you caught it in flight) and which registered enrollments have
/// actually published their APKAM signing key.
///
/// Signing keys are deliberately NOT looked up via scan: `public:_apsk.*`
/// keys start with an underscore, and testing this demo found that the
/// atServer's `scan` verb does not surface them even with showHiddenKeys -
/// only a direct get() by the exact computed uri does (which is exactly
/// what EnvelopeSigning.getApkamPublicKey does for real, and exactly what
/// this script mirrors: it's not scannable by design, only addressable by
/// (atsign, enrollmentId)).
///
///   dart run bin/inspect_state.dart -a @delta -L inspector -r vip.ve.atsign.zone:64
Future<void> main(List<String> args) async {
  final ctx = await bootstrap(args);
  final atsign = ctx.atClient.getCurrentAtSign();

  print('=== Unconsumed __ssenv envelopes on $atsign ===');
  final envelopeKeys = await ctx.atClient.getAtKeys(
      regex: '.*__ssenv.*', useRemoteAtServer: true, showHiddenKeys: true);
  if (envelopeKeys.isEmpty) {
    print('  (none - either nothing is in flight, or it was already swept)');
  }
  for (final k in envelopeKeys) {
    final av = await ctx.atClient.get(k,
        getRequestOptions: GetRequestOptions()..useRemoteAtServer = true);
    final raw = av.value as String;
    print('  $k');
    print('    ttl remaining: ${k.metadata.ttl}ms');
    print('    value: ${raw.substring(0, raw.length > 160 ? 160 : raw.length)}...');
  }

  print('\n=== APKAM signing keys for enrollments registered in the local '
      'directory stand-in ===');
  final entries = jsonDecode(sharedDirectoryFile().existsSync()
      ? sharedDirectoryFile().readAsStringSync()
      : '[]') as List;
  final enrollmentIds = entries
      .map((e) => (e as Map)['enrollmentId'] as String)
      .toSet();
  if (enrollmentIds.isEmpty) {
    print('  (no devices registered yet - run 03_register_device.dart first)');
  }
  for (final enrollmentId in enrollmentIds) {
    final uri = 'public:_apsk.$enrollmentId.'
        '${EnrollmentConstants.perEnrollmentApproved}$atsign';
    try {
      await ctx.atClient.get(AtKey.fromString(uri),
          getRequestOptions: GetRequestOptions()..useRemoteAtServer = true);
      print('  $uri  -> published');
    } on AtKeyNotFoundException {
      print('  $uri  -> NOT published');
    }
  }
  exit(0);
}
