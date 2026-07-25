import 'dart:convert';

import 'package:at_chops/at_chops.dart' show XWingPureDartAlgo;
import 'package:at_client/src/secret_sharing/algo_ids.dart';
import 'package:at_client/src/secret_sharing/key_package.dart';

/// Step 0 - no atSign, no atServer, no args needed.
///
/// The smallest building block of the secret-sharing substrate: one device's
/// "business card". Every APKAM keypair (device/enrollment) that wants to
/// *receive* secrets generates an X-Wing KEM keypair and wraps its public
/// half in a KeyPackage. The KeyPackage's kpid - a short hash of the public
/// key - is the "mailbox slot name" every later step in this demo addresses.
void main() async {
  print('--- Generating an X-Wing keypair (this device\'s enc identity) ---');
  final keyPair = await XWingPureDartAlgo.instance.generateKeyPair();
  print('Public key: ${keyPair.publicKey.length} bytes '
      '(this is what gets advertised)');
  print('Secret key: ${keyPair.secretKey.length} bytes '
      '(this never leaves the device)');

  final pub = base64Encode(keyPair.publicKey);
  final kid = PackageKey.computeKid(pub);
  print('\n--- Deriving the key id (kid) ---');
  print('kid = first 8 bytes of SHA-256(pub), hex-encoded = $kid');

  final keyPackage = KeyPackage(
    enrollmentId: 'demo-enrollment-1',
    createdAt: DateTime.now().toUtc(),
    keys: [
      PackageKey(
        use: SecretSharingAlgos.useEnc,
        alg: SecretSharingAlgos.xWing,
        pub: pub,
      ),
    ],
  );
  print('\n--- The KeyPackage ("business card") this device would advertise ---');
  print(const JsonEncoder.withIndent('  ').convert(keyPackage.toJson()));
  print('\nkpid (this device\'s routing address) = ${keyPackage.kpid}');

  print('\n--- Round-tripping through the wire format ---');
  final roundTripped = KeyPackage.fromPayload(
    keyPackage.toJson(),
    enrollmentId: keyPackage.enrollmentId,
  );
  print('Same kpid after JSON round-trip? '
      '${roundTripped.kpid == keyPackage.kpid}');

  print('\nIn production this KeyPackage rides along inside enroll:request '
      'metadata at enrollment time - it is never written as a standalone '
      'at-key. Next: 01_seal_and_open.dart uses this same shape to actually '
      'seal something to it.');
}
