import 'dart:convert';
import 'dart:typed_data';

import 'package:at_chops/at_chops.dart'
    show PqOpenException, XWingPureDartAlgo, pqOpen, pqSeal;
import 'package:at_client/src/secret_sharing/algo_ids.dart';
import 'package:at_client/src/secret_sharing/key_package.dart';
import 'package:at_client/src/secret_sharing/secret_envelope.dart';

/// Domain-separation context bound into the key schedule - see
/// PairwiseSecretSharing._sealInfo in the SDK. Ties a sealed payload to this
/// substrate so it can't be replayed into a different pqSeal-based protocol.
final Uint8List _sealInfo =
    Uint8List.fromList(utf8.encode('at_client/secret_sharing/v1'));

/// Step 1 - no atSign, no atServer, no args needed.
///
/// The actual cryptography behind one pairwise send: X-Wing KEM
/// encapsulation + AES-256-GCM AEAD over an HKDF key schedule (at_chops
/// pqSeal/pqOpen), and the SecretEnvelope wire shape that carries it.
void main() async {
  print('--- Recipient generates its enc keypair (see step 00) ---');
  final recipient = await XWingPureDartAlgo.instance.generateKeyPair();
  final recipientPub = base64Encode(recipient.publicKey);
  final kid = PackageKey.computeKid(recipientPub);
  print('Recipient kid: $kid');

  final payload = {'kind': 'secret', 'name': 'db-password', 'value': 'hunter2'};
  print('\n--- Sender seals a payload to the recipient\'s public key ---');
  print('Plaintext payload: ${jsonEncode(payload)}');
  final sealed = await pqSeal(
    XWingPureDartAlgo.instance,
    recipient.publicKey,
    Uint8List.fromList(utf8.encode(jsonEncode(payload))),
    info: _sealInfo,
  );
  print('Sealed size: ${sealed.length} bytes '
      '(KEM ciphertext + AEAD ciphertext + tag)');

  final envelope = SecretEnvelope(
    fromKpid: 'sender-kpid-demo',
    fromEnrollmentId: 'sender-enrollment-demo',
    toKpid: kid,
    suite: SecretSharingAlgos.xWingHpke,
    kid: kid,
    sealed: base64Encode(sealed),
  );
  print('\n--- The SecretEnvelope on the wire (this is the __ssenv at-key value, '
      'before the outer APKAM signature wrapper) ---');
  print(const JsonEncoder.withIndent('  ').convert(envelope.toJson()));

  print('\n--- Recipient opens it ---');
  final opened = await pqOpen(
    XWingPureDartAlgo.instance,
    recipient.secretKey,
    base64Decode(envelope.sealed),
    info: _sealInfo,
  );
  print('Decrypted: ${utf8.decode(opened)}');

  print('\n--- What happens if the ciphertext is tampered with? ---');
  final tampered = base64Decode(envelope.sealed);
  tampered[tampered.length - 1] ^= 0xFF; // flip the last byte
  try {
    await pqOpen(XWingPureDartAlgo.instance, recipient.secretKey, tampered,
        info: _sealInfo);
    print('(unexpected: tampering was not detected!)');
  } on PqOpenException catch (e) {
    print('pqOpen rejected it, as expected: $e');
  }

  print('\nIn the real substrate this whole envelope is also wrapped in an '
      'APKAM signature (EnvelopeSigning.wrapAndSignAndJsonEncode) and '
      'verified BEFORE decrypting - see 05_receive_secret.dart.');
}
