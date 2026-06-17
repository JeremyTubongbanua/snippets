/// XWing interop test — Dart client
///
/// Protocol
/// --------
/// 1. Connect to the Python server.
/// 2. Receive the 1216-byte X-Wing public key.
/// 3. Encapsulate using XWingFfiAlgo → get a 1120-byte ciphertext and a
///    32-byte shared secret.
/// 4. Encrypt a message with AES-256-GCM (key = shared secret).
/// 5. Send: [4-byte big-endian length][1120-byte XWing ct][12-byte nonce][AES ct+tag]
/// 6. Receive "OK\n" from the server.
import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:at_chops/at_chops.dart';
import 'package:cryptography/cryptography.dart';

// ── AES-256-GCM ──────────────────────────────────────────────────────────────

Future<({Uint8List nonce, Uint8List ciphertextWithTag})> aes256GcmEncrypt(
  Uint8List key,
  List<int> plaintext,
) async {
  final AesGcm aesGcm = AesGcm.with256bits(nonceLength: 12);
  final SecretKey secretKey = SecretKey(key);
  final Uint8List nonceBytes = Uint8List(12);
  final Random rng = Random.secure();
  for (int i = 0; i < 12; i++) {
    nonceBytes[i] = rng.nextInt(256);
  }
  final SecretBox box = await aesGcm.encrypt(
    plaintext,
    secretKey: secretKey,
    nonce: nonceBytes,
  );
  final Uint8List ctWithTag =
      Uint8List(box.cipherText.length + box.mac.bytes.length)
        ..setRange(0, box.cipherText.length, box.cipherText)
        ..setRange(
            box.cipherText.length,
            box.cipherText.length + box.mac.bytes.length,
            box.mac.bytes);
  return (nonce: nonceBytes, ciphertextWithTag: ctWithTag);
}

// ── Buffered socket reader ────────────────────────────────────────────────────

/// Buffers all data arriving on a [Socket] so we can make multiple sequential
/// fixed-size reads without fighting Dart's single-subscriber stream rule.
class SocketBuffer {
  final List<int> _buf = [];
  bool _done = false;

  // Completer fired whenever new bytes arrive or the socket closes.
  Completer<void> _notify = Completer<void>.sync();

  SocketBuffer(Socket socket) {
    socket.listen(
      (Uint8List chunk) {
        _buf.addAll(chunk);
        if (!_notify.isCompleted) _notify.complete();
        _notify = Completer<void>.sync();
      },
      onDone: () {
        _done = true;
        if (!_notify.isCompleted) _notify.complete();
      },
      onError: (Object e) {
        _done = true;
        if (!_notify.isCompleted) _notify.complete();
      },
    );
  }

  /// Returns the next [n] bytes, waiting for them to arrive if necessary.
  Future<Uint8List> read(int n) async {
    while (_buf.length < n) {
      if (_done) {
        throw StateError('Connection closed: need $n bytes, have ${_buf.length}');
      }
      await _notify.future;
    }
    final Uint8List slice = Uint8List.fromList(_buf.sublist(0, n));
    _buf.removeRange(0, n);
    return slice;
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

const String _host = '127.0.0.1';
const int _port = 9876;

void main() async {
  // Load libcrypto
  final StringBuffer loadedPath = StringBuffer();
  final DynamicLibrary? lib = tryLoadLibCrypto(loadedPath: loadedPath);
  if (lib == null) {
    stderr.writeln('ERROR: libcrypto not found. Set AT_CHOPS_LIBCRYPTO_PATH.');
    exit(1);
  }
  if (!libCryptoSupportsMlKem768(lib)) {
    stderr.writeln('ERROR: libcrypto does not support ML-KEM-768 (need >= 3.3).');
    exit(1);
  }
  print('[client] libcrypto loaded from: ${loadedPath.toString()}');

  final XWingFfiAlgo xwing = XWingFfiAlgo.fromLib(lib);

  // Connect
  print('[client] connecting to $_host:$_port ...');
  final Socket socket = await Socket.connect(_host, _port);
  print('[client] connected');

  final SocketBuffer reader = SocketBuffer(socket);

  try {
    // Step 1: receive 1216-byte public key
    final Uint8List pkBuffer = await reader.read(XWingFfiAlgo.publicKeyLength);
    print('[client] received public key (${pkBuffer.length} bytes): '
        '${_hex(pkBuffer, max: 32)}...');

    // Step 2: encapsulate
    final ({Uint8List ciphertext, Uint8List sharedSecret}) enc =
        await xwing.encapsulate(pkBuffer);
    print('[client] shared secret: ${_hex(enc.sharedSecret)}');
    print('[client] ciphertext (${enc.ciphertext.length} bytes): '
        '${_hex(enc.ciphertext, max: 32)}...');

    // Step 3: encrypt a message
    const String message = 'Hello from Dart XWing FFI (at_chops 3.2.x)!';
    print('[client] plaintext: $message');
    final ({Uint8List nonce, Uint8List ciphertextWithTag}) aes =
        await aes256GcmEncrypt(enc.sharedSecret, message.codeUnits);
    print('[client] AES nonce:  ${_hex(aes.nonce)}');
    print('[client] AES ct+tag: ${_hex(aes.ciphertextWithTag, max: 32)}...');

    // Step 4: send [4-byte BE length][XWing ct 1120B][nonce 12B][AES ct+tag]
    final int totalLen =
        enc.ciphertext.length + aes.nonce.length + aes.ciphertextWithTag.length;
    final Uint8List lengthPrefix = Uint8List(4)
      ..buffer.asByteData().setUint32(0, totalLen, Endian.big);
    socket.add(lengthPrefix);
    socket.add(enc.ciphertext);
    socket.add(aes.nonce);
    socket.add(aes.ciphertextWithTag);
    await socket.flush();
    print('[client] sent payload ($totalLen bytes + 4-byte length prefix)');

    // Step 5: wait for "OK\n" (3 bytes)
    final Uint8List responseBytes = await reader.read(3);
    final String response = String.fromCharCodes(responseBytes).trim();
    print('[client] server response: $response');
    if (response == 'OK') {
      print('[client] SUCCESS — shared secrets match, message decrypted correctly');
    } else {
      stderr.writeln('[client] FAILURE — unexpected response: $response');
      exit(1);
    }
  } finally {
    await socket.close();
  }
}

String _hex(Uint8List bytes, {int max = 0}) {
  final Iterable<int> slice = max > 0 ? bytes.take(max) : bytes;
  return slice.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
