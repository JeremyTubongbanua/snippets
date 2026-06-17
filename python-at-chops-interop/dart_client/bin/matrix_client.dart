/// Matrix interop client — Dart side
///
/// Driven by the Python server. For each round:
///   - reads [py_impl_idx, dart_impl_idx] to know which Dart impl to use
///   - executes the KEM or signing operation with the specified impl
///
/// XWing round: receives pk → encapsulates with dart_impl → sends ct + ss
/// ML-DSA round:
///   Sub-A: receives pk+sig+msg from Python → verifies with dart_impl → sends result
///   Sub-B: generates keypair + signs with dart_impl → sends pk+sig+msg → waits for result
import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:at_chops/at_chops.dart';

// ── Buffered socket reader ────────────────────────────────────────────────────

class SocketBuffer {
  final List<int> _buf = [];
  bool _done = false;
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
      onError: (Object _) {
        _done = true;
        if (!_notify.isCompleted) _notify.complete();
      },
    );
  }

  Future<Uint8List> read(int n) async {
    while (_buf.length < n) {
      if (_done) throw StateError('Connection closed: need $n, have ${_buf.length}');
      await _notify.future;
    }
    final Uint8List slice = Uint8List.fromList(_buf.sublist(0, n));
    _buf.removeRange(0, n);
    return slice;
  }
}

// ── Framed I/O ────────────────────────────────────────────────────────────────

void sendFramed(Socket socket, Uint8List data) {
  final Uint8List prefix = Uint8List(4)
    ..buffer.asByteData().setUint32(0, data.length, Endian.big);
  socket.add(prefix);
  socket.add(data);
}

Future<Uint8List> recvFramed(SocketBuffer r) async {
  final Uint8List lenBytes = await r.read(4);
  final int n = ByteData.sublistView(lenBytes).getUint32(0, Endian.big);
  return r.read(n);
}

// ── Dart impl index → names ───────────────────────────────────────────────────

const List<String> _dartImpls = ['pure_dart', 'dart_ffi'];
const List<String> _pyImpls   = ['pure_python', 'openssl_ffi'];

// ── Main ──────────────────────────────────────────────────────────────────────

const String _host = '127.0.0.1';
const int    _port = 9878;

void main() async {
  final StringBuffer loadedPath = StringBuffer();
  final DynamicLibrary? lib = tryLoadLibCrypto(loadedPath: loadedPath);
  if (lib == null) {
    stderr.writeln('ERROR: libcrypto not found.');
    exit(1);
  }
  if (!libCryptoSupportsMlKem768(lib) || !libCryptoSupportsMlDsa65(lib)) {
    stderr.writeln('ERROR: libcrypto does not support ML-KEM-768 or ML-DSA-65.');
    exit(1);
  }

  final XWingFfiAlgo    xwingFfi   = XWingFfiAlgo.fromLib(lib);
  final MlDsa65FfiAlgo  mldsa65Ffi = MlDsa65FfiAlgo.fromLib(lib);

  print('[dart] libcrypto: ${loadedPath.toString()}');
  print('[dart] connecting to $_host:$_port ...');
  final Socket socket = await Socket.connect(_host, _port);
  print('[dart] connected\n');
  final SocketBuffer reader = SocketBuffer(socket);

  try {
    // ── XWing rounds (4 total: 2 py × 2 dart) ────────────────────────────────
    for (int round = 0; round < 4; round++) {
      final Uint8List header = await reader.read(2);
      final int pyIdx   = header[0];
      final int dartIdx = header[1];
      final String pyImpl   = _pyImpls[pyIdx];
      final String dartImpl = _dartImpls[dartIdx];

      // Read pk (2-byte length prefix)
      final Uint8List pkLenBytes = await reader.read(2);
      final int pkLen = ByteData.sublistView(pkLenBytes).getUint16(0, Endian.big);
      final Uint8List pk = await reader.read(pkLen);

      // Encapsulate with the specified Dart impl
      final ({Uint8List ciphertext, Uint8List sharedSecret}) enc;
      if (dartIdx == 0) {
        enc = await XWingPureDartAlgo.instance.encapsulate(pk);
      } else {
        enc = await xwingFfi.encapsulate(pk);
      }

      sendFramed(socket, enc.ciphertext);
      sendFramed(socket, enc.sharedSecret);
      await socket.flush();

      // Receive match result from server
      final int matchByte = (await reader.read(1))[0];
      final String icon = matchByte == 1 ? '✓' : '✗';
      print('[dart] xwing  $icon  py=$pyImpl  dart=$dartImpl  '
          'ss=${_hex(enc.sharedSecret, max: 8)}...');
    }

    print('');

    // ── ML-DSA rounds (4 total: 2 py × 2 dart) ───────────────────────────────
    for (int round = 0; round < 4; round++) {
      final Uint8List header = await reader.read(2);
      final int pyIdx   = header[0];
      final int dartIdx = header[1];
      final String pyImpl   = _pyImpls[pyIdx];
      final String dartImpl = _dartImpls[dartIdx];

      // Sub-round A: Python signs, Dart verifies
      final Uint8List pyPk  = await recvFramed(reader);
      final Uint8List pySig = await recvFramed(reader);
      final Uint8List pyMsg = await recvFramed(reader);

      final bool okA;
      if (dartIdx == 0) {
        okA = await MlDsa65PureDartAlgo.verifyBytes(pyMsg, pySig, pyPk);
      } else {
        okA = await mldsa65Ffi.verifyBytes(pyPk, pyMsg, pySig);
      }
      socket.add(Uint8List.fromList([okA ? 1 : 0]));
      await socket.flush();

      // Sub-round B: Dart signs, Python verifies
      final ({Uint8List publicKey, Uint8List secretKey}) kp;
      if (dartIdx == 0) {
        kp = await MlDsa65PureDartAlgo.generateKeyPair();
      } else {
        kp = await mldsa65Ffi.generateKeyPair();
      }
      final Uint8List dartMsg =
          Uint8List.fromList('py=$pyImpl → dart=$dartImpl'.codeUnits);
      final Uint8List dartSig;
      if (dartIdx == 0) {
        dartSig = await MlDsa65PureDartAlgo.signBytes(dartMsg, kp.secretKey);
      } else {
        dartSig = await mldsa65Ffi.signBytes(kp.secretKey, dartMsg);
      }
      sendFramed(socket, kp.publicKey);
      sendFramed(socket, dartSig);
      sendFramed(socket, dartMsg);
      await socket.flush();

      final int okBByte = (await reader.read(1))[0];
      final bool okB = okBByte == 1;

      final String iA = okA ? '✓' : '✗';
      final String iB = okB ? '✓' : '✗';
      print('[dart] mldsa65 py→dart $iA  dart→py $iB  '
          'py=$pyImpl  dart=$dartImpl');
    }

    // End-of-session marker
    final int eos = (await reader.read(1))[0];
    if (eos == 0xFF) {
      print('\n[dart] session complete');
    }
  } finally {
    await socket.close();
  }
}

String _hex(Uint8List bytes, {int max = 0}) {
  final Iterable<int> slice = max > 0 ? bytes.take(max) : bytes;
  return slice.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
