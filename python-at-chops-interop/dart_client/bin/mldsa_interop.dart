/// ML-DSA-65 interoperability test — Dart side
///
/// Protocol (single TCP connection, both directions tested)
/// ---------------------------------------------------------
/// Round 1 — Dart signs, Python verifies:
///   Dart  → [4B pk_len][public_key (1952 B)]
///         → [4B sig_len][signature (3309 B)]
///         → [4B msg_len][message]
///   Python verifies; sends "OK\n" or "FAIL\n"
///
/// Round 2 — Python signs, Dart verifies:
///   Python → [4B pk_len][public_key (1952 B)]
///          → [4B sig_len][signature (3309 B)]
///          → [4B msg_len][message]
///   Dart verifies; sends "OK\n" or "FAIL\n"
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

// ── Framed send/receive ───────────────────────────────────────────────────────

void sendFramed(Socket socket, Uint8List data) {
  final Uint8List prefix = Uint8List(4)
    ..buffer.asByteData().setUint32(0, data.length, Endian.big);
  socket.add(prefix);
  socket.add(data);
}

Future<Uint8List> recvFramed(SocketBuffer reader) async {
  final Uint8List lenBytes = await reader.read(4);
  final int n = ByteData.sublistView(lenBytes).getUint32(0, Endian.big);
  return reader.read(n);
}

// ── Main ──────────────────────────────────────────────────────────────────────

const String _host = '127.0.0.1';
const int _port = 9877;

void main() async {
  final StringBuffer loadedPath = StringBuffer();
  final DynamicLibrary? lib = tryLoadLibCrypto(loadedPath: loadedPath);
  if (lib == null) {
    stderr.writeln('ERROR: libcrypto not found.');
    exit(1);
  }
  if (!libCryptoSupportsMlDsa65(lib)) {
    stderr.writeln('ERROR: libcrypto does not support ML-DSA-65 (need >= 3.3).');
    exit(1);
  }
  print('[dart] libcrypto loaded from: ${loadedPath.toString()}');

  final MlDsa65FfiAlgo algo = MlDsa65FfiAlgo.fromLib(lib);

  print('[dart] connecting to $_host:$_port ...');
  final Socket socket = await Socket.connect(_host, _port);
  print('[dart] connected');
  final SocketBuffer reader = SocketBuffer(socket);

  try {
    // ── Round 1: Dart signs, Python verifies ─────────────────────────────────
    print('\n[dart] === Round 1: Dart signs, Python verifies ===');

    final ({Uint8List publicKey, Uint8List secretKey}) kp =
        await algo.generateKeyPair();
    print('[dart] generated public key (${kp.publicKey.length} B): '
        '${_hex(kp.publicKey, max: 32)}...');

    final Uint8List message =
        Uint8List.fromList('Hello from Dart ML-DSA-65 FFI (at_chops 3.2.x)!'.codeUnits);
    final Uint8List sig = await algo.signBytes(kp.secretKey, message);
    print('[dart] signature (${sig.length} B): ${_hex(sig, max: 32)}...');
    print('[dart] message: ${String.fromCharCodes(message)}');

    sendFramed(socket, kp.publicKey);
    sendFramed(socket, sig);
    sendFramed(socket, message);
    await socket.flush();
    print('[dart] sent public key + signature + message');

    final Uint8List r1Response = await reader.read(3);
    final String r1 = String.fromCharCodes(r1Response).trim();
    print('[dart] Python verify response: $r1');
    if (r1 != 'OK') {
      stderr.writeln('[dart] FAIL — Python rejected Dart signature');
      exit(1);
    }

    // ── Round 2: Python signs, Dart verifies ─────────────────────────────────
    print('\n[dart] === Round 2: Python signs, Dart verifies ===');

    final Uint8List pyPk  = await recvFramed(reader);
    final Uint8List pySig = await recvFramed(reader);
    final Uint8List pyMsg = await recvFramed(reader);

    print('[dart] received public key (${pyPk.length} B): ${_hex(pyPk, max: 32)}...');
    print('[dart] received signature  (${pySig.length} B): ${_hex(pySig, max: 32)}...');
    print('[dart] received message:   ${String.fromCharCodes(pyMsg)}');

    final bool ok = await algo.verifyBytes(pyPk, pyMsg, pySig);
    print('[dart] verify result: $ok');
    socket.add(ok ? Uint8List.fromList('OK\n'.codeUnits)
                  : Uint8List.fromList('FAIL\n'.codeUnits));
    await socket.flush();

    if (ok) {
      print('\n[dart] SUCCESS — both directions verified correctly');
    } else {
      stderr.writeln('[dart] FAIL — Python signature did not verify in Dart');
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
