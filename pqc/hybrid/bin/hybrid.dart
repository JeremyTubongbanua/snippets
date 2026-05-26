import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:cryptography/cryptography.dart';
import 'package:pqcrypto/pqcrypto.dart';

// ── OpenSSL EVP opaque types ──────────────────────────────────────────────────
final class EVP_PKEY extends Opaque {}
final class EVP_PKEY_CTX extends Opaque {}
final class OSSL_PARAM extends Opaque {}
final class OSSL_PARAM_BLD extends Opaque {}

// ── FFI typedefs (ML-KEM-768 via OpenSSL EVP) ────────────────────────────────
typedef EvpPkeyCtxNewFromNameNative = Pointer<EVP_PKEY_CTX> Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Void>);
typedef EvpPkeyCtxNewFromNameDart = Pointer<EVP_PKEY_CTX> Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Void>);

typedef EvpPkeyCtxNewNative = Pointer<EVP_PKEY_CTX> Function(
    Pointer<EVP_PKEY>, Pointer<Void>);
typedef EvpPkeyCtxNewDart = Pointer<EVP_PKEY_CTX> Function(
    Pointer<EVP_PKEY>, Pointer<Void>);

typedef EvpPkeyCtxFreeNative = Void Function(Pointer<EVP_PKEY_CTX>);
typedef EvpPkeyCtxFreeDart = void Function(Pointer<EVP_PKEY_CTX>);

typedef EvpPkeyFreeNative = Void Function(Pointer<EVP_PKEY>);
typedef EvpPkeyFreeDart = void Function(Pointer<EVP_PKEY>);

typedef EvpPkeyKeygenInitNative = Int32 Function(Pointer<EVP_PKEY_CTX>);
typedef EvpPkeyKeygenInitDart = int Function(Pointer<EVP_PKEY_CTX>);

typedef EvpPkeyKemInitNative = Int32 Function(
    Pointer<EVP_PKEY_CTX>, Pointer<Void>);
typedef EvpPkeyKemInitDart = int Function(
    Pointer<EVP_PKEY_CTX>, Pointer<Void>);

typedef EvpPkeyFromdataInitNative = Int32 Function(Pointer<EVP_PKEY_CTX>);
typedef EvpPkeyFromdataInitDart = int Function(Pointer<EVP_PKEY_CTX>);

typedef EvpPkeyKeygenNative = Int32 Function(
    Pointer<EVP_PKEY_CTX>, Pointer<Pointer<EVP_PKEY>>);
typedef EvpPkeyKeygenDart = int Function(
    Pointer<EVP_PKEY_CTX>, Pointer<Pointer<EVP_PKEY>>);

typedef EvpPkeyGet1EncodedPublicKeyNative = IntPtr Function(
    Pointer<EVP_PKEY>, Pointer<Pointer<Uint8>>);
typedef EvpPkeyGet1EncodedPublicKeyDart = int Function(
    Pointer<EVP_PKEY>, Pointer<Pointer<Uint8>>);

typedef EvpPkeyEncapsulateNative = Int32 Function(Pointer<EVP_PKEY_CTX>,
    Pointer<Uint8>, Pointer<IntPtr>, Pointer<Uint8>, Pointer<IntPtr>);
typedef EvpPkeyEncapsulateDart = int Function(Pointer<EVP_PKEY_CTX>,
    Pointer<Uint8>, Pointer<IntPtr>, Pointer<Uint8>, Pointer<IntPtr>);

typedef EvpPkeyDecapsulateNative = Int32 Function(Pointer<EVP_PKEY_CTX>,
    Pointer<Uint8>, Pointer<IntPtr>, Pointer<Uint8>, IntPtr);
typedef EvpPkeyDecapsulateDart = int Function(Pointer<EVP_PKEY_CTX>,
    Pointer<Uint8>, Pointer<IntPtr>, Pointer<Uint8>, int);

typedef OsslParamBldNewNative = Pointer<OSSL_PARAM_BLD> Function();
typedef OsslParamBldNewDart = Pointer<OSSL_PARAM_BLD> Function();

typedef OsslParamBldFreeNative = Void Function(Pointer<OSSL_PARAM_BLD>);
typedef OsslParamBldFreeDart = void Function(Pointer<OSSL_PARAM_BLD>);

typedef OsslParamBldToParamNative = Pointer<OSSL_PARAM> Function(
    Pointer<OSSL_PARAM_BLD>);
typedef OsslParamBldToParamDart = Pointer<OSSL_PARAM> Function(
    Pointer<OSSL_PARAM_BLD>);

typedef OsslParamBldPushOctetStringNative = Int32 Function(
    Pointer<OSSL_PARAM_BLD>, Pointer<Utf8>, Pointer<Uint8>, IntPtr);
typedef OsslParamBldPushOctetStringDart = int Function(
    Pointer<OSSL_PARAM_BLD>, Pointer<Utf8>, Pointer<Uint8>, int);

typedef OsslParamFreeNative = Void Function(Pointer<OSSL_PARAM>);
typedef OsslParamFreeDart = void Function(Pointer<OSSL_PARAM>);

typedef EvpPkeyFromdataNative = Int32 Function(Pointer<EVP_PKEY_CTX>,
    Pointer<Pointer<EVP_PKEY>>, Int32, Pointer<OSSL_PARAM>);
typedef EvpPkeyFromdataDart = int Function(Pointer<EVP_PKEY_CTX>,
    Pointer<Pointer<EVP_PKEY>>, int, Pointer<OSSL_PARAM>);

typedef CryptoFreeNative = Void Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef CryptoFreeDart = void Function(Pointer<Void>, Pointer<Utf8>, int);

const int _evpPkeyPublicKey = 0x86;

// ── OpenSSL ML-KEM-768 wrapper ────────────────────────────────────────────────
class OpenSslMlKem768 {
  final DynamicLibrary _lib;

  late final EvpPkeyCtxNewFromNameDart _ctxNewFromName;
  late final EvpPkeyCtxNewDart _ctxNew;
  late final EvpPkeyCtxFreeDart _ctxFree;
  late final EvpPkeyFreeDart _pkeyFree;
  late final EvpPkeyKeygenInitDart _keygenInit;
  late final EvpPkeyKeygenDart _keygen;
  late final EvpPkeyGet1EncodedPublicKeyDart _get1EncodedPubKey;
  late final EvpPkeyKemInitDart _encapsInit;
  late final EvpPkeyEncapsulateDart _encapsulate;
  late final EvpPkeyKemInitDart _decapsInit;
  late final EvpPkeyDecapsulateDart _decapsulate;
  late final OsslParamBldNewDart _bldNew;
  late final OsslParamBldFreeDart _bldFree;
  late final OsslParamBldToParamDart _bldToParam;
  late final OsslParamBldPushOctetStringDart _bldPushOctet;
  late final OsslParamFreeDart _paramFree;
  late final EvpPkeyFromdataInitDart _fromdataInit;
  late final EvpPkeyFromdataDart _fromdata;
  late final CryptoFreeDart _cryptoFree;

  OpenSslMlKem768.load(String path) : _lib = DynamicLibrary.open(path) {
    _ctxNewFromName = _lib.lookupFunction<EvpPkeyCtxNewFromNameNative,
        EvpPkeyCtxNewFromNameDart>('EVP_PKEY_CTX_new_from_name');
    _ctxNew = _lib.lookupFunction<EvpPkeyCtxNewNative, EvpPkeyCtxNewDart>(
        'EVP_PKEY_CTX_new');
    _ctxFree = _lib.lookupFunction<EvpPkeyCtxFreeNative, EvpPkeyCtxFreeDart>(
        'EVP_PKEY_CTX_free');
    _pkeyFree = _lib.lookupFunction<EvpPkeyFreeNative, EvpPkeyFreeDart>(
        'EVP_PKEY_free');
    _keygenInit = _lib.lookupFunction<EvpPkeyKeygenInitNative,
        EvpPkeyKeygenInitDart>('EVP_PKEY_keygen_init');
    _keygen = _lib.lookupFunction<EvpPkeyKeygenNative, EvpPkeyKeygenDart>(
        'EVP_PKEY_keygen');
    _get1EncodedPubKey = _lib.lookupFunction<EvpPkeyGet1EncodedPublicKeyNative,
        EvpPkeyGet1EncodedPublicKeyDart>('EVP_PKEY_get1_encoded_public_key');
    _encapsInit = _lib.lookupFunction<EvpPkeyKemInitNative, EvpPkeyKemInitDart>(
        'EVP_PKEY_encapsulate_init');
    _encapsulate = _lib.lookupFunction<EvpPkeyEncapsulateNative,
        EvpPkeyEncapsulateDart>('EVP_PKEY_encapsulate');
    _decapsInit = _lib.lookupFunction<EvpPkeyKemInitNative, EvpPkeyKemInitDart>(
        'EVP_PKEY_decapsulate_init');
    _decapsulate = _lib.lookupFunction<EvpPkeyDecapsulateNative,
        EvpPkeyDecapsulateDart>('EVP_PKEY_decapsulate');
    _bldNew = _lib.lookupFunction<OsslParamBldNewNative, OsslParamBldNewDart>(
        'OSSL_PARAM_BLD_new');
    _bldFree = _lib.lookupFunction<OsslParamBldFreeNative, OsslParamBldFreeDart>(
        'OSSL_PARAM_BLD_free');
    _bldToParam = _lib.lookupFunction<OsslParamBldToParamNative,
        OsslParamBldToParamDart>('OSSL_PARAM_BLD_to_param');
    _bldPushOctet = _lib.lookupFunction<OsslParamBldPushOctetStringNative,
        OsslParamBldPushOctetStringDart>('OSSL_PARAM_BLD_push_octet_string');
    _paramFree = _lib.lookupFunction<OsslParamFreeNative, OsslParamFreeDart>(
        'OSSL_PARAM_free');
    _fromdataInit = _lib.lookupFunction<EvpPkeyFromdataInitNative,
        EvpPkeyFromdataInitDart>('EVP_PKEY_fromdata_init');
    _fromdata = _lib.lookupFunction<EvpPkeyFromdataNative, EvpPkeyFromdataDart>(
        'EVP_PKEY_fromdata');
    _cryptoFree = _lib.lookupFunction<CryptoFreeNative, CryptoFreeDart>(
        'CRYPTO_free');
  }

  (Uint8List, Pointer<EVP_PKEY>) generateKeypair() {
    final algName = 'ML-KEM-768'.toNativeUtf8();
    final ctx = _ctxNewFromName(nullptr, algName, nullptr);
    calloc.free(algName);
    if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new_from_name failed');
    try {
      if (_keygenInit(ctx) <= 0) throw StateError('EVP_PKEY_keygen_init failed');
      final pkeyPtr = calloc<Pointer<EVP_PKEY>>();
      try {
        if (_keygen(ctx, pkeyPtr) <= 0) throw StateError('EVP_PKEY_keygen failed');
        final pkey = pkeyPtr.value;
        return (_extractPublicKeyBytes(pkey), pkey);
      } finally {
        calloc.free(pkeyPtr);
      }
    } finally {
      _ctxFree(ctx);
    }
  }

  Uint8List _extractPublicKeyBytes(Pointer<EVP_PKEY> pkey) {
    final ppub = calloc<Pointer<Uint8>>();
    try {
      final len = _get1EncodedPubKey(pkey, ppub);
      if (len <= 0) throw StateError('EVP_PKEY_get1_encoded_public_key failed');
      final bytes = Uint8List.fromList(ppub.value.asTypedList(len));
      _cryptoFree(ppub.value.cast(), nullptr, 0);
      return bytes;
    } finally {
      calloc.free(ppub);
    }
  }

  Pointer<EVP_PKEY> importPublicKey(Uint8List pubKeyBytes) {
    final algName = 'ML-KEM-768'.toNativeUtf8();
    final paramName = 'pub'.toNativeUtf8();
    final keyBuf = calloc<Uint8>(pubKeyBytes.length);
    keyBuf.asTypedList(pubKeyBytes.length).setAll(0, pubKeyBytes);

    Pointer<OSSL_PARAM>? params;
    Pointer<EVP_PKEY_CTX>? ctx;
    final pkeyPtr = calloc<Pointer<EVP_PKEY>>();
    try {
      final bld = _bldNew();
      if (bld == nullptr) throw StateError('OSSL_PARAM_BLD_new failed');
      if (_bldPushOctet(bld, paramName, keyBuf, pubKeyBytes.length) <= 0) {
        _bldFree(bld);
        throw StateError('OSSL_PARAM_BLD_push_octet_string failed');
      }
      params = _bldToParam(bld);
      _bldFree(bld);
      if (params == nullptr) throw StateError('OSSL_PARAM_BLD_to_param failed');

      ctx = _ctxNewFromName(nullptr, algName, nullptr);
      if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new_from_name failed');
      if (_fromdataInit(ctx) <= 0) throw StateError('EVP_PKEY_fromdata_init failed');
      if (_fromdata(ctx, pkeyPtr, _evpPkeyPublicKey, params) <= 0) {
        throw StateError('EVP_PKEY_fromdata failed');
      }
      return pkeyPtr.value;
    } finally {
      if (ctx != null) _ctxFree(ctx);
      if (params != null) _paramFree(params);
      calloc.free(keyBuf);
      calloc.free(paramName);
      calloc.free(algName);
      calloc.free(pkeyPtr);
    }
  }

  (Uint8List, Uint8List) encapsulate(Pointer<EVP_PKEY> pubKey) {
    final ctx = _ctxNew(pubKey, nullptr);
    if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new failed');
    try {
      if (_encapsInit(ctx, nullptr) <= 0) {
        throw StateError('EVP_PKEY_encapsulate_init failed');
      }
      final ctLen = calloc<IntPtr>();
      final ssLen = calloc<IntPtr>();
      try {
        if (_encapsulate(ctx, nullptr, ctLen, nullptr, ssLen) <= 0) {
          throw StateError('EVP_PKEY_encapsulate (size query) failed');
        }
        final ctBuf = calloc<Uint8>(ctLen.value);
        final ssBuf = calloc<Uint8>(ssLen.value);
        try {
          if (_encapsulate(ctx, ctBuf, ctLen, ssBuf, ssLen) <= 0) {
            throw StateError('EVP_PKEY_encapsulate failed');
          }
          return (
            Uint8List.fromList(ctBuf.asTypedList(ctLen.value)),
            Uint8List.fromList(ssBuf.asTypedList(ssLen.value)),
          );
        } finally {
          calloc.free(ctBuf);
          calloc.free(ssBuf);
        }
      } finally {
        calloc.free(ctLen);
        calloc.free(ssLen);
      }
    } finally {
      _ctxFree(ctx);
    }
  }

  Uint8List decapsulate(Pointer<EVP_PKEY> secretKey, Uint8List ciphertext) {
    final ctx = _ctxNew(secretKey, nullptr);
    if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new failed');
    try {
      if (_decapsInit(ctx, nullptr) <= 0) {
        throw StateError('EVP_PKEY_decapsulate_init failed');
      }
      final ssLen = calloc<IntPtr>();
      final ctBuf = calloc<Uint8>(ciphertext.length);
      ctBuf.asTypedList(ciphertext.length).setAll(0, ciphertext);
      try {
        if (_decapsulate(ctx, nullptr, ssLen, ctBuf, ciphertext.length) <= 0) {
          throw StateError('EVP_PKEY_decapsulate (size query) failed');
        }
        final ssBuf = calloc<Uint8>(ssLen.value);
        try {
          if (_decapsulate(ctx, ssBuf, ssLen, ctBuf, ciphertext.length) <= 0) {
            throw StateError('EVP_PKEY_decapsulate failed');
          }
          return Uint8List.fromList(ssBuf.asTypedList(ssLen.value));
        } finally {
          calloc.free(ssBuf);
        }
      } finally {
        calloc.free(ssLen);
        calloc.free(ctBuf);
      }
    } finally {
      _ctxFree(ctx);
    }
  }

  void freeKey(Pointer<EVP_PKEY> pkey) => _pkeyFree(pkey);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
String hex(List<int> bytes, {int maxBytes = 16}) {
  final shown = bytes.length > maxBytes ? bytes.sublist(0, maxBytes) : bytes;
  final h = shown.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
  return bytes.length > maxBytes ? '$h... (${bytes.length} bytes)' : h;
}

bool bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

final _failures = <String>[];

void check(String label, bool condition) {
  final mark = condition ? 'PASS' : 'FAIL';
  print('  [$mark] $label');
  if (!condition) _failures.add(label);
}

// ── Hybrid key derivation ─────────────────────────────────────────────────────
//
// IKM = mlkem_ss || x25519_ss   (ML-KEM first, per X25519MLKEM768 / RFC 9180)
// HKDF-SHA256(IKM, salt=[], info="hybrid-x25519-mlkem768") → 32-byte hybrid key
//
Future<Uint8List> deriveHybridKey(
  Uint8List mlkemSs,
  Uint8List x25519Ss,
) async {
  final ikm = Uint8List(mlkemSs.length + x25519Ss.length);
  ikm.setAll(0, mlkemSs);
  ikm.setAll(mlkemSs.length, x25519Ss);

  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final derived = await hkdf.deriveKey(
    secretKey: SecretKey(ikm),
    nonce: [],
    info: 'hybrid-x25519-mlkem768'.codeUnits,
  );
  return Uint8List.fromList(await derived.extractBytes());
}

// ── Main ──────────────────────────────────────────────────────────────────────
Future<void> main() async {
  const libPath = '/opt/homebrew/opt/openssl@3.6/lib/libcrypto.dylib';
  final ossl = OpenSslMlKem768.load(libPath);
  final pq = PqcKem.kyber768;
  final x25519 = X25519();

  print('=== Hybrid X25519 + ML-KEM-768 Key Exchange ===');
  print('    X25519: cryptography package (pure Dart)');
  print('    ML-KEM-768: pqcrypto package (patched fork) + OpenSSL 3.6 (reference)\n');

  // ── Test A: pqcrypto ML-KEM-768 + cryptography X25519 (pure Dart, no FFI) ─
  //
  // Models Alice and Bob running the full hybrid protocol using only the
  // pure-Dart pqcrypto and cryptography packages — no native libs.
  //
  // Protocol:
  //   1. Bob generates:  ML-KEM-768 keypair (bob_mlkem_pk, bob_mlkem_sk)
  //                      X25519 keypair     (bob_x25519_pk, bob_x25519_sk)
  //   2. Alice:          encapsulates to bob_mlkem_pk → (mlkem_ct, alice_mlkem_ss)
  //                      computes X25519(alice_x25519_sk, bob_x25519_pk) → alice_x25519_ss
  //                      derives  hybrid_key = HKDF(mlkem_ss || x25519_ss)
  //   3. Bob:            decapsulates mlkem_ct with bob_mlkem_sk → bob_mlkem_ss
  //                      computes X25519(bob_x25519_sk, alice_x25519_pk) → bob_x25519_ss
  //                      derives  hybrid_key = HKDF(mlkem_ss || x25519_ss)
  //   4. Check:          alice_hybrid_key == bob_hybrid_key
  //
  print('--- Test A: pqcrypto ML-KEM-768 + cryptography X25519 (pure Dart) ---');

  // Bob's keypairs
  final (bobMlkemPk, bobMlkemSk) = pq.generateKeyPair();
  final bobX25519Kp = await x25519.newKeyPair();
  final bobX25519Pub = await bobX25519Kp.extractPublicKey();

  // Alice's keypair (X25519 only — ML-KEM has no Alice keypair, she encapsulates)
  final aliceX25519Kp = await x25519.newKeyPair();
  final aliceX25519Pub = await aliceX25519Kp.extractPublicKey();

  // Alice encapsulates to Bob's ML-KEM public key
  final (mlkemCtA, aliceMlkemSsA) = pq.encapsulate(bobMlkemPk);

  // Alice computes X25519 shared secret with Bob's public key
  final aliceX25519SsA = Uint8List.fromList(
    await (await x25519.sharedSecretKey(
      keyPair: aliceX25519Kp,
      remotePublicKey: bobX25519Pub,
    )).extractBytes(),
  );

  // Alice derives hybrid key
  final aliceHybridA = await deriveHybridKey(aliceMlkemSsA, aliceX25519SsA);

  // Bob decapsulates the ML-KEM ciphertext
  final bobMlkemSsA = pq.decapsulate(bobMlkemSk, mlkemCtA);

  // Bob computes X25519 shared secret with Alice's public key
  final bobX25519SsA = Uint8List.fromList(
    await (await x25519.sharedSecretKey(
      keyPair: bobX25519Kp,
      remotePublicKey: aliceX25519Pub,
    )).extractBytes(),
  );

  // Bob derives hybrid key
  final bobHybridA = await deriveHybridKey(bobMlkemSsA, bobX25519SsA);

  print('  ML-KEM SS (Alice): ${hex(aliceMlkemSsA)}');
  print('  ML-KEM SS (Bob):   ${hex(bobMlkemSsA)}');
  print('  X25519 SS (Alice): ${hex(aliceX25519SsA)}');
  print('  X25519 SS (Bob):   ${hex(bobX25519SsA)}');
  print('  Hybrid key (Alice): ${hex(aliceHybridA, maxBytes: 32)}');
  print('  Hybrid key (Bob):   ${hex(bobHybridA, maxBytes: 32)}');
  check('pqcrypto ML-KEM-768 shared secrets match', bytesEqual(aliceMlkemSsA, bobMlkemSsA));
  check('cryptography X25519 shared secrets match', bytesEqual(aliceX25519SsA, bobX25519SsA));
  check('Test A: pure-Dart hybrid keys match', bytesEqual(aliceHybridA, bobHybridA));

  // ── Test B: OpenSSL ML-KEM-768 + cryptography X25519 (cross-impl hybrid) ──
  //
  // Same protocol as Test A, but the ML-KEM side is split across implementations:
  //   Alice encapsulates with pqcrypto, Bob decapsulates with OpenSSL (or vice versa).
  // This ensures the hybrid key agreement survives even when Alice and Bob use
  // different ML-KEM implementations — as long as both are FIPS 203 compliant.
  //
  // Sub-test B1: Bob's ML-KEM keypair via OpenSSL, Alice encapsulates via pqcrypto
  // Sub-test B2: Bob's ML-KEM keypair via pqcrypto, Alice encapsulates via OpenSSL
  //
  print('\n--- Test B1: OpenSSL keygen + pqcrypto encaps + OpenSSL decaps (hybrid) ---');

  final (opensslPkB1, opensslSkB1) = ossl.generateKeypair();
  final bobX25519KpB1 = await x25519.newKeyPair();
  final bobX25519PubB1 = await bobX25519KpB1.extractPublicKey();
  final aliceX25519KpB1 = await x25519.newKeyPair();
  final aliceX25519PubB1 = await aliceX25519KpB1.extractPublicKey();

  // Alice: pqcrypto encaps against OpenSSL public key
  final (mlkemCtB1, aliceMlkemSsB1) = pq.encapsulate(opensslPkB1);

  final aliceX25519SsB1 = Uint8List.fromList(
    await (await x25519.sharedSecretKey(
      keyPair: aliceX25519KpB1,
      remotePublicKey: bobX25519PubB1,
    )).extractBytes(),
  );
  final aliceHybridB1 = await deriveHybridKey(aliceMlkemSsB1, aliceX25519SsB1);

  // Bob: OpenSSL decaps
  final bobMlkemSsB1 = ossl.decapsulate(opensslSkB1, mlkemCtB1);
  ossl.freeKey(opensslSkB1);

  final bobX25519SsB1 = Uint8List.fromList(
    await (await x25519.sharedSecretKey(
      keyPair: bobX25519KpB1,
      remotePublicKey: aliceX25519PubB1,
    )).extractBytes(),
  );
  final bobHybridB1 = await deriveHybridKey(bobMlkemSsB1, bobX25519SsB1);

  print('  ML-KEM SS (Alice/pqcrypto): ${hex(aliceMlkemSsB1)}');
  print('  ML-KEM SS (Bob/OpenSSL):    ${hex(bobMlkemSsB1)}');
  print('  Hybrid key (Alice): ${hex(aliceHybridB1, maxBytes: 32)}');
  print('  Hybrid key (Bob):   ${hex(bobHybridB1, maxBytes: 32)}');
  check('Test B1: ML-KEM SS match (OpenSSL keygen / pqcrypto encaps / OpenSSL decaps)', bytesEqual(aliceMlkemSsB1, bobMlkemSsB1));
  check('Test B1: hybrid keys match', bytesEqual(aliceHybridB1, bobHybridB1));

  print('\n--- Test B2: pqcrypto keygen + OpenSSL encaps + pqcrypto decaps (hybrid) ---');

  final (pqPkB2, pqSkB2) = pq.generateKeyPair();
  final bobX25519KpB2 = await x25519.newKeyPair();
  final bobX25519PubB2 = await bobX25519KpB2.extractPublicKey();
  final aliceX25519KpB2 = await x25519.newKeyPair();
  final aliceX25519PubB2 = await aliceX25519KpB2.extractPublicKey();

  // Alice: OpenSSL encaps against pqcrypto public key
  final opensslImportedPkB2 = ossl.importPublicKey(Uint8List.fromList(pqPkB2));
  final (mlkemCtB2, aliceMlkemSsB2) = ossl.encapsulate(opensslImportedPkB2);
  ossl.freeKey(opensslImportedPkB2);

  final aliceX25519SsB2 = Uint8List.fromList(
    await (await x25519.sharedSecretKey(
      keyPair: aliceX25519KpB2,
      remotePublicKey: bobX25519PubB2,
    )).extractBytes(),
  );
  final aliceHybridB2 = await deriveHybridKey(aliceMlkemSsB2, aliceX25519SsB2);

  // Bob: pqcrypto decaps
  final bobMlkemSsB2 = pq.decapsulate(pqSkB2, mlkemCtB2);

  final bobX25519SsB2 = Uint8List.fromList(
    await (await x25519.sharedSecretKey(
      keyPair: bobX25519KpB2,
      remotePublicKey: aliceX25519PubB2,
    )).extractBytes(),
  );
  final bobHybridB2 = await deriveHybridKey(bobMlkemSsB2, bobX25519SsB2);

  print('  ML-KEM SS (Alice/OpenSSL):  ${hex(aliceMlkemSsB2)}');
  print('  ML-KEM SS (Bob/pqcrypto):   ${hex(bobMlkemSsB2)}');
  print('  Hybrid key (Alice): ${hex(aliceHybridB2, maxBytes: 32)}');
  print('  Hybrid key (Bob):   ${hex(bobHybridB2, maxBytes: 32)}');
  check('Test B2: ML-KEM SS match (pqcrypto keygen / OpenSSL encaps / pqcrypto decaps)', bytesEqual(aliceMlkemSsB2, bobMlkemSsB2));
  check('Test B2: hybrid keys match', bytesEqual(aliceHybridB2, bobHybridB2));

  // ── Summary ───────────────────────────────────────────────────────────────
  print('\n=== Summary ===');
  if (_failures.isEmpty) {
    print('[PASS] All tests passed.');
    print('The hybrid X25519 + ML-KEM-768 key agreement works correctly:');
    print('  - Pure-Dart (pqcrypto + cryptography) derives identical hybrid keys');
    print('  - Cross-impl (OpenSSL ML-KEM-768 + cryptography X25519) derives identical hybrid keys');
    print('  - IKM order: mlkem_ss || x25519_ss  →  HKDF-SHA256  →  32-byte hybrid key');
  } else {
    print('[FAIL] ${_failures.length} test(s) failed:');
    for (final f in _failures) {
      print('  - $f');
    }
  }
}
