# hybrid

End-to-end hybrid key exchange test: **X25519** (classical) + **ML-KEM-768** (post-quantum), combined via **HKDF-SHA256**.

## What it tests

Three tests in two groups:

| Test | ML-KEM-768 keygen | ML-KEM-768 encaps | ML-KEM-768 decaps | X25519 |
|------|-------------------|-------------------|-------------------|--------|
| **A** | pqcrypto | pqcrypto | pqcrypto | cryptography |
| **B1** | OpenSSL | pqcrypto | OpenSSL | cryptography |
| **B2** | pqcrypto | OpenSSL | pqcrypto | cryptography |

Test A is a pure-Dart sanity check — no native libraries needed for the KEM side. Tests B1 and B2 are the meaningful cross-implementation checks: they verify the hybrid key agreement still produces identical 32-byte keys when Alice and Bob use different ML-KEM-768 implementations. X25519 is always provided by the `cryptography` package (pure Dart).

## Protocol

For each test, Alice and Bob run the following:

```
Bob generates:
  (bob_mlkem_pk, bob_mlkem_sk)  ← ML-KEM-768 keygen
  (bob_x25519_pk, bob_x25519_sk) ← X25519 keygen

Alice:
  (mlkem_ct, alice_mlkem_ss) ← ML-KEM-768 encaps(bob_mlkem_pk)
  alice_x25519_ss ← X25519(alice_x25519_sk, bob_x25519_pk)
  alice_hybrid_key ← HKDF-SHA256(IKM = alice_mlkem_ss || alice_x25519_ss,
                                  salt = [],
                                  info = "hybrid-x25519-mlkem768")

Bob:
  bob_mlkem_ss ← ML-KEM-768 decaps(bob_mlkem_sk, mlkem_ct)
  bob_x25519_ss ← X25519(bob_x25519_sk, alice_x25519_pk)
  bob_hybrid_key ← HKDF-SHA256(IKM = bob_mlkem_ss || bob_x25519_ss,
                                salt = [],
                                info = "hybrid-x25519-mlkem768")

Assert: alice_hybrid_key == bob_hybrid_key  (32 bytes)
```

**IKM concatenation order**: ML-KEM shared secret first, X25519 second — matching the `X25519MLKEM768` convention from the TLS 1.3 hybrid key share draft and RFC 9180.

## Result

```
[PASS] pqcrypto ML-KEM-768 shared secrets match
[PASS] cryptography X25519 shared secrets match
[PASS] Test A: pure-Dart hybrid keys match
[PASS] Test B1: ML-KEM SS match (OpenSSL keygen / pqcrypto encaps / OpenSSL decaps)
[PASS] Test B1: hybrid keys match
[PASS] Test B2: ML-KEM SS match (pqcrypto keygen / OpenSSL encaps / pqcrypto decaps)
[PASS] Test B2: hybrid keys match
```

## Prerequisites

### Dart SDK ≥ 3.11

```sh
dart --version
```

### OpenSSL 3.6 via Homebrew

```sh
brew install openssl@3.6
```

The test loads `/opt/homebrew/opt/openssl@3.6/lib/libcrypto.dylib` directly.

### Patched pqcrypto fork

`pubspec.yaml` pins the fork via git ref:

```yaml
dependency_overrides:
  pqcrypto:
    git:
      url: https://github.com/JeremyTubongbanua/pqcrypto
      ref: 4572b3b
```

This fork contains four FIPS 203 conformance fixes. See
[`../openssl_pqcrypto_interop`](../openssl_pqcrypto_interop) for the
compliance test that verifies those fixes against OpenSSL directly.

## Run

**Fresh:**
```sh
cd /Users/jeremytubongbanua/GitHub/snippets/pqc/hybrid && dart pub get && dart run bin/hybrid.dart
```

**Quick** (deps already resolved):
```sh
dart run bin/hybrid.dart
```

## Dependencies

| Package | Purpose |
|---------|---------|
| [`pqcrypto`](https://pub.dev/packages/pqcrypto) | Pure-Dart ML-KEM-768 (patched fork) |
| [`cryptography`](https://pub.dev/packages/cryptography) | Pure-Dart X25519 + HKDF-SHA256 |
| [`ffi`](https://pub.dev/packages/ffi) | `calloc` allocator for OpenSSL FFI bindings |
| OpenSSL 3.6 (`libcrypto.dylib`) | Reference ML-KEM-768 implementation for cross-impl tests |

## Relationship to the interop test

[`../openssl_pqcrypto_interop`](../openssl_pqcrypto_interop) answers:
> "Is pqcrypto's ML-KEM-768 byte-compatible with OpenSSL?"

This test answers:
> "Does the hybrid key agreement work end-to-end when ML-KEM-768 implementations are mixed?"

Both questions must be answered before using this construction in production.
