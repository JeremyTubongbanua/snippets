# python-at-chops-interop

Cross-language interoperability tests between Python (OpenSSL 3 via `ctypes`) and Dart (`at_chops 3.2.x` FFI) for post-quantum algorithms.

Both sides use the same underlying `libcrypto.dylib` (OpenSSL 3.6.2).

---

## Test 1 — XWing KEM (`server.py` + `dart_client/bin/client.dart`)

Implements `draft-connolly-cfrg-xwing-kem-10` (ML-KEM-768 + X25519).

```
Python server                          Dart client
     |                                      |
     |---- 1216-byte XWing public key ----->|
     |                                      | encapsulate(pk)
     |<--- [4B len][1120B ct][12B nonce]    |
     |     [AES-256-GCM ct+tag] -----------|
     | decapsulate(seed, ct)                |
     | AES-256-GCM decrypt                  |
     |---- "OK\n" ------------------------->|
```

- **Python server**: generates the XWing key pair, sends the public key, decapsulates the ciphertext, decrypts the AES-256-GCM message.
- **Dart client**: receives the public key, encapsulates to derive the shared secret, encrypts a message with AES-256-GCM, sends ciphertext.

### Run

Terminal 1:
```
cd ~/GitHub/snippets/python-at-chops-interop
python3 server.py
```

Terminal 2:
```
cd ~/GitHub/snippets/python-at-chops-interop/dart_client
dart run bin/client.dart
```

### Output

```
[server] generating X-Wing key pair ...
[server] public key (1216 bytes): fab321ab6b231499ca9087193ab80fd9685a35b55198e31e2bebbd31913ea1c7...
[server] listening on 127.0.0.1:9876
[server] connection from ('127.0.0.1', 58666)
[server] sent public key
[server] received payload (1191 bytes)
[server] XWing ciphertext (1120 bytes): a99c5c618c17b781bcd1b760d0091bd7848e542eebfae04dddedfb72c09d05d3...
[server] AES nonce:  ad3de6798f976d828ad7c12b
[server] AES ct+tag: 9384030d46aa7c7db117ed6bd7fe06876150a1ebda24365dff4dab14d302ba02...
[server] shared secret: 8d4a19a1683dd76fbb88fc22038ccaf85f60b51e18e5be66194c8be3d173c5b1
[server] decrypted message: Hello from Dart XWing FFI (at_chops 3.2.x)!
[server] done
```

```
[client] libcrypto loaded from: /opt/homebrew/lib/libcrypto.dylib
[client] connecting to 127.0.0.1:9876 ...
[client] connected
[client] received public key (1216 bytes): fab321ab6b231499ca9087193ab80fd9685a35b55198e31e2bebbd31913ea1c7...
[client] shared secret: 8d4a19a1683dd76fbb88fc22038ccaf85f60b51e18e5be66194c8be3d173c5b1
[client] ciphertext (1120 bytes): a99c5c618c17b781bcd1b760d0091bd7848e542eebfae04dddedfb72c09d05d3...
[client] plaintext: Hello from Dart XWing FFI (at_chops 3.2.x)!
[client] AES nonce:  ad3de6798f976d828ad7c12b
[client] AES ct+tag: 9384030d46aa7c7db117ed6bd7fe06876150a1ebda24365dff4dab14d302ba02...
[client] sent payload (1191 bytes + 4-byte length prefix)
[client] server response: OK
[client] SUCCESS — shared secrets match, message decrypted correctly
```

Both sides derive the same shared secret (`8d4a19a1...`), confirming cross-language XWing interoperability.

---

## Test 2 — ML-DSA-65 signatures (`mldsa_interop.py` + `dart_client/bin/mldsa_interop.dart`)

Implements FIPS 204 (ML-DSA-65). Tests both directions in a single connection.

```
Dart client                            Python server
     |                                      |
     |--- [4B][pk 1952B] ----------------->|
     |--- [4B][sig 3309B] ---------------->|  Round 1:
     |--- [4B][message] ----------------->|  Dart signs,
     |                                      |  Python verifies
     |<-- "OK\n" --------------------------|
     |                                      |
     |<-- [4B][pk 1952B] ------------------|
     |<-- [4B][sig 3309B] -----------------|  Round 2:
     |<-- [4B][message] ------------------|  Python signs,
     |                                      |  Dart verifies
     |--- "OK\n" ------------------------->|
```

- **Dart client**: generates a key pair, signs a message, sends to Python; then receives Python's public key + signature, verifies.
- **Python server**: verifies Dart's signature; generates its own key pair, signs a message, sends to Dart.

Key/signature sizes:
| Field      | Size    |
|------------|---------|
| Public key | 1952 B  |
| Secret key | 4032 B  |
| Signature  | 3309 B  |

### Run

Terminal 1:
```
cd ~/GitHub/snippets/python-at-chops-interop
python3 mldsa_interop.py
```

Terminal 2:
```
cd ~/GitHub/snippets/python-at-chops-interop/dart_client
dart run bin/mldsa_interop.dart
```

### Output

```
[dart] libcrypto loaded from: /opt/homebrew/lib/libcrypto.dylib
[dart] connecting to 127.0.0.1:9877 ...
[dart] connected

[dart] === Round 1: Dart signs, Python verifies ===
[dart] generated public key (1952 B): c5a0c93ff967ea00ac086a6e86193bdd677aadae0db6faf748a0ceddf662a048...
[dart] signature (3309 B): fbec8e41549343ce65c619202a2169a2c3fcfc01d413a75dce3266bbfea83d96...
[dart] message: Hello from Dart ML-DSA-65 FFI (at_chops 3.2.x)!
[dart] sent public key + signature + message
[dart] Python verify response: OK

[dart] === Round 2: Python signs, Dart verifies ===
[dart] received public key (1952 B): ff7969586cb7a4d68a0cf4ecc05c06feabcf953da7899809661b1005a06b83d1...
[dart] received signature  (3309 B): 5153e691a8da2c89ba4ad53fa0bdccafe302c511cb14feb581b70791a63eca9d...
[dart] received message:   Hello from Python ML-DSA-65 (OpenSSL 3 ctypes)!
[dart] verify result: true

[dart] SUCCESS — both directions verified correctly
```

```
[py-server] listening on 127.0.0.1:9877
[py-server] connection from ('127.0.0.1', 58767)

[py-server] === Round 1: Dart signs, Python verifies ===
[py-server] received public key (1952 B): c5a0c93ff967ea00ac086a6e86193bdd677aadae0db6faf748a0ceddf662a048...
[py-server] received signature  (3309 B): fbec8e41549343ce65c619202a2169a2c3fcfc01d413a75dce3266bbfea83d96...
[py-server] received message:   Hello from Dart ML-DSA-65 FFI (at_chops 3.2.x)!
[py-server] verify result: True

[py-server] === Round 2: Python signs, Dart verifies ===
[py-server] generated public key (1952 B): ff7969586cb7a4d68a0cf4ecc05c06feabcf953da7899809661b1005a06b83d1...
[py-server] signature (3309 B): 5153e691a8da2c89ba4ad53fa0bdccafe302c511cb14feb581b70791a63eca9d...
[py-server] message: Hello from Python ML-DSA-65 (OpenSSL 3 ctypes)!
[py-server] Dart verify response: OK
[py-server] SUCCESS — both directions verified correctly
```

Both directions verify correctly, confirming cross-language ML-DSA-65 interoperability.
