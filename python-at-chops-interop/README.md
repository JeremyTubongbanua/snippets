# python-at-chops-interop

XWing interoperability test between Python (OpenSSL 3 via `ctypes`) and Dart (`at_chops 3.2.x` FFI).

Both sides implement `draft-connolly-cfrg-xwing-kem-10` (ML-KEM-768 + X25519) using the same underlying `libcrypto.dylib` (OpenSSL 3.6.2).

## Protocol

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

- **Python server**: generates the XWing key pair, sends the public key, decapsulates the ciphertext, decrypts the message.
- **Dart client**: receives the public key, encapsulates to derive the shared secret, encrypts a message with AES-256-GCM, sends ciphertext.

## Run

Terminal 1 — start the server:

```
cd ~/GitHub/snippets/python-at-chops-interop
python3 server.py
```

Terminal 2 — run the client:

```
cd ~/GitHub/snippets/python-at-chops-interop/dart_client
dart run bin/client.dart
```

## Output

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
