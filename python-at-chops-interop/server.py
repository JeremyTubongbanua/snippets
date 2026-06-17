"""
XWing interop server (Python / OpenSSL 3 via ctypes)

Protocol
--------
1. Server generates an X-Wing key pair (ML-KEM-768 + X25519).
2. Server sends the 1216-byte public key to the client.
3. Client sends back a framed message:
       [4-byte big-endian length] [ciphertext (1120 B)] [12-byte GCM nonce] [GCM ciphertext + 16-byte tag]
4. Server decapsulates the X-Wing ciphertext to get the 32-byte shared secret,
   then uses it as the AES-256-GCM key to decrypt the client's message.
5. Server prints the plaintext and sends back "OK\n".

X-Wing spec: draft-connolly-cfrg-xwing-kem-10
  public key  = pk_M (1184 B) || pk_X (32 B)        = 1216 B
  ciphertext  = ct_M (1088 B) || ct_X (32 B)         = 1120 B
  shared_secret = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
  XWingLabel  = b'\\.//' + b'^\\' (6 bytes)

Combiner implemented in pure Python using hashlib; ML-KEM-768 and X25519
are done through OpenSSL 3 EVP APIs via ctypes.
"""

import ctypes
import hashlib
import hmac
import os
import socket
import struct
import sys

# ── OpenSSL libcrypto ────────────────────────────────────────────────────────

_LIBCRYPTO_PATHS = [
    "/opt/homebrew/lib/libcrypto.dylib",   # macOS Homebrew Apple Silicon
    "/usr/local/lib/libcrypto.dylib",       # macOS Homebrew Intel
    "libcrypto.so.3",                       # Linux OpenSSL 3
    "libcrypto.so",                         # Linux generic
]


def _load_libcrypto() -> ctypes.CDLL:
    env = os.environ.get("AT_CHOPS_LIBCRYPTO_PATH")
    if env:
        try:
            return ctypes.CDLL(env)
        except OSError:
            print(f"warning: AT_CHOPS_LIBCRYPTO_PATH={env!r} failed to load", file=sys.stderr)
    for path in _LIBCRYPTO_PATHS:
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue
    raise RuntimeError("Could not load libcrypto. Set AT_CHOPS_LIBCRYPTO_PATH.")


_lib = _load_libcrypto()

# EVP helpers
_lib.EVP_PKEY_CTX_new_from_name.restype = ctypes.c_void_p
_lib.EVP_PKEY_CTX_new_from_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]

_lib.EVP_PKEY_CTX_free.restype = None
_lib.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]

_lib.EVP_PKEY_keygen_init.restype = ctypes.c_int
_lib.EVP_PKEY_keygen_init.argtypes = [ctypes.c_void_p]

_lib.EVP_PKEY_keygen.restype = ctypes.c_int
_lib.EVP_PKEY_keygen.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]

_lib.EVP_PKEY_free.restype = None
_lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]

_lib.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int
_lib.EVP_PKEY_get_raw_public_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.EVP_PKEY_get_raw_private_key.restype = ctypes.c_int
_lib.EVP_PKEY_get_raw_private_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.EVP_PKEY_new_raw_private_key_ex.restype = ctypes.c_void_p
_lib.EVP_PKEY_new_raw_private_key_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]

_lib.EVP_PKEY_CTX_new.restype = ctypes.c_void_p
_lib.EVP_PKEY_CTX_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_lib.EVP_PKEY_derive_init.restype = ctypes.c_int
_lib.EVP_PKEY_derive_init.argtypes = [ctypes.c_void_p]

_lib.EVP_PKEY_derive_set_peer.restype = ctypes.c_int
_lib.EVP_PKEY_derive_set_peer.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_lib.EVP_PKEY_derive.restype = ctypes.c_int
_lib.EVP_PKEY_derive.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.EVP_PKEY_encapsulate.restype = ctypes.c_int
_lib.EVP_PKEY_encapsulate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.EVP_PKEY_decapsulate.restype = ctypes.c_int
_lib.EVP_PKEY_decapsulate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t]

_lib.EVP_PKEY_new_raw_public_key_ex.restype = ctypes.c_void_p
_lib.EVP_PKEY_new_raw_public_key_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]

# AES-256-GCM
_lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
_lib.EVP_CIPHER_CTX_new.argtypes = []

_lib.EVP_CIPHER_CTX_free.restype = None
_lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

_lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
_lib.EVP_aes_256_gcm.argtypes = []

_lib.EVP_DecryptInit_ex.restype = ctypes.c_int
_lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

_lib.EVP_DecryptUpdate.restype = ctypes.c_int
_lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]

_lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
_lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]

_lib.EVP_DecryptFinal_ex.restype = ctypes.c_int
_lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]

EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_SET_TAG = 0x11
EVP_CTRL_GCM_GET_TAG = 0x10

# ── X-Wing constants ─────────────────────────────────────────────────────────

_XWING_LABEL = b"\x5c\x2e\x2f\x2f\x5e\x5c"  # b'\.//^\' (6 bytes)
_MLKEM768_PK_LEN = 1184
_MLKEM768_CT_LEN = 1088
_X25519_KEY_LEN  = 32
_XWING_PK_LEN    = _MLKEM768_PK_LEN + _X25519_KEY_LEN   # 1216
_XWING_CT_LEN    = _MLKEM768_CT_LEN + _X25519_KEY_LEN   # 1120
_XWING_SS_LEN    = 32

# ── SHAKE-256 seed expansion ─────────────────────────────────────────────────

def _expand_seed(seed: bytes) -> tuple[bytes, bytes]:
    """SHAKE-256(seed, 96 bytes) → (mlkem_seed_64B, x25519_sk_32B)."""
    shake = hashlib.shake_256(seed)
    expanded = shake.digest(96)
    return expanded[:64], expanded[64:96]


# ── ML-KEM-768 via OpenSSL EVP ───────────────────────────────────────────────

def _mlkem768_generate_from_seed(seed_64: bytes) -> tuple[bytes, bytes]:
    """Generate ML-KEM-768 key pair from a 64-byte (d||z) seed."""
    ctx = _lib.EVP_PKEY_CTX_new_from_name(None, b"ML-KEM-768", None)
    if not ctx:
        raise RuntimeError("EVP_PKEY_CTX_new_from_name(ML-KEM-768) failed")
    try:
        # Set the seed parameter before keygen
        _lib.EVP_PKEY_keygen_init(ctx)

        # Use EVP_PKEY_CTX_set_params to pass the seed
        _lib.EVP_PKEY_CTX_set_params.restype = ctypes.c_int
        _lib.EVP_PKEY_CTX_set_params.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        # Build an OSSL_PARAM array: seed param
        _lib.OSSL_PARAM_construct_octet_string.restype = ctypes.c_void_p  # we build manually
        # Use the raw keygen with the param approach via OSSL_PARAM_BLD
        _lib.OSSL_PARAM_BLD_new.restype = ctypes.c_void_p
        _lib.OSSL_PARAM_BLD_new.argtypes = []
        _lib.OSSL_PARAM_BLD_free.restype = None
        _lib.OSSL_PARAM_BLD_free.argtypes = [ctypes.c_void_p]
        _lib.OSSL_PARAM_BLD_push_octet_string.restype = ctypes.c_int
        _lib.OSSL_PARAM_BLD_push_octet_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        _lib.OSSL_PARAM_BLD_to_param.restype = ctypes.c_void_p
        _lib.OSSL_PARAM_BLD_to_param.argtypes = [ctypes.c_void_p]
        _lib.OSSL_PARAM_free.restype = None
        _lib.OSSL_PARAM_free.argtypes = [ctypes.c_void_p]

        bld = _lib.OSSL_PARAM_BLD_new()
        if not bld:
            raise RuntimeError("OSSL_PARAM_BLD_new failed")
        try:
            rc = _lib.OSSL_PARAM_BLD_push_octet_string(bld, b"seed", seed_64, len(seed_64))
            if rc != 1:
                raise RuntimeError("OSSL_PARAM_BLD_push_octet_string(seed) failed")
            params = _lib.OSSL_PARAM_BLD_to_param(bld)
            if not params:
                raise RuntimeError("OSSL_PARAM_BLD_to_param failed")
            try:
                rc = _lib.EVP_PKEY_CTX_set_params(ctx, params)
                if rc != 1:
                    raise RuntimeError("EVP_PKEY_CTX_set_params(seed) failed")
            finally:
                _lib.OSSL_PARAM_free(params)
        finally:
            _lib.OSSL_PARAM_BLD_free(bld)

        pkey_ptr = ctypes.c_void_p(None)
        rc = _lib.EVP_PKEY_keygen(ctx, ctypes.byref(pkey_ptr))
        if rc != 1:
            raise RuntimeError("EVP_PKEY_keygen(ML-KEM-768) failed")
        pkey = pkey_ptr.value
        try:
            pk = _get_raw_public_key(pkey, _MLKEM768_PK_LEN)
            sk_len = ctypes.c_size_t(4096)
            sk_buf = ctypes.create_string_buffer(4096)
            rc = _lib.EVP_PKEY_get_raw_private_key(pkey, sk_buf, ctypes.byref(sk_len))
            if rc != 1:
                raise RuntimeError("EVP_PKEY_get_raw_private_key(ML-KEM-768) failed")
            sk = bytes(sk_buf[:sk_len.value])
            return pk, sk
        finally:
            _lib.EVP_PKEY_free(pkey)
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)


def _mlkem768_decapsulate(sk_bytes: bytes, ct: bytes) -> bytes:
    """ML-KEM-768 decapsulation using a raw secret key."""
    pkey = _lib.EVP_PKEY_new_raw_private_key_ex(None, b"ML-KEM-768", None, sk_bytes, len(sk_bytes))
    if not pkey:
        raise RuntimeError("EVP_PKEY_new_raw_private_key_ex(ML-KEM-768) failed")
    try:
        ctx = _lib.EVP_PKEY_CTX_new(pkey, None)
        if not ctx:
            raise RuntimeError("EVP_PKEY_CTX_new failed")
        try:
            _lib.EVP_PKEY_decapsulate_init.restype = ctypes.c_int
            _lib.EVP_PKEY_decapsulate_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            rc = _lib.EVP_PKEY_decapsulate_init(ctx, None)
            if rc != 1:
                raise RuntimeError("EVP_PKEY_decapsulate_init failed")
            ss_len = ctypes.c_size_t(64)
            ss_buf = ctypes.create_string_buffer(64)
            rc = _lib.EVP_PKEY_decapsulate(ctx, ss_buf, ctypes.byref(ss_len), ct, len(ct))
            if rc != 1:
                raise RuntimeError("EVP_PKEY_decapsulate failed")
            return bytes(ss_buf[:ss_len.value])
        finally:
            _lib.EVP_PKEY_CTX_free(ctx)
    finally:
        _lib.EVP_PKEY_free(pkey)


# ── X25519 via OpenSSL EVP ───────────────────────────────────────────────────

def _x25519_public_from_private(sk_bytes: bytes) -> bytes:
    """Derive X25519 public key from raw 32-byte private key."""
    pkey = _lib.EVP_PKEY_new_raw_private_key_ex(None, b"X25519", None, sk_bytes, len(sk_bytes))
    if not pkey:
        raise RuntimeError("EVP_PKEY_new_raw_private_key_ex(X25519) failed")
    try:
        return _get_raw_public_key(pkey, _X25519_KEY_LEN)
    finally:
        _lib.EVP_PKEY_free(pkey)


def _x25519_dh(sk_bytes: bytes, peer_pk_bytes: bytes) -> bytes:
    """X25519 DH: returns 32-byte shared secret."""
    sk_pkey = _lib.EVP_PKEY_new_raw_private_key_ex(None, b"X25519", None, sk_bytes, len(sk_bytes))
    if not sk_pkey:
        raise RuntimeError("EVP_PKEY_new_raw_private_key_ex(X25519) failed")
    peer_pkey = _lib.EVP_PKEY_new_raw_public_key_ex(None, b"X25519", None, peer_pk_bytes, len(peer_pk_bytes))
    if not peer_pkey:
        _lib.EVP_PKEY_free(sk_pkey)
        raise RuntimeError("EVP_PKEY_new_raw_public_key_ex(X25519) failed")
    try:
        ctx = _lib.EVP_PKEY_CTX_new(sk_pkey, None)
        if not ctx:
            raise RuntimeError("EVP_PKEY_CTX_new failed")
        try:
            rc = _lib.EVP_PKEY_derive_init(ctx)
            if rc != 1:
                raise RuntimeError("EVP_PKEY_derive_init failed")
            rc = _lib.EVP_PKEY_derive_set_peer(ctx, peer_pkey)
            if rc != 1:
                raise RuntimeError("EVP_PKEY_derive_set_peer failed")
            ss_len = ctypes.c_size_t(32)
            ss_buf = ctypes.create_string_buffer(32)
            rc = _lib.EVP_PKEY_derive(ctx, ss_buf, ctypes.byref(ss_len))
            if rc != 1:
                raise RuntimeError("EVP_PKEY_derive failed")
            return bytes(ss_buf[:ss_len.value])
        finally:
            _lib.EVP_PKEY_CTX_free(ctx)
    finally:
        _lib.EVP_PKEY_free(sk_pkey)
        _lib.EVP_PKEY_free(peer_pkey)


def _get_raw_public_key(pkey: int, expected_len: int) -> bytes:
    pk_len = ctypes.c_size_t(expected_len)
    pk_buf = ctypes.create_string_buffer(expected_len)
    rc = _lib.EVP_PKEY_get_raw_public_key(pkey, pk_buf, ctypes.byref(pk_len))
    if rc != 1:
        raise RuntimeError("EVP_PKEY_get_raw_public_key failed")
    return bytes(pk_buf[:pk_len.value])


# ── X-Wing combiner ──────────────────────────────────────────────────────────

def _xwing_combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    """SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)."""
    data = ss_m + ss_x + ct_x + pk_x + _XWING_LABEL
    return hashlib.sha3_256(data).digest()


# ── X-Wing key pair generation ───────────────────────────────────────────────

def xwing_generate_keypair(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Generate an X-Wing key pair.

    Returns (public_key: 1216 B, secret_key: 32-byte seed).
    The secret key IS the seed; all other state is re-derived on decapsulation.
    """
    if seed is None:
        seed = os.urandom(32)
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")

    mlkem_seed, x25519_sk = _expand_seed(seed)
    mlkem_pk, _mlkem_sk = _mlkem768_generate_from_seed(mlkem_seed)
    x25519_pk = _x25519_public_from_private(x25519_sk)

    public_key = mlkem_pk + x25519_pk  # 1184 + 32 = 1216
    return public_key, seed


# ── X-Wing decapsulation ─────────────────────────────────────────────────────

def xwing_decapsulate(secret_key_seed: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate an X-Wing ciphertext.

    secret_key_seed: 32-byte seed (the secret key returned by xwing_generate_keypair)
    ciphertext: 1120-byte X-Wing ciphertext
    Returns: 32-byte shared secret
    """
    if len(secret_key_seed) != 32:
        raise ValueError("secret_key_seed must be 32 bytes")
    if len(ciphertext) != _XWING_CT_LEN:
        raise ValueError(f"ciphertext must be {_XWING_CT_LEN} bytes")

    mlkem_seed, x25519_sk = _expand_seed(secret_key_seed)
    _mlkem_pk, mlkem_sk = _mlkem768_generate_from_seed(mlkem_seed)
    x25519_pk = _x25519_public_from_private(x25519_sk)

    ct_m = ciphertext[:_MLKEM768_CT_LEN]
    ct_x = ciphertext[_MLKEM768_CT_LEN:]

    ss_m = _mlkem768_decapsulate(mlkem_sk, ct_m)
    ss_x = _x25519_dh(x25519_sk, ct_x)

    return _xwing_combine(ss_m, ss_x, ct_x, x25519_pk)


# ── AES-256-GCM decryption ───────────────────────────────────────────────────

def aes256gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    """Decrypt AES-256-GCM. ciphertext_with_tag = ciphertext || 16-byte tag."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if len(ciphertext_with_tag) < 16:
        raise ValueError("ciphertext_with_tag too short")

    ct = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    ctx = _lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = _lib.EVP_aes_256_gcm()
        rc = _lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None)
        if rc != 1:
            raise RuntimeError("EVP_DecryptInit_ex(init) failed")
        # Set IV length to 12
        rc = _lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, None)
        if rc != 1:
            raise RuntimeError("EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed")
        rc = _lib.EVP_DecryptInit_ex(ctx, None, None, key, nonce)
        if rc != 1:
            raise RuntimeError("EVP_DecryptInit_ex(key+nonce) failed")
        # Set expected tag
        tag_buf = ctypes.create_string_buffer(tag, 16)
        rc = _lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_buf)
        if rc != 1:
            raise RuntimeError("EVP_CIPHER_CTX_ctrl(SET_TAG) failed")

        plaintext_buf = ctypes.create_string_buffer(len(ct) + 16)
        out_len = ctypes.c_int(0)
        rc = _lib.EVP_DecryptUpdate(ctx, plaintext_buf, ctypes.byref(out_len), ct, len(ct))
        if rc != 1:
            raise RuntimeError("EVP_DecryptUpdate failed")
        total = out_len.value

        final_buf = ctypes.create_string_buffer(16)
        final_len = ctypes.c_int(0)
        rc = _lib.EVP_DecryptFinal_ex(ctx, final_buf, ctypes.byref(final_len))
        if rc != 1:
            raise RuntimeError("EVP_DecryptFinal_ex failed — authentication tag mismatch!")
        total += final_len.value
        return bytes(plaintext_buf[:total])
    finally:
        _lib.EVP_CIPHER_CTX_free(ctx)


# ── Socket helpers ───────────────────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


# ── Main ─────────────────────────────────────────────────────────────────────

HOST = "127.0.0.1"
PORT = 9876


def main() -> None:
    print(f"[server] generating X-Wing key pair ...")
    pk, sk_seed = xwing_generate_keypair()
    print(f"[server] public key ({len(pk)} bytes): {pk.hex()[:64]}...")
    print(f"[server] listening on {HOST}:{PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        conn, addr = srv.accept()
        with conn:
            print(f"[server] connection from {addr}")

            # Step 1: send public key (no length prefix — size is fixed at 1216)
            conn.sendall(pk)
            print(f"[server] sent public key")

            # Step 2: receive framed payload
            #   [4-byte big-endian total_len] [1120-byte XWing ct] [12-byte nonce] [ct+tag]
            raw_len = _recv_exact(conn, 4)
            total_len = struct.unpack(">I", raw_len)[0]
            payload = _recv_exact(conn, total_len)

            xwing_ct = payload[:_XWING_CT_LEN]
            nonce    = payload[_XWING_CT_LEN : _XWING_CT_LEN + 12]
            aes_ct   = payload[_XWING_CT_LEN + 12:]

            print(f"[server] received payload ({total_len} bytes)")
            print(f"[server] XWing ciphertext ({len(xwing_ct)} bytes): {xwing_ct.hex()[:64]}...")
            print(f"[server] AES nonce:  {nonce.hex()}")
            print(f"[server] AES ct+tag: {aes_ct.hex()[:64]}...")

            # Step 3: decapsulate
            shared_secret = xwing_decapsulate(sk_seed, xwing_ct)
            print(f"[server] shared secret: {shared_secret.hex()}")

            # Step 4: decrypt
            plaintext = aes256gcm_decrypt(shared_secret, nonce, aes_ct)
            print(f"[server] decrypted message: {plaintext.decode()}")

            # Step 5: acknowledge
            conn.sendall(b"OK\n")
            print("[server] done")


if __name__ == "__main__":
    main()
