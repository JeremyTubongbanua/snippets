"""
ML-DSA-65 interoperability test (Python / OpenSSL 3 via ctypes)

Protocol (single TCP connection, both directions tested)
---------------------------------------------------------
Round 1 — Dart signs, Python verifies:
  Dart  → [4B pk_len][public_key (1952 B)]
        → [4B sig_len][signature (3309 B)]
        → [4B msg_len][message]
  Python verifies; sends b"OK\n" or b"FAIL\n"

Round 2 — Python signs, Dart verifies:
  Python → [4B pk_len][public_key (1952 B)]
         → [4B sig_len][signature (3309 B)]
         → [4B msg_len][message]
  Dart verifies; sends b"OK\n" or b"FAIL\n"
"""

import ctypes
import os
import socket
import struct
import sys

# ── OpenSSL libcrypto ────────────────────────────────────────────────────────

_LIBCRYPTO_PATHS = [
    "/opt/homebrew/lib/libcrypto.dylib",
    "/usr/local/lib/libcrypto.dylib",
    "libcrypto.so.3",
    "libcrypto.so",
]


def _load_libcrypto() -> ctypes.CDLL:
    env = os.environ.get("AT_CHOPS_LIBCRYPTO_PATH")
    if env:
        try:
            return ctypes.CDLL(env)
        except OSError:
            print(f"warning: AT_CHOPS_LIBCRYPTO_PATH={env!r} failed", file=sys.stderr)
    for path in _LIBCRYPTO_PATHS:
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue
    raise RuntimeError("Could not load libcrypto. Set AT_CHOPS_LIBCRYPTO_PATH.")


_lib = _load_libcrypto()

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

_lib.EVP_PKEY_new_raw_public_key_ex.restype = ctypes.c_void_p
_lib.EVP_PKEY_new_raw_public_key_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]

_lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
_lib.EVP_MD_CTX_new.argtypes = []

_lib.EVP_MD_CTX_free.restype = None
_lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]

_lib.EVP_DigestSignInit.restype = ctypes.c_int
_lib.EVP_DigestSignInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_lib.EVP_DigestSign.restype = ctypes.c_int
_lib.EVP_DigestSign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t]

_lib.EVP_DigestVerifyInit.restype = ctypes.c_int
_lib.EVP_DigestVerifyInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_lib.EVP_DigestVerify.restype = ctypes.c_int
_lib.EVP_DigestVerify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]

# ── ML-DSA-65 constants ───────────────────────────────────────────────────────

_MLDSA65_PK_LEN  = 1952
_MLDSA65_SK_LEN  = 4032
_MLDSA65_SIG_LEN = 3309

# ── ML-DSA-65 operations ──────────────────────────────────────────────────────

def mldsa65_generate_keypair() -> tuple[bytes, bytes]:
    """Returns (public_key: 1952 B, secret_key: 4032 B)."""
    ctx = _lib.EVP_PKEY_CTX_new_from_name(None, b"ML-DSA-65", None)
    if not ctx:
        raise RuntimeError("EVP_PKEY_CTX_new_from_name(ML-DSA-65) failed")
    try:
        if _lib.EVP_PKEY_keygen_init(ctx) <= 0:
            raise RuntimeError("EVP_PKEY_keygen_init failed")
        pkey_ptr = ctypes.c_void_p(None)
        if _lib.EVP_PKEY_keygen(ctx, ctypes.byref(pkey_ptr)) <= 0:
            raise RuntimeError("EVP_PKEY_keygen failed")
        pkey = pkey_ptr.value
        try:
            pk = _get_raw_public_key(pkey, _MLDSA65_PK_LEN)
            sk = _get_raw_private_key(pkey, _MLDSA65_SK_LEN)
            return pk, sk
        finally:
            _lib.EVP_PKEY_free(pkey)
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)


def mldsa65_sign(sk_bytes: bytes, message: bytes) -> bytes:
    """Sign message with raw 4032-byte secret key. Returns 3309-byte signature."""
    pkey = _lib.EVP_PKEY_new_raw_private_key_ex(None, b"ML-DSA-65", None, sk_bytes, len(sk_bytes))
    if not pkey:
        raise RuntimeError("EVP_PKEY_new_raw_private_key_ex(ML-DSA-65) failed")
    try:
        ctx = _lib.EVP_MD_CTX_new()
        if not ctx:
            raise RuntimeError("EVP_MD_CTX_new failed")
        try:
            if _lib.EVP_DigestSignInit(ctx, None, None, None, pkey) <= 0:
                raise RuntimeError("EVP_DigestSignInit failed")
            sig_len = ctypes.c_size_t(0)
            if _lib.EVP_DigestSign(ctx, None, ctypes.byref(sig_len), message, len(message)) <= 0:
                raise RuntimeError("EVP_DigestSign (size query) failed")
            sig_buf = ctypes.create_string_buffer(sig_len.value)
            if _lib.EVP_DigestSign(ctx, sig_buf, ctypes.byref(sig_len), message, len(message)) <= 0:
                raise RuntimeError("EVP_DigestSign failed")
            return bytes(sig_buf[:sig_len.value])
        finally:
            _lib.EVP_MD_CTX_free(ctx)
    finally:
        _lib.EVP_PKEY_free(pkey)


def mldsa65_verify(pk_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify signature over message against raw 1952-byte public key."""
    pkey = _lib.EVP_PKEY_new_raw_public_key_ex(None, b"ML-DSA-65", None, pk_bytes, len(pk_bytes))
    if not pkey:
        raise RuntimeError("EVP_PKEY_new_raw_public_key_ex(ML-DSA-65) failed")
    try:
        ctx = _lib.EVP_MD_CTX_new()
        if not ctx:
            raise RuntimeError("EVP_MD_CTX_new failed")
        try:
            if _lib.EVP_DigestVerifyInit(ctx, None, None, None, pkey) <= 0:
                raise RuntimeError("EVP_DigestVerifyInit failed")
            result = _lib.EVP_DigestVerify(ctx, signature, len(signature), message, len(message))
            return result == 1
        finally:
            _lib.EVP_MD_CTX_free(ctx)
    finally:
        _lib.EVP_PKEY_free(pkey)


def _get_raw_public_key(pkey: int, expected_len: int) -> bytes:
    pk_len = ctypes.c_size_t(expected_len)
    pk_buf = ctypes.create_string_buffer(expected_len)
    if _lib.EVP_PKEY_get_raw_public_key(pkey, pk_buf, ctypes.byref(pk_len)) <= 0:
        raise RuntimeError("EVP_PKEY_get_raw_public_key failed")
    return bytes(pk_buf[:pk_len.value])


def _get_raw_private_key(pkey: int, expected_len: int) -> bytes:
    sk_len = ctypes.c_size_t(expected_len)
    sk_buf = ctypes.create_string_buffer(expected_len)
    if _lib.EVP_PKEY_get_raw_private_key(pkey, sk_buf, ctypes.byref(sk_len)) <= 0:
        raise RuntimeError("EVP_PKEY_get_raw_private_key failed")
    return bytes(sk_buf[:sk_len.value])


# ── Socket helpers ────────────────────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def _recv_framed(sock: socket.socket) -> bytes:
    """Read a [4B big-endian length][data] frame."""
    raw_len = _recv_exact(sock, 4)
    n = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, n)


def _send_framed(sock: socket.socket, data: bytes) -> None:
    """Send a [4B big-endian length][data] frame."""
    sock.sendall(struct.pack(">I", len(data)) + data)


# ── Main ──────────────────────────────────────────────────────────────────────

HOST = "127.0.0.1"
PORT = 9877


def main() -> None:
    print(f"[py-server] listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        conn, addr = srv.accept()
        with conn:
            print(f"[py-server] connection from {addr}")

            # ── Round 1: Dart signs, Python verifies ──────────────────────────
            print("\n[py-server] === Round 1: Dart signs, Python verifies ===")

            dart_pk  = _recv_framed(conn)
            dart_sig = _recv_framed(conn)
            dart_msg = _recv_framed(conn)

            print(f"[py-server] received public key ({len(dart_pk)} B): {dart_pk.hex()[:64]}...")
            print(f"[py-server] received signature  ({len(dart_sig)} B): {dart_sig.hex()[:64]}...")
            print(f"[py-server] received message:   {dart_msg.decode()}")

            ok = mldsa65_verify(dart_pk, dart_msg, dart_sig)
            print(f"[py-server] verify result: {ok}")
            conn.sendall(b"OK\n" if ok else b"FAIL\n")
            if not ok:
                print("[py-server] FAIL — Dart signature did not verify in Python!", file=sys.stderr)
                return

            # ── Round 2: Python signs, Dart verifies ──────────────────────────
            print("\n[py-server] === Round 2: Python signs, Dart verifies ===")

            py_pk, py_sk = mldsa65_generate_keypair()
            py_msg = b"Hello from Python ML-DSA-65 (OpenSSL 3 ctypes)!"
            py_sig = mldsa65_sign(py_sk, py_msg)

            print(f"[py-server] generated public key ({len(py_pk)} B): {py_pk.hex()[:64]}...")
            print(f"[py-server] signature ({len(py_sig)} B): {py_sig.hex()[:64]}...")
            print(f"[py-server] message: {py_msg.decode()}")

            _send_framed(conn, py_pk)
            _send_framed(conn, py_sig)
            _send_framed(conn, py_msg)

            response = _recv_exact(conn, 3).decode().strip()
            print(f"[py-server] Dart verify response: {response}")
            if response == "OK":
                print("[py-server] SUCCESS — both directions verified correctly")
            else:
                print("[py-server] FAIL — Dart rejected Python's signature", file=sys.stderr)


if __name__ == "__main__":
    main()
