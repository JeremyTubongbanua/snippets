"""
Matrix interop server — Python side

Tests all 4 × 4 implementation combinations for XWing KEM and ML-DSA-65:
  Python impls:  pure_python, openssl_ffi
  Dart impls:    pure_dart,   dart_ffi       (declared by Dart over the wire)

Protocol (single TCP connection)
---------------------------------
The server drives the outer loop; Dart responds to each round.

For XWing (4 rounds, one per python_impl × dart_impl pair — Dart tells us
its impl label, Python uses whichever impl the round dictates):

  Each round:
    S→D  [1B: python_impl index 0..1]
         [1B: dart_impl index  0..1]   (which Dart impl to use next)
         [2B: pk_len big-endian]
         [pk_len bytes: XWing public key from *python* impl]
    D→S  [4B: ct_len][ciphertext]      (Dart encapsulates with declared impl)
         [4B: ss_len][shared_secret_dart]
    S    decapsulates → derives ss_python
    S→D  [1B: 1=match / 0=mismatch]

For ML-DSA-65 (4 rounds):

  Each round:
    S→D  [1B: python_impl index]
         [1B: dart_impl index]
    Sub-round A — Python signs, Dart verifies:
      S→D  [4B: pk_len][pk]
           [4B: sig_len][sig]
           [4B: msg_len][msg]
      D→S  [1B: 1=ok / 0=fail]
    Sub-round B — Dart signs, Python verifies:
      D→S  [4B: pk_len][pk]
           [4B: sig_len][sig]
           [4B: msg_len][msg]
      S→D  [1B: 1=ok / 0=fail]

After all rounds: S→D [1B: 0xFF] as end-of-session marker.
"""

import ctypes
import hashlib
import os
import socket
import struct
import sys

# ── venv path fix ─────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_VENV = os.path.join(_HERE, ".venv")
_SITE = None
for _root, _dirs, _files in os.walk(os.path.join(_VENV, "lib")):
    if _root.endswith("site-packages"):
        _SITE = _root
        break
if _SITE and _SITE not in sys.path:
    sys.path.insert(0, _SITE)

# ── Pure-Python imports ───────────────────────────────────────────────────────
from mlkem import ml_kem as _mlkem_mod, parameter_set as _mlkem_ps
from dilithium_py.ml_dsa import ML_DSA_65 as _DilithiumMlDsa65

_mlkem = _mlkem_mod.ML_KEM(_mlkem_ps.ML_KEM_768)

# ── OpenSSL libcrypto ─────────────────────────────────────────────────────────

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
            pass
    for path in _LIBCRYPTO_PATHS:
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue
    raise RuntimeError("Could not load libcrypto.")


_lib = _load_libcrypto()

_lib.EVP_PKEY_CTX_new_from_name.restype  = ctypes.c_void_p
_lib.EVP_PKEY_CTX_new_from_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.EVP_PKEY_CTX_free.restype  = None
_lib.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]
_lib.EVP_PKEY_keygen_init.restype  = ctypes.c_int
_lib.EVP_PKEY_keygen_init.argtypes = [ctypes.c_void_p]
_lib.EVP_PKEY_keygen.restype  = ctypes.c_int
_lib.EVP_PKEY_keygen.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
_lib.EVP_PKEY_free.restype  = None
_lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
_lib.EVP_PKEY_get_raw_public_key.restype  = ctypes.c_int
_lib.EVP_PKEY_get_raw_public_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
_lib.EVP_PKEY_get_raw_private_key.restype  = ctypes.c_int
_lib.EVP_PKEY_get_raw_private_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
_lib.EVP_PKEY_new_raw_private_key_ex.restype  = ctypes.c_void_p
_lib.EVP_PKEY_new_raw_private_key_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
_lib.EVP_PKEY_new_raw_public_key_ex.restype  = ctypes.c_void_p
_lib.EVP_PKEY_new_raw_public_key_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
_lib.EVP_PKEY_CTX_new.restype  = ctypes.c_void_p
_lib.EVP_PKEY_CTX_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_lib.EVP_PKEY_derive_init.restype  = ctypes.c_int
_lib.EVP_PKEY_derive_init.argtypes = [ctypes.c_void_p]
_lib.EVP_PKEY_derive_set_peer.restype  = ctypes.c_int
_lib.EVP_PKEY_derive_set_peer.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_lib.EVP_PKEY_derive.restype  = ctypes.c_int
_lib.EVP_PKEY_derive.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
_lib.EVP_PKEY_decapsulate_init.restype  = ctypes.c_int
_lib.EVP_PKEY_decapsulate_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_lib.EVP_PKEY_decapsulate.restype  = ctypes.c_int
_lib.EVP_PKEY_decapsulate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t]
_lib.EVP_MD_CTX_new.restype  = ctypes.c_void_p
_lib.EVP_MD_CTX_new.argtypes = []
_lib.EVP_MD_CTX_free.restype  = None
_lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
_lib.EVP_DigestSignInit.restype  = ctypes.c_int
_lib.EVP_DigestSignInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_lib.EVP_DigestSign.restype  = ctypes.c_int
_lib.EVP_DigestSign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t]
_lib.EVP_DigestVerifyInit.restype  = ctypes.c_int
_lib.EVP_DigestVerifyInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_lib.EVP_DigestVerify.restype  = ctypes.c_int
_lib.EVP_DigestVerify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
_lib.OSSL_PARAM_BLD_new.restype  = ctypes.c_void_p
_lib.OSSL_PARAM_BLD_new.argtypes = []
_lib.OSSL_PARAM_BLD_free.restype  = None
_lib.OSSL_PARAM_BLD_free.argtypes = [ctypes.c_void_p]
_lib.OSSL_PARAM_BLD_push_octet_string.restype  = ctypes.c_int
_lib.OSSL_PARAM_BLD_push_octet_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
_lib.OSSL_PARAM_BLD_to_param.restype  = ctypes.c_void_p
_lib.OSSL_PARAM_BLD_to_param.argtypes = [ctypes.c_void_p]
_lib.OSSL_PARAM_free.restype  = None
_lib.OSSL_PARAM_free.argtypes = [ctypes.c_void_p]
_lib.EVP_PKEY_CTX_set_params.restype  = ctypes.c_int
_lib.EVP_PKEY_CTX_set_params.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

# ── X-Wing constants ──────────────────────────────────────────────────────────

_XWING_LABEL      = b"\x5c\x2e\x2f\x2f\x5e\x5c"
_MLKEM768_PK_LEN  = 1184
_MLKEM768_CT_LEN  = 1088
_X25519_KEY_LEN   = 32
_XWING_PK_LEN     = 1216
_XWING_CT_LEN     = 1120

# ── OpenSSL helpers ───────────────────────────────────────────────────────────

def _ossl_raw_pubkey(pkey: int, expected: int) -> bytes:
    n = ctypes.c_size_t(expected)
    buf = ctypes.create_string_buffer(expected)
    if _lib.EVP_PKEY_get_raw_public_key(pkey, buf, ctypes.byref(n)) <= 0:
        raise RuntimeError("EVP_PKEY_get_raw_public_key failed")
    return bytes(buf[:n.value])

def _ossl_raw_privkey(pkey: int, expected: int) -> bytes:
    n = ctypes.c_size_t(expected)
    buf = ctypes.create_string_buffer(expected)
    if _lib.EVP_PKEY_get_raw_private_key(pkey, buf, ctypes.byref(n)) <= 0:
        raise RuntimeError("EVP_PKEY_get_raw_private_key failed")
    return bytes(buf[:n.value])


# ── X-Wing combiner ───────────────────────────────────────────────────────────

def _xwing_combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _XWING_LABEL).digest()

def _expand_seed(seed: bytes) -> tuple[bytes, bytes]:
    exp = hashlib.shake_256(seed).digest(96)
    return exp[:64], exp[64:96]

# ── XWing: pure Python ────────────────────────────────────────────────────────

def _x25519_pubkey_from_privkey_ossl(sk: bytes) -> bytes:
    pkey = _lib.EVP_PKEY_new_raw_private_key_ex(None, b"X25519", None, sk, len(sk))
    if not pkey:
        raise RuntimeError("EVP_PKEY_new_raw_private_key_ex(X25519) failed")
    try:
        return _ossl_raw_pubkey(pkey, _X25519_KEY_LEN)
    finally:
        _lib.EVP_PKEY_free(pkey)

def _x25519_dh_ossl(sk: bytes, peer_pk: bytes) -> bytes:
    sk_pkey   = _lib.EVP_PKEY_new_raw_private_key_ex(None, b"X25519", None, sk, len(sk))
    peer_pkey = _lib.EVP_PKEY_new_raw_public_key_ex(None, b"X25519", None, peer_pk, len(peer_pk))
    if not sk_pkey or not peer_pkey:
        raise RuntimeError("EVP_PKEY_new_raw_*_key_ex(X25519) failed")
    try:
        ctx = _lib.EVP_PKEY_CTX_new(sk_pkey, None)
        if not ctx:
            raise RuntimeError("EVP_PKEY_CTX_new failed")
        try:
            _lib.EVP_PKEY_derive_init(ctx)
            _lib.EVP_PKEY_derive_set_peer(ctx, peer_pkey)
            n = ctypes.c_size_t(32)
            buf = ctypes.create_string_buffer(32)
            _lib.EVP_PKEY_derive(ctx, buf, ctypes.byref(n))
            return bytes(buf[:n.value])
        finally:
            _lib.EVP_PKEY_CTX_free(ctx)
    finally:
        _lib.EVP_PKEY_free(sk_pkey)
        _lib.EVP_PKEY_free(peer_pkey)

def xwing_keygen_pure(seed: bytes | None = None) -> tuple[bytes, bytes]:
    if seed is None:
        seed = os.urandom(32)
    mlkem_seed, x25519_sk = _expand_seed(seed)
    d, z = mlkem_seed[:32], mlkem_seed[32:]
    ek, _dk = _mlkem._key_gen(d, z)
    pk_x = _x25519_pubkey_from_privkey_ossl(x25519_sk)
    return ek + pk_x, seed

def xwing_decaps_pure(seed: bytes, ct: bytes) -> bytes:
    mlkem_seed, x25519_sk = _expand_seed(seed)
    d, z = mlkem_seed[:32], mlkem_seed[32:]
    ek, dk = _mlkem._key_gen(d, z)
    pk_x = _x25519_pubkey_from_privkey_ossl(x25519_sk)
    ct_m, ct_x = ct[:_MLKEM768_CT_LEN], ct[_MLKEM768_CT_LEN:]
    ss_m = _mlkem.decaps(dk, ct_m)
    ss_x = _x25519_dh_ossl(x25519_sk, ct_x)
    return _xwing_combine(ss_m, ss_x, ct_x, pk_x)

# ── XWing: OpenSSL FFI ────────────────────────────────────────────────────────

def _mlkem768_keygen_from_seed_ossl(seed_64: bytes) -> tuple[bytes, bytes]:
    ctx = _lib.EVP_PKEY_CTX_new_from_name(None, b"ML-KEM-768", None)
    if not ctx:
        raise RuntimeError("EVP_PKEY_CTX_new_from_name(ML-KEM-768) failed")
    try:
        _lib.EVP_PKEY_keygen_init(ctx)
        bld = _lib.OSSL_PARAM_BLD_new()
        try:
            _lib.OSSL_PARAM_BLD_push_octet_string(bld, b"seed", seed_64, len(seed_64))
            params = _lib.OSSL_PARAM_BLD_to_param(bld)
            try:
                _lib.EVP_PKEY_CTX_set_params(ctx, params)
            finally:
                _lib.OSSL_PARAM_free(params)
        finally:
            _lib.OSSL_PARAM_BLD_free(bld)
        pkey_ptr = ctypes.c_void_p(None)
        if _lib.EVP_PKEY_keygen(ctx, ctypes.byref(pkey_ptr)) <= 0:
            raise RuntimeError("EVP_PKEY_keygen(ML-KEM-768) failed")
        pkey = pkey_ptr.value
        try:
            pk = _ossl_raw_pubkey(pkey, _MLKEM768_PK_LEN)
            n  = ctypes.c_size_t(4096)
            buf = ctypes.create_string_buffer(4096)
            _lib.EVP_PKEY_get_raw_private_key(pkey, buf, ctypes.byref(n))
            sk = bytes(buf[:n.value])
            return pk, sk
        finally:
            _lib.EVP_PKEY_free(pkey)
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)

def _mlkem768_decaps_ossl(sk: bytes, ct: bytes) -> bytes:
    pkey = _lib.EVP_PKEY_new_raw_private_key_ex(None, b"ML-KEM-768", None, sk, len(sk))
    if not pkey:
        raise RuntimeError("EVP_PKEY_new_raw_private_key_ex(ML-KEM-768) failed")
    try:
        ctx = _lib.EVP_PKEY_CTX_new(pkey, None)
        try:
            _lib.EVP_PKEY_decapsulate_init(ctx, None)
            n   = ctypes.c_size_t(64)
            buf = ctypes.create_string_buffer(64)
            if _lib.EVP_PKEY_decapsulate(ctx, buf, ctypes.byref(n), ct, len(ct)) <= 0:
                raise RuntimeError("EVP_PKEY_decapsulate failed")
            return bytes(buf[:n.value])
        finally:
            _lib.EVP_PKEY_CTX_free(ctx)
    finally:
        _lib.EVP_PKEY_free(pkey)

def xwing_keygen_ffi(seed: bytes | None = None) -> tuple[bytes, bytes]:
    if seed is None:
        seed = os.urandom(32)
    mlkem_seed, x25519_sk = _expand_seed(seed)
    mlkem_pk, _mlkem_sk = _mlkem768_keygen_from_seed_ossl(mlkem_seed)
    pk_x = _x25519_pubkey_from_privkey_ossl(x25519_sk)
    return mlkem_pk + pk_x, seed

def xwing_decaps_ffi(seed: bytes, ct: bytes) -> bytes:
    mlkem_seed, x25519_sk = _expand_seed(seed)
    _mlkem_pk, mlkem_sk = _mlkem768_keygen_from_seed_ossl(mlkem_seed)
    pk_x = _x25519_pubkey_from_privkey_ossl(x25519_sk)
    ct_m, ct_x = ct[:_MLKEM768_CT_LEN], ct[_MLKEM768_CT_LEN:]
    ss_m = _mlkem768_decaps_ossl(mlkem_sk, ct_m)
    ss_x = _x25519_dh_ossl(x25519_sk, ct_x)
    return _xwing_combine(ss_m, ss_x, ct_x, pk_x)

# ── ML-DSA-65: pure Python ────────────────────────────────────────────────────

def mldsa65_keygen_pure() -> tuple[bytes, bytes]:
    pk, sk = _DilithiumMlDsa65.keygen()
    return pk, sk

def mldsa65_sign_pure(sk: bytes, msg: bytes) -> bytes:
    return _DilithiumMlDsa65.sign(sk, msg)

def mldsa65_verify_pure(pk: bytes, msg: bytes, sig: bytes) -> bool:
    return _DilithiumMlDsa65.verify(pk, msg, sig)

# ── ML-DSA-65: OpenSSL FFI ────────────────────────────────────────────────────

def mldsa65_keygen_ffi() -> tuple[bytes, bytes]:
    ctx = _lib.EVP_PKEY_CTX_new_from_name(None, b"ML-DSA-65", None)
    if not ctx:
        raise RuntimeError("EVP_PKEY_CTX_new_from_name(ML-DSA-65) failed")
    try:
        _lib.EVP_PKEY_keygen_init(ctx)
        pkey_ptr = ctypes.c_void_p(None)
        if _lib.EVP_PKEY_keygen(ctx, ctypes.byref(pkey_ptr)) <= 0:
            raise RuntimeError("EVP_PKEY_keygen(ML-DSA-65) failed")
        pkey = pkey_ptr.value
        try:
            pk = _ossl_raw_pubkey(pkey, 1952)
            sk = _ossl_raw_privkey(pkey, 4032)
            return pk, sk
        finally:
            _lib.EVP_PKEY_free(pkey)
    finally:
        _lib.EVP_PKEY_CTX_free(ctx)

def mldsa65_sign_ffi(sk: bytes, msg: bytes) -> bytes:
    pkey = _lib.EVP_PKEY_new_raw_private_key_ex(None, b"ML-DSA-65", None, sk, len(sk))
    if not pkey:
        raise RuntimeError("EVP_PKEY_new_raw_private_key_ex(ML-DSA-65) failed")
    try:
        ctx = _lib.EVP_MD_CTX_new()
        try:
            _lib.EVP_DigestSignInit(ctx, None, None, None, pkey)
            n = ctypes.c_size_t(0)
            _lib.EVP_DigestSign(ctx, None, ctypes.byref(n), msg, len(msg))
            buf = ctypes.create_string_buffer(n.value)
            if _lib.EVP_DigestSign(ctx, buf, ctypes.byref(n), msg, len(msg)) <= 0:
                raise RuntimeError("EVP_DigestSign failed")
            return bytes(buf[:n.value])
        finally:
            _lib.EVP_MD_CTX_free(ctx)
    finally:
        _lib.EVP_PKEY_free(pkey)

def mldsa65_verify_ffi(pk: bytes, msg: bytes, sig: bytes) -> bool:
    pkey = _lib.EVP_PKEY_new_raw_public_key_ex(None, b"ML-DSA-65", None, pk, len(pk))
    if not pkey:
        raise RuntimeError("EVP_PKEY_new_raw_public_key_ex(ML-DSA-65) failed")
    try:
        ctx = _lib.EVP_MD_CTX_new()
        try:
            _lib.EVP_DigestVerifyInit(ctx, None, None, None, pkey)
            return _lib.EVP_DigestVerify(ctx, sig, len(sig), msg, len(msg)) == 1
        finally:
            _lib.EVP_MD_CTX_free(ctx)
    finally:
        _lib.EVP_PKEY_free(pkey)

# ── Dispatch tables ───────────────────────────────────────────────────────────

PY_IMPLS = ["pure_python", "openssl_ffi"]

XWING_KEYGEN  = [xwing_keygen_pure,  xwing_keygen_ffi]
XWING_DECAPS  = [xwing_decaps_pure,  xwing_decaps_ffi]

MLDSA_KEYGEN  = [mldsa65_keygen_pure,  mldsa65_keygen_ffi]
MLDSA_SIGN    = [mldsa65_sign_pure,    mldsa65_sign_ffi]
MLDSA_VERIFY  = [mldsa65_verify_pure,  mldsa65_verify_ffi]

DART_IMPLS = ["pure_dart", "dart_ffi"]

# ── Socket helpers ────────────────────────────────────────────────────────────

def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)

def _recv_framed(s: socket.socket) -> bytes:
    n = struct.unpack(">I", _recv_exact(s, 4))[0]
    return _recv_exact(s, n)

def _send_framed(s: socket.socket, data: bytes) -> None:
    s.sendall(struct.pack(">I", len(data)) + data)

# ── Main ──────────────────────────────────────────────────────────────────────

HOST = "127.0.0.1"
PORT = 9878
PASS = "✓"
FAIL = "✗"


def main() -> None:
    print(f"[server] listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        conn, addr = srv.accept()
        with conn:
            print(f"[server] connection from {addr}\n")

            xwing_results:  list[tuple[str, str, str]] = []
            mldsa_results:  list[tuple[str, str, str, str]] = []

            # ── XWing matrix ──────────────────────────────────────────────────
            print("=" * 60)
            print("XWing KEM matrix (Python generates keypair, Dart encapsulates)")
            print("=" * 60)

            for py_idx, py_impl in enumerate(PY_IMPLS):
                for dart_idx, dart_impl in enumerate(DART_IMPLS):
                    # Tell Dart which python impl and which dart impl to use
                    conn.sendall(bytes([py_idx, dart_idx]))

                    pk, seed = XWING_KEYGEN[py_idx]()
                    # Send pk length (2B) + pk
                    conn.sendall(struct.pack(">H", len(pk)) + pk)

                    ct      = _recv_framed(conn)
                    ss_dart = _recv_framed(conn)

                    ss_py = XWING_DECAPS[py_idx](seed, ct)
                    match = ss_py == ss_dart

                    conn.sendall(bytes([1 if match else 0]))

                    icon = PASS if match else FAIL
                    label = f"py={py_impl:<12} dart={dart_impl}"
                    print(f"  {icon}  {label}   ss={ss_py.hex()[:16]}...")
                    xwing_results.append((py_impl, dart_impl, icon))

            # ── ML-DSA-65 matrix ──────────────────────────────────────────────
            print()
            print("=" * 60)
            print("ML-DSA-65 matrix (both directions per combo)")
            print("=" * 60)

            for py_idx, py_impl in enumerate(PY_IMPLS):
                for dart_idx, dart_impl in enumerate(DART_IMPLS):
                    conn.sendall(bytes([py_idx, dart_idx]))

                    # Sub-round A: Python signs, Dart verifies
                    py_pk, py_sk = MLDSA_KEYGEN[py_idx]()
                    py_msg = f"py={py_impl} → dart={dart_impl}".encode()
                    py_sig = MLDSA_SIGN[py_idx](py_sk, py_msg)
                    _send_framed(conn, py_pk)
                    _send_framed(conn, py_sig)
                    _send_framed(conn, py_msg)
                    dart_ok_a = _recv_exact(conn, 1)[0] == 1

                    # Sub-round B: Dart signs, Python verifies
                    dart_pk  = _recv_framed(conn)
                    dart_sig = _recv_framed(conn)
                    dart_msg = _recv_framed(conn)
                    py_ok_b = MLDSA_VERIFY[py_idx](dart_pk, dart_msg, dart_sig)
                    conn.sendall(bytes([1 if py_ok_b else 0]))

                    icon_a = PASS if dart_ok_a else FAIL
                    icon_b = PASS if py_ok_b   else FAIL
                    label  = f"py={py_impl:<12} dart={dart_impl}"
                    print(f"  py→dart {icon_a}  dart→py {icon_b}   {label}")
                    mldsa_results.append((py_impl, dart_impl, icon_a, icon_b))

            # End-of-session marker
            conn.sendall(bytes([0xFF]))

            # ── Summary ───────────────────────────────────────────────────────
            print()
            print("=" * 60)
            print("SUMMARY")
            print("=" * 60)
            all_pass = True

            print("\nXWing KEM:")
            for py_impl, dart_impl, icon in xwing_results:
                print(f"  {icon}  py={py_impl:<12} × dart={dart_impl}")
                if icon == FAIL:
                    all_pass = False

            print("\nML-DSA-65:")
            for py_impl, dart_impl, icon_a, icon_b in mldsa_results:
                print(f"  py→dart {icon_a}  dart→py {icon_b}   py={py_impl:<12} × dart={dart_impl}")
                if FAIL in (icon_a, icon_b):
                    all_pass = False

            print()
            print("ALL PASS" if all_pass else "SOME FAILURES — see above")


if __name__ == "__main__":
    main()
