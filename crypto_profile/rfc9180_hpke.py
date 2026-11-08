# -*- coding: utf-8 -*-
"""
RFC 9180 - Hybrid Public Key Encryption (HPKE)
==============================================================================
Module dùng chung để ĐỒNG THỐNG toàn repo về RFC 9180 (thay cho 2 kiểu KDF
phân kỳ trước đây: HPKE-pyhpke ở wrapDEK/APIinstall/counttimescript và
HKDF standalone 5869 ở threshold wrap/combine).

Cài đúng các mục của RFC:
  * Section 4     : LabeledExtract / LabeledExpand (suite_id + nhãn "HPKE-v1")
  * Section 4.1   : DHKEM(X25519, HKDF-SHA256) - Encap/Decap/ExtractAndExpand
                    (kem_id = 0x0020, suite_id KEM = "KEM" || kem_id)
  * Section 5.1   : KeySchedule base mode (mode = 0x00) -> key, base_nonce,
                    exporter_secret (suite_id HPKE = "HPKE" || kem || kdf || aead)
  * Section 5.2   : Seal/Open với nonce = base_nonce XOR I2OSP(seq, Nn)
  * Appendix A.1.1: self_test() kiểm chứng với test vector chính thức
                    DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.

Hai điểm dùng trong repo:
  1. HPKEPerUser (stage5_baseline_compare.py)  -> encap/decap/key_schedule_base
  2. Threshold wrap key (wrap_dek_partial_decryption.py + ablation) ->
     derive_wrap_key(): shared_secret = K (Lagrange), info = AAD của wrap,
     key lấy từ KeySchedule base - cùng bộ nhãn với HPKE nên KDF "đồng nhất".

Thư viện: chỉ hmac/hashlib + cryptography (X25519, AESGCM). Không phụ thuộc
pyhpke (môi trường này không cài được - 196).
"""

import hashlib
import hmac
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --- Bộ nhận diện (RFC 9180 §7: 2 byte mỗi loại) -----------------------------
MODE_BASE = 0x00
KEM_ID = 0x0020                 # DHKEM(X25519, HKDF-SHA256)
KDF_ID = 0x0001                 # HKDF-SHA256
AEAD_ID_AES_128 = 0x0001        # AES-128-GCM  (vector A.1)
AEAD_ID_AES_256 = 0x0002        # AES-256-GCM  (suite của repo: pyhpke + HPKEPerUser)
NENC = 32                       # Nenc/Npk/Nsk của X25519
NSECRET = 32                    # Nsecret = Nh = 32 (HKDF-SHA256)
NN = 12                         # Nn của AES-GCM
NK = {AEAD_ID_AES_128: 16, AEAD_ID_AES_256: 32}
NH = 32


# =============================================================================
# §4 - LabeledExtract / LabeledExpand
# =============================================================================
def i2osp(x: int, length: int) -> bytes:
    """Integer to Octet String Primitive (RFC 8017)."""
    return x.to_bytes(length, "big")


def _extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 §2.2) = HMAC-Hash(salt, ikm)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 §2.3)."""
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def labeled_extract(suite_id: bytes, salt: bytes, label: bytes,
                    ikm: bytes) -> bytes:
    """RFC 9180 §4: Extract(salt, concat("HPKE-v1", suite_id, label, ikm))."""
    return _extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes,
                   length: int) -> bytes:
    """RFC 9180 §4: Expand(prk, concat(I2OSP(L,2), "HPKE-v1", suite_id, ...))."""
    labeled_info = i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info
    return _expand(prk, labeled_info, length)


def kem_suite_id(kem_id: int = KEM_ID) -> bytes:
    """RFC 9180 §4.1: suite_id = concat("KEM", I2OSP(kem_id, 2))."""
    return b"KEM" + i2osp(kem_id, 2)


def hpke_suite_id(kem_id: int = KEM_ID, kdf_id: int = KDF_ID,
                  aead_id: int = AEAD_ID_AES_256) -> bytes:
    """RFC 9180 §5.1: suite_id = concat("HPKE", kem_id, kdf_id, aead_id)."""
    return b"HPKE" + i2osp(kem_id, 2) + i2osp(kdf_id, 2) + i2osp(aead_id, 2)


# =============================================================================
# §4.1 - DHKEM(X25519, HKDF-SHA256)
# =============================================================================
def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    """DHKEM.ExtractAndExpand: eae_prk -> shared_secret (32B)."""
    suite = kem_suite_id()
    eae_prk = labeled_extract(suite, b"", b"eae_prk", dh)
    return labeled_expand(suite, eae_prk, b"shared_secret", kem_context,
                          NSECRET)


def _pk_raw(pub) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def encap(pk_r: bytes, sk_e: Optional[x25519.X25519PrivateKey] = None
          ) -> Tuple[bytes, bytes]:
    """RFC 9180 §4.1 Encap -> (shared_secret, enc). pk_r: raw 32B."""
    sk_e = sk_e or x25519.X25519PrivateKey.generate()
    enc = _pk_raw(sk_e.public_key())
    dh = sk_e.exchange(x25519.X25519PublicKey.from_public_bytes(pk_r))
    kem_context = enc + pk_r
    return _extract_and_expand(dh, kem_context), enc


def decap(enc: bytes, sk_r: x25519.X25519PrivateKey) -> bytes:
    """RFC 9180 §4.1 Decap -> shared_secret."""
    pk_e = x25519.X25519PublicKey.from_public_bytes(enc)
    dh = sk_r.exchange(pk_e)
    kem_context = enc + _pk_raw(sk_r.public_key())
    return _extract_and_expand(dh, kem_context)


# =============================================================================
# §5.1/§5.2 - KeySchedule base + Seal/Open
# =============================================================================
def key_schedule_base(shared_secret: bytes, info: bytes,
                      aead_id: int = AEAD_ID_AES_256
                      ) -> Tuple[bytes, bytes, bytes]:
    """
    RFC 9180 §5.1 KeySchedule(mode=base): psk/psk_id rỗng (default).
    -> (key [Nk], base_nonce [Nn], exporter_secret [Nh]).
    """
    suite = hpke_suite_id(aead_id=aead_id)
    psk_id_hash = labeled_extract(suite, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(suite, b"", b"info_hash", info)
    ksc = i2osp(MODE_BASE, 1) + psk_id_hash + info_hash
    secret = labeled_extract(suite, shared_secret, b"secret", b"")
    key = labeled_expand(suite, secret, b"key", ksc, NK[aead_id])
    base_nonce = labeled_expand(suite, secret, b"base_nonce", ksc, NN)
    exporter = labeled_expand(suite, secret, b"exp", ksc, NH)
    return key, base_nonce, exporter


def seq_nonce(base_nonce: bytes, seq: int) -> bytes:
    """RFC 9180 §5.2: nonce = base_nonce XOR I2OSP(seq, Nn)."""
    return bytes(a ^ b for a, b in zip(base_nonce, i2osp(seq, NN)))


def seal(key: bytes, nonce: bytes, pt: bytes, aad: bytes) -> bytes:
    """RFC 9180 §5.2 Seal (AES-GCM)."""
    return AESGCM(key).encrypt(nonce, pt, aad)


def open_(key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    """RFC 9180 §5.2 Open (AES-GCM)."""
    return AESGCM(key).decrypt(nonce, ct, aad)


def derive_wrap_key(shared_secret: bytes, info: bytes) -> bytes:
    """
    Điểm đồng nhất giữa HPKE và threshold pipeline: derive wrap_key bằng
    ĐÚNG KeySchedule base (RFC 9180 §5.1) với suite DHKEM(X25519,HKDF-SHA256)
    / HKDF-SHA256 / AES-256-GCM (0x0020/0x0001/0x0002 - trùng bộ pyhpke):
      shared_secret = K (điểm Lagrange), info = AAD gắn (object, epoch, root).
    Trả về key 32B; nonce wrap vẫn lưu riêng trong ThresholdWrappedDEK.
    """
    key, _, _ = key_schedule_base(shared_secret, info, AEAD_ID_AES_256)
    return key


# =============================================================================
# Appendix A.1.1 - TEST VECTOR CHÍNH THỨC (RFC 9180)
# =============================================================================
_VECTOR = {
    "info": "4f6465206f6e2061204772656369616e2055726e",
    "pkRm": "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
    "skRm": "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
    "enc": "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    "shared_secret":
        "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
    "key": "4531685d41d65f03dc48f6b8302c05b0",
    "base_nonce": "56d890e5accaaf011cff4b7d",
    "exporter_secret":
        "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
    "pt": "4265617574792069732074727574682c20747275746820626561757479",
    "aad0": "436f756e742d30",
    "ct0": "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
           "6d8770ac83d07bea87e13c512a",
    "nonce1": "56d890e5accaaf011cff4b7c",
    "aad1": "436f756e742d31",
    "ct1": "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab25"
           "1c03d0c22a56b8ca42c2063b84",
}


def self_test_vector() -> List[Tuple[str, bool]]:
    """
    Kiểm chứng implementation với vector Appendix A.1.1 của RFC 9180
    (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode):
    khóa công khai, Decap, KeySchedule, Seal (seq 0) và nonce seq 1.
    """
    h = lambda k: bytes.fromhex(_VECTOR[k])
    results: List[Tuple[str, bool]] = []

    sk_r = x25519.X25519PrivateKey.from_private_bytes(h("skRm"))
    results.append(("pkRm tu skRm dung", _pk_raw(sk_r.public_key()) == h("pkRm")))

    ss = decap(h("enc"), sk_r)
    results.append(("Decap -> shared_secret dung", ss == h("shared_secret")))

    key, nonce, exporter = key_schedule_base(ss, h("info"),
                                             AEAD_ID_AES_128)
    results.append(("KeySchedule -> key dung", key == h("key")))
    results.append(("KeySchedule -> base_nonce dung", nonce == h("base_nonce")))
    results.append(("KeySchedule -> exporter_secret dung",
                    exporter == h("exporter_secret")))

    ct0 = seal(key, nonce, h("pt"), h("aad0"))
    results.append(("Seal seq=0 -> ct dung", ct0 == h("ct0")))

    n1 = seq_nonce(nonce, 1)
    results.append(("seq nonce=1 dung", n1 == h("nonce1")))
    ct1 = seal(key, n1, h("pt"), h("aad1"))
    results.append(("Seal seq=1 -> ct dung", ct1 == h("ct1")))

    try:
        open_(key, nonce, h("ct0"), b"Count-X")
        results.append(("Open bi tu choi khi aad sai", False))
    except Exception:
        results.append(("Open bi tu choi khi aad sai", True))
    return results


if __name__ == "__main__":
    ok = 0
    for name, passed in self_test_vector():
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok += 1 if passed else 0
    total = len(self_test_vector())
    print(f"\n  {ok}/{total} - RFC 9180 Appendix A.1.1 test vector")
