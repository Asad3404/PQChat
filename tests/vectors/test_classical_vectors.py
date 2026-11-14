"""Published test vectors for the classical primitives (PROJECT-BRIEF.md §8)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pqchat.crypto import aead, kdf
from pqchat.crypto.dh import X25519KeyPair

h = bytes.fromhex


# RFC 7748 §6.1 (Alice/Bob) and §5.2 (single scalar multiplication)
def test_x25519_rfc7748_alice_bob() -> None:
    alice = X25519KeyPair.from_private_bytes(
        h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    )
    bob = X25519KeyPair.from_private_bytes(
        h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    )
    assert alice.public == h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert bob.public == h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert alice.dh(bob.public) == shared
    assert bob.dh(alice.public) == shared


def test_x25519_rfc7748_section_5_2() -> None:
    k = X25519KeyPair.from_private_bytes(
        h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    )
    u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    assert k.dh(u) == h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")


# RFC 5869 Appendix A
@pytest.mark.parametrize(
    ("ikm", "salt", "info", "length", "okm"),
    [
        (
            "0b" * 22,
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            42,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            "0b" * 22,
            "",
            "",
            42,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    ],
    ids=["tc1", "tc3"],
)
def test_hkdf_rfc5869(ikm: str, salt: str, info: str, length: int, okm: str) -> None:
    assert kdf.hkdf(h(ikm), h(salt), h(info), length) == h(okm)


# RFC 4231 §4.2, §4.3
@pytest.mark.parametrize(
    ("key", "data", "mac"),
    [
        (
            "0b" * 20,
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe".hex(),
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
    ],
    ids=["tc1", "tc2"],
)
def test_hmac_sha256_rfc4231(key: str, data: bytes, mac: str) -> None:
    assert kdf.hmac_sha256(h(key), data) == h(mac)
    assert kdf.verify_hmac(h(key), data, h(mac))


# McGrew & Viega, "The Galois/Counter Mode of Operation", test cases 13-16 (AES-256)
K15 = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
P15 = (
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
)
C15 = (
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
)


@pytest.mark.parametrize(
    ("key", "iv", "pt", "ad", "ct", "tag"),
    [
        ("00" * 32, "00" * 12, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"),
        (
            "00" * 32,
            "00" * 12,
            "00" * 16,
            "",
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        ),
        (K15, "cafebabefacedbaddecaf888", P15, "", C15, "b094dac5d93471bdec1a502270e3cc6c"),
        (
            K15,
            "cafebabefacedbaddecaf888",
            P15[:120],
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            C15[:120],
            "76fc6ece0f4e1768cddf8853bb2d551b",
        ),
    ],
    ids=["tc13", "tc14", "tc15", "tc16"],
)
def test_aes256gcm_vectors(key: str, iv: str, pt: str, ad: str, ct: str, tag: str) -> None:
    sealed = aead.seal(h(key), h(iv), h(pt), h(ad))
    assert sealed == h(ct + tag)
    assert aead.open_(h(key), h(iv), sealed, h(ad)) == h(pt)


# RFC 8032 §7.1 tests 1 and 2 (validates the pyca primitive our wrapper uses)
@pytest.mark.parametrize(
    ("sk", "pk", "msg", "sig"),
    [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ],
    ids=["test1", "test2"],
)
def test_ed25519_rfc8032(sk: str, pk: str, msg: str, sig: str) -> None:
    key = Ed25519PrivateKey.from_private_bytes(h(sk))
    assert key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == h(pk)
    assert key.sign(h(msg)) == h(sig)
