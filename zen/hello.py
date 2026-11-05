"""Bun (BoringSSL) ClientHello'sunu bayt bayt üret. manual-tls'in gen_client_hello'sunun yerine geçer.
Kaynak: 26 Eki 2026 pcap (zen katmanı → opencode.ai). Uzantı sırası: 0,23,65281,10,11,35,16,5,13,18,51,45,43,41(yok: PSK yalnız bilet varken)."""
import struct
from . import kripto as _K
def hkdf_finished_key(binder_key): return _K.derive_secret(b"finished", binder_key, b"", 32)

CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
GROUPS = [0x11ec, 0x001d, 0x0017, 0x0018]          # Bun: X25519MLKEM768, X25519, P-256, P-384
SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]   # OpenCode 2.0.26 ClientHello (27 Eki 2026 tcpdump): 9 algoritma; 0x0807/0x0603 YOK (JA4 imza hash'i bunlarla bozuluyordu)

def _u16(n): return struct.pack(">H", n)
def _ext(t, v): return _u16(t) + _u16(len(v)) + v

def client_hello(host: str, client_random: bytes, p256_x: int, p256_y: int, x25519_acik: bytes = b"", mlkem_ek: bytes = b"", psk=None, session_id: bytes = b"") -> bytes:
    """psk = (bilet, obfuscated_age, binder_key, early_secret) verilirse uzantı 41 sona eklenir; binder = HMAC(binder_key, hash(hello[:binder öncesi]))."""
    sni = host.encode(); sni_liste = b"\x00" + _u16(len(sni)) + sni
    p256 = b"\x04" + p256_x.to_bytes(32, "big") + p256_y.to_bytes(32, "big")
    hibrit = (_u16(0x11ec) + _u16(1184 + 32) + mlkem_ek + x25519_acik) if mlkem_ek else b""   # RFC 10024: ML-KEM ek (1184) || X25519 (32)
    key_share_ic = hibrit + (_u16(0x001d) + _u16(32) + x25519_acik if x25519_acik else b"")   # Bun: yalnız hibrit + X25519 anahtarı (P-256 ilan edilir, anahtar yollanmaz)
    if not x25519_acik: key_share_ic += _u16(0x0017) + _u16(len(p256)) + p256
    uzantilar = (
        _ext(0, _u16(len(sni_liste)) + sni_liste)                      # server_name
        + _ext(23, b"")                                                # extended_master_secret
        + _ext(65281, b"\x00")                                         # renegotiation_info
        + _ext(10, _u16(len(GROUPS) * 2) + b"".join(_u16(g) for g in GROUPS))   # supported_groups
        + _ext(11, b"\x01\x00")                                        # ec_point_formats: uncompressed
        + _ext(35, b"")                                                # session_ticket
        + _ext(16, _u16(9) + b"\x08http/1.1")                          # ALPN http/1.1
        + _ext(5, b"\x01\x00\x00\x00\x00")                             # status_request (OCSP)
        + _ext(13, _u16(len(SIGALGS) * 2) + b"".join(_u16(s) for s in SIGALGS))  # signature_algorithms
        + _ext(18, b"")                                                # signed_certificate_timestamp
        + _ext(51, _u16(len(key_share_ic)) + key_share_ic)             # key_share
        + _ext(45, b"\x01\x01")                                        # psk_key_exchange_modes: psk_dhe_ke
        + _ext(43, b"\x04\x03\x04\x03\x03")                            # supported_versions: 1.3, 1.2
    )
    sifreler = b"".join(_u16(c) for c in CIPHERS)
    def paketle(uz):
        govde = (b"\x03\x03" + client_random + bytes([len(session_id)]) + session_id + _u16(len(sifreler)) + sifreler + b"\x01\x00" + _u16(len(uz)) + uz)   # BoringSSL/Bun: 32 bayt legacy_session_id (27 Eki 2026 tcpdump)
        return b"\x01" + len(govde).to_bytes(3, "big") + govde
    if not psk: return paketle(uzantilar)
    import hashlib, hmac
    bilet, yas, binder_key, _ = psk
    kimlikler = _u16(len(bilet)) + bilet + struct.pack(">I", yas)
    binder_bos = b"\x20" + b"\x00" * 32
    psk_ic = _u16(len(kimlikler)) + kimlikler + _u16(len(binder_bos)) + binder_bos
    tam = paketle(uzantilar + _ext(41, psk_ic))
    kesik = tam[:-35]                                   # RFC 8446 4.2.11.2: binders alanının tamamı hariç (2 uzunluk + 1 + 32)
    binder = hmac.new(hkdf_finished_key(binder_key), hashlib.sha256(kesik).digest(), hashlib.sha256).digest()
    return tam[:-32] + binder
