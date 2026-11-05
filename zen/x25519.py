"""X25519 (RFC 7748) saf Python: anahtar üret, paylaşılan sır. TLS 1.3 key_share için."""
import os

P = 2**255 - 19
A24 = 121665

def _clamp(k: bytes) -> int:
    b = bytearray(k); b[0] &= 248; b[31] &= 127; b[31] |= 64
    return int.from_bytes(b, "little")

def _ladder(k: int, u: int) -> int:
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1; swap ^= kt
        if swap: x2, x3 = x3, x2; z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P; aa = a * a % P; b = (x2 - z2) % P; bb = b * b % P; e = (aa - bb) % P
        c = (x3 + z3) % P; d = (x3 - z3) % P; da = d * a % P; cb = c * b % P
        x3 = pow(da + cb, 2, P); z3 = x1 * pow(da - cb, 2, P) % P
        x2 = aa * bb % P; z2 = e * (aa + A24 * e) % P
    if swap: x2, x3 = x3, x2; z2, z3 = z3, z2
    return x2 * pow(z2, P - 2, P) % P

def anahtar_uret() -> tuple[bytes, bytes]:
    """(özel, açık) 32'şer bayt."""
    ozel = os.urandom(32)
    acik = _ladder(_clamp(ozel), 9).to_bytes(32, "little")
    return ozel, acik

def paylasilan_sir(ozel: bytes, karsi_acik: bytes) -> bytes:
    u = int.from_bytes(karsi_acik, "little") & ((1 << 255) - 1)
    return _ladder(_clamp(ozel), u).to_bytes(32, "little")
