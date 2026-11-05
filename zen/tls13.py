"""Saf Python TLS 1.3 istemcisi (manual-tls kripto yardımcıları + x25519 + kyber-py). Bun/BoringSSL ClientHello parmak izi,
oturum bileti (NewSessionTicket) saklama ve ikinci bağlantıda PSK + binder ile devam. Tek sunucu, tek istek, HTTP/1.1.
Amaç: Zen free kapısını saf Python'dan geçmek (26 Eki 2026 deneyi)."""
import hmac as _hmac, hashlib, os, socket, struct, sys, time

from . import kripto as M, x25519, hello as bun_hello
from kyber_py.ml_kem import ML_KEM_768

HS, CCS, APP, ALERT = b"\x16", b"\x14", b"\x17", b"\x15"
def u16(n): return struct.pack(">H", n)
def hkdf_expand_label(secret, label, ctx, n): return M.derive_secret(label, secret, ctx, n)
def hkdf_extract(salt, ikm): return M.hmac_sha256(salt, ikm)
def sha256(b): return hashlib.sha256(b).digest()
BILET: dict = {}   # host -> {"bilet", "sir", "yas_ekle", "alinma", "omur"}

class Baglanti:
    def __init__(self, host, port=443, timeout=90, proxy=""):
        from cikis import tunel as cikis
        self.host = host; self.s = cikis.ac(host, port, proxy, timeout); self.cs = self.ss = 0; self.tampon = bytearray(); self.transcript = b""
    # --- kayıt katmanı
    def _gonder_kayit(self, tip, veri): self.s.sendall(tip + b"\x03\x03" + u16(len(veri)) + veri)
    def _al_kayit(self):
        bas = self._al(5); n = struct.unpack(">H", bas[3:5])[0]; return bas[0:1], self._al(n)
    def _al(self, n):
        r = bytearray()
        while len(r) < n:
            d = self.s.recv(min(65536, n - len(r)))
            if not d: raise ConnectionError("kapandi")
            r += d
        return bytes(r)
    def _gonder_sifreli(self, ictip, veri):
        self._gonder_kayit(APP, M.do_authenticated_encryption(self.ckey, self.civ, self.cs, ictip, veri)); self.cs += 1
    def _al_sifreli(self):
        while True:
            tip, veri = self._al_kayit()
            if tip == CCS: continue
            if tip == ALERT: raise ConnectionError(f"alert {veri.hex()}")
            ictip, acik = M.do_authenticated_decryption(self.skey, self.siv, self.ss, APP, veri); self.ss += 1
            return ictip, acik
    def _sonraki_hs(self):
        while True:
            if len(self.tampon) >= 4:
                n = 4 + int.from_bytes(self.tampon[1:4], "big")
                if len(self.tampon) >= n: m = bytes(self.tampon[:n]); del self.tampon[:n]; return m
            ictip, acik = self._al_sifreli(); assert ictip == HS, ictip; self.tampon += acik
    # --- el sıkışma
    def el_sikis(self):
        rnd = os.urandom(32)
        x_ozel, x_acik = x25519.anahtar_uret(); k_ek, k_dk = ML_KEM_768.keygen()
        p_priv = int.from_bytes(os.urandom(31), "big")
        p_x, p_y = M.multiply_num_on_ec_point(p_priv, M.SECP256R1_G[0], M.SECP256R1_G[1], M.SECP256R1_A, M.SECP256R1_P)
        bilet = BILET.get(self.host)
        psk_ek = None
        if bilet:
            # PSK: binder key = HKDF-Expand(early_secret, "res binder", "") ; obfuscated age
            early = hkdf_extract(b"\x00" * 32, bilet["sir"])
            binder_key = hkdf_expand_label(early, b"res binder", sha256(b""), 32)
            yas = (int((time.time() - bilet["alinma"]) * 1000) + bilet["yas_ekle"]) & 0xffffffff
            psk_ek = (bilet["bilet"], yas, binder_key, early)
        hello = bun_hello.client_hello(self.host, rnd, p_x, p_y, x_acik, k_ek, psk_ek, session_id=os.urandom(32))
        self._gonder_kayit(HS, hello); self.transcript = hello
        tip, sh = self._al_kayit()
        if tip == ALERT: raise ConnectionError(f"sunucu alert: {sh.hex()}")
        assert tip == HS and sh[0] == 2, f"ServerHello bekleniyordu: tip={tip.hex()} ilk={sh[:8].hex()}"; self.transcript += sh
        # ServerHello: key_share grubu + anahtar, psk seçildi mi
        p = 4 + 2 + 32; p += 1 + sh[p]; p += 2 + 1; el = struct.unpack(">H", sh[p:p+2])[0]; p += 2; son = p + el
        grup = None; s_acik = None; psk_secildi = False
        while p + 4 <= son:
            t, l = struct.unpack(">HH", sh[p:p+4]); v = sh[p+4:p+4+l]; p += 4 + l
            if t == 51: grup = v[:2]; s_acik = v[4:]
            if t == 41: psk_secildi = True
        if grup == b"\x11\xec": sir = ML_KEM_768.decaps(k_dk, s_acik[:1088]) + x25519.paylasilan_sir(x_ozel, s_acik[1088:1120])
        elif grup == b"\x00\x1d": sir = x25519.paylasilan_sir(x_ozel, s_acik)
        elif grup == b"\x00\x17": sir = M.num_to_bytes(M.multiply_num_on_ec_point(p_priv, int.from_bytes(s_acik[1:33], "big"), int.from_bytes(s_acik[33:65], "big"), M.SECP256R1_A, M.SECP256R1_P)[0], 32)
        else: raise ConnectionError(f"grup yok/HRR: {grup}")
        early = psk_ek[3] if (psk_ek and psk_secildi) else hkdf_extract(b"\x00" * 32, b"\x00" * 32)
        hs_secret = hkdf_extract(hkdf_expand_label(early, b"derived", sha256(b""), 32), sir)
        th = sha256(self.transcript)
        s_hs = hkdf_expand_label(hs_secret, b"s hs traffic", th, 32); c_hs = hkdf_expand_label(hs_secret, b"c hs traffic", th, 32)
        self.skey, self.siv = hkdf_expand_label(s_hs, b"key", b"", 16), hkdf_expand_label(s_hs, b"iv", b"", 12)
        self.ckey, self.civ = hkdf_expand_label(c_hs, b"key", b"", 16), hkdf_expand_label(c_hs, b"iv", b"", 12)
        self.cs = self.ss = 0
        # EncryptedExtensions, (Certificate, CertificateVerify), Finished
        while True:
            m = self._sonraki_hs(); self.transcript += m
            if m[0] == 20: break
        # client Finished
        c_fin_key = hkdf_expand_label(c_hs, b"finished", b"", 32)
        fin = b"\x14" + len(sha256(b"")).to_bytes(3, "big") + _hmac.new(c_fin_key, sha256(self.transcript), hashlib.sha256).digest()
        self._gonder_kayit(CCS, b"\x01"); self._gonder_sifreli(HS, fin)
        # uygulama anahtarları
        master = hkdf_extract(hkdf_expand_label(hs_secret, b"derived", sha256(b""), 32), b"\x00" * 32)
        th = sha256(self.transcript)
        s_ap = hkdf_expand_label(master, b"s ap traffic", th, 32); c_ap = hkdf_expand_label(master, b"c ap traffic", th, 32)
        self.transcript += fin
        self.res_master = hkdf_expand_label(master, b"res master", sha256(self.transcript), 32)
        self.skey, self.siv = hkdf_expand_label(s_ap, b"key", b"", 16), hkdf_expand_label(s_ap, b"iv", b"", 12)
        self.ckey, self.civ = hkdf_expand_label(c_ap, b"key", b"", 16), hkdf_expand_label(c_ap, b"iv", b"", 12)
        self.cs = self.ss = 0; self.psk_secildi = psk_secildi; self.grup = grup
    def _bilet_isle(self, m):
        omur, yas_ekle = struct.unpack(">II", m[4:12]); nl = m[12]; nonce = m[13:13+nl]; p = 13 + nl
        bl = struct.unpack(">H", m[p:p+2])[0]; bilet = m[p+2:p+2+bl]
        sir = hkdf_expand_label(self.res_master, b"resumption", nonce, 32)
        BILET[self.host] = {"bilet": bilet, "sir": sir, "yas_ekle": yas_ekle, "alinma": time.time(), "omur": omur}
    def istek(self, ham: bytes) -> bytes:
        for i in range(0, len(ham), 16000): self._gonder_sifreli(APP, ham[i:i + 16000])   # TLS kayıt sınırı 2^14
        cevap = b""
        def bitti():
            bas, ayrac, gov = cevap.partition(b"\r\n\r\n")
            if not ayrac: return False
            b = bas.lower()
            if b"transfer-encoding: chunked" in b: return gov.endswith(b"0\r\n\r\n")
            cl = [l for l in b.split(b"\r\n") if l.startswith(b"content-length:")]
            return bool(cl) and len(gov) >= int(cl[0].split(b":")[1])
        while not bitti():
            try: ictip, acik = self._al_sifreli()
            except (ConnectionError, TimeoutError, OSError): break
            if ictip == APP: cevap += acik
            elif ictip == HS and acik and acik[0] == 4: self._bilet_isle(acik)
            elif ictip == ALERT: break
        try: self.s.close()
        except Exception: pass
        return cevap
