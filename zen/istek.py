"""Zen'e HTTP/1.1 isteği (saf Python TLS 1.3, Bun parmak izi). Akış: cevap parçaları geldikçe asyncio kuyruğuna düşer.
Her istek yeni bağlantı; oturum bileti (PSK) tls13.BILET'te süreç boyunca tutulur."""
import asyncio, json, os, re, secrets, threading, time
from . import tls13

ALF = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
def oturum_kimligi() -> str:
    """OpenCode Identifier.create(descending): 12 hex (48 bit ~ms) + 14 base62."""
    d = ~(int(time.time() * 1000) * 0x1000 + 1)
    return "ses_" + "".join(f"{(d >> (40 - 8 * i)) & 0xFF:02x}" for i in range(6)) + "".join(ALF[b % 62] for b in os.urandom(14))

def basliklar(host: str, ua: str, proje: str, govde: bytes, ses: str | None = None, metot: str = "POST", sikistirma: bool = True) -> list:
    """Gerçek OpenCode başlıkları, SIRALI: sıra ve Accept değeri zen.sablon'dan (gerçek OpenCode'dan yakalanır; 5 Kas 2026 v2.0.26:
    Authorization … Connection, Accept: */*, Host, Accept-Encoding, Content-Length). -> [(ad, değer)]
    Authorization: anonim = "Bearer public" (yakalama metnindeki *** çıktı maskesidir, değer 'public')."""
    from . import sablon
    ses = ses or oturum_kimligi(); tr = secrets.token_hex(16); sp = secrets.token_hex(8); pa = secrets.token_hex(8)
    d = {"authorization": "Bearer public", "content-type": "application/json", "user-agent": ua, "b3": f"{tr}-{sp}-1-{pa}",
         "traceparent": f"00-{tr}-{sp}-01", "x-opencode-client": "cli", "x-opencode-project": proje, "x-opencode-session": ses,
         "x-opencode-session-id": ses, "x-session-affinity": ses, "x-session-id": ses, "connection": "keep-alive", "accept": sablon.accept(),
         "host": host, "accept-encoding": "gzip, deflate, br, zstd" if (metot == "POST" and sikistirma) else "identity", "content-length": str(len(govde))}
    sira = sablon.baslik_sirasi() or ["Authorization", "Content-Type", "User-Agent", "b3", "traceparent", "x-opencode-client", "x-opencode-project",
                                      "x-opencode-session", "x-opencode-session-id", "x-session-affinity", "x-session-id", "Connection", "Accept", "Host",
                                      "Accept-Encoding", "Content-Length"]
    out = [(ad, d[ad.lower()]) for ad in sira if ad.lower() in d]
    if metot != "POST": out = [(k, v) for k, v in out if k.lower() not in ("content-type", "content-length")]
    return out

def baslik(host: str, yol: str, ua: str, proje: str, govde: bytes, ses: str | None = None, metot: str = "POST", sikistirma: bool = True) -> bytes:
    """Ham HTTP/1.1 isteği (satır + başlıklar + gövde), tls13 yolu için."""
    satir = [f"{metot} {yol} HTTP/1.1"] + [f"{k}: {v}" for k, v in basliklar(host, ua, proje, govde, ses, metot, sikistirma)]
    return ("\r\n".join(satir) + "\r\n\r\n").encode() + govde

def _gov_coz(bas: bytes, gov: bytes) -> bytes:
    """chunked ise birleştir (akışta parça parça yapılır; burada yalnız akışsız)."""
    if b"transfer-encoding: chunked" not in bas.lower(): return gov
    out = b""; p = 0
    while p < len(gov):
        i = gov.find(b"\r\n", p); n = int(gov[p:i].split(b";")[0], 16); p = i + 2
        if n == 0: break
        out += gov[p:p+n]; p += n + 2
    return out

from ortak.cevap import Cevap, chunk_akit as _chunk_akit

def _kos(host: str, ham: bytes, cevap: Cevap, loop, proxy: str = ""):
    try:
        c = tls13.Baglanti(host, timeout=120, proxy=proxy); c.el_sikis()
        for i in range(0, len(ham), 16000): c._gonder_sifreli(tls13.APP, ham[i:i + 16000])
        tampon = bytearray(); bas_ok = False; chunked = False; durumu = {"kalan": 0, "bitti": False}; cl = None; govde_say = 0
        while not durumu["bitti"]:
            try: ictip, acik = c._al_sifreli()
            except Exception: break
            if ictip == tls13.HS and acik and acik[0] == 4: c._bilet_isle(acik); continue
            if ictip != tls13.APP: break
            tampon += acik
            if not bas_ok:
                k = tampon.find(b"\r\n\r\n")
                if k < 0: continue
                bas = bytes(tampon[:k]); del tampon[:k + 4]; bas_ok = True
                satirlar = bas.decode(errors="replace").split("\r\n"); cevap.durum = int(satirlar[0].split(" ")[1])
                cevap.basliklar = {s.split(":", 1)[0].strip().lower(): s.split(":", 1)[1].strip() for s in satirlar[1:] if ":" in s}
                chunked = cevap.basliklar.get("transfer-encoding", "").lower() == "chunked"; cl = int(cevap.basliklar.get("content-length", "0") or 0)
                loop.call_soon_threadsafe(cevap.hazir.set)
            if chunked: _chunk_akit(cevap, loop, tampon, durumu)
            else:
                if tampon: parca = bytes(tampon); tampon.clear(); govde_say += len(parca); loop.call_soon_threadsafe(cevap.kuyruk.put_nowait, parca)
                if cl is not None and govde_say >= cl: break
        try: c.s.close()
        except Exception: pass
    except Exception as e:
        if not cevap.durum: cevap.yerel_hata = True          # Zen'e hiç ulaşılamadı (çıkış noktası/bağlantı sorunu): istemci sıradaki noktayı dener
        cevap.durum = cevap.durum or 502; cevap.basliklar.setdefault("content-type", "application/json")
        loop.call_soon_threadsafe(cevap.kuyruk.put_nowait, json.dumps({"error": {"type": "zen_baglanti", "message": str(e)[:200]}}).encode())
    finally:
        loop.call_soon_threadsafe(cevap.hazir.set); loop.call_soon_threadsafe(cevap.kuyruk.put_nowait, None)

async def gonder(host: str, yol: str, ua: str, proje: str, govde: dict, metot: str = "POST", cikis: dict | None = None, sikistirma: bool = True) -> Cevap:
    """İsteği gönder; başlıklar gelince döner, gövde cevap.kuyruk'tan (None = son).
    `cikis` (cikis.havuz.sec): tur dogrudan/ajan -> saf Python TLS (tünel üstünde); tur cloudflare -> Worker aktarıcısı (aynı başlık/gövde)."""
    gov = json.dumps(govde, separators=(",", ":"), ensure_ascii=False).encode() if metot == "POST" else b""
    cikis = cikis or {}
    if cikis.get("tur") == "cloudflare":
        from cikis import cloudflare
        return await cloudflare.gonder(cikis, f"https://{host}{yol}", metot, basliklar(host, ua, proje, gov, metot=metot, sikistirma=False), gov)
    ham = baslik(host, yol, ua, proje, gov, metot=metot, sikistirma=sikistirma)
    cevap = Cevap(); loop = asyncio.get_running_loop()
    threading.Thread(target=_kos, args=(host, ham, cevap, loop, cikis.get("proxy", "")), daemon=True).start()
    await cevap.hazir.wait(); return cevap
