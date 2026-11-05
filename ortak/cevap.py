"""Sağlayıcıdan bağımsız cevap taşıyıcısı: durum, başlıklar, gövde parçaları asyncio kuyruğunda (None = son).
chunk_akit: HTTP chunked gövdeyi parça parça çözüp kuyruğa koyar (akış)."""
import asyncio

class Cevap:
    def __init__(self):
        self.durum = 0; self.basliklar: dict = {}; self.kuyruk: asyncio.Queue = asyncio.Queue(); self.hazir = asyncio.Event()
        self.cikis = ""        # istek hangi çıkıştan (proxy adı / dogrudan) gitti
        self.bitti = False     # kuyruğa None konuldu mu

def chunk_akit(cevap: Cevap, loop, veri: bytearray, durumu: dict) -> None:
    """durumu = {"kalan": 0, "bitti": False}; tam chunk'lar kuyruğa, son chunk'ta None."""
    while True:
        if durumu["kalan"] == 0:
            i = veri.find(b"\r\n")
            if i < 0: return
            n = int(veri[:i].split(b";")[0] or b"0", 16); del veri[:i + 2]
            if n == 0: loop.call_soon_threadsafe(cevap.kuyruk.put_nowait, None); durumu["bitti"] = True; cevap.bitti = True; return
            durumu["kalan"] = n
        if len(veri) < durumu["kalan"] + 2: return
        parca = bytes(veri[:durumu["kalan"]]); del veri[:durumu["kalan"] + 2]; durumu["kalan"] = 0
        loop.call_soon_threadsafe(cevap.kuyruk.put_nowait, parca)
