"""Zen'e istek: model listesi ve chat iletimi. Yol saf Python TLS 1.3 (zen.istek), gövde OpenCode şekli (zen.sekil).
Bun/zen-proxy yok; free kapısı bu yoldan geçer (26 Eki 2026 ölçüldü)."""
import hashlib, json, time
from . import istek, sekil, birlestir, sablon
from cikis import havuz as cikis_havuzu

_modeller: dict = {"zaman": 0, "veri": []}

HEP_FREE = {"big-pickle"}   # '-free' eki olmayan ama ücretsiz olanlar (Orçun 26 Eki 2026)
KAPALI = set()   # Orçun 27 Eki 2026: TÜM ücretsiz modeller gelsin; kullanıcı kısıtlamak isterse ayar "kapali_modeller" ile yapar

def _free(m: dict, ayar: dict | None = None) -> bool:
    """Yalnız ücretsiz modeller: id '-free' ile biter, HEP_FREE listesinde ya da fiyatı 0. Kapalı listedekiler hiç listelenmez."""
    if m.get("id") in KAPALI or m.get("id") in set((ayar or {}).get("kapali_modeller") or []): return False
    if str(m.get("id", "")).endswith("-free") or m.get("id") in HEP_FREE: return True
    f = m.get("cost") or m.get("pricing") or {}
    return bool(f) and all(float(v or 0) == 0 for v in f.values() if isinstance(v, (int, float, str)) and str(v).replace(".", "").isdigit())

async def _bosalt(c: istek.Cevap) -> bytes:
    b = bytearray()
    while True:
        p = await c.kuyruk.get()
        if p is None: return bytes(b)
        b += p

def _hazir_cevap(durum: int, govde: bytes, basliklar: dict | None = None, cikis: str = "-") -> istek.Cevap:
    c = istek.Cevap(); c.durum = durum; c.cikis = cikis; c.basliklar = {"content-type": "application/json", **(basliklar or {})}
    c.kuyruk.put_nowait(govde); c.kuyruk.put_nowait(None); c.hazir.set(); return c

async def her_noktadan(ayar: dict, gonder, turler: tuple | None = None) -> istek.Cevap:
    """Orçun kuralı (27 Eki 2026): model cevap verene kadar havuzdaki HER çıkış noktası denenir; kullanıcı 429'u ancak hepsi doluysa görür.
      429                 -> nokta kara listeye (Retry-After), sıradaki nokta
      yerel bağlantı hatası (Zen/Worker'a ulaşılamadı) -> nokta 60 sn dinlenir, sıradaki nokta
      Zen 5xx (model/sunucu tarafı) -> en çok `hata_deneme` farklı noktada
      200 ve diğer 4xx    -> olduğu gibi döner
    Açık nokta bitince SON TUR: kara listedekiler (son hatası en eski olan önce) bir kez daha. Süre tavanı `deneme_suresi_sn`.
    `gonder(cikis)` -> istek.Cevap (başlıklar gelmiş)."""
    denenen: set = set(); t0 = time.time(); tavan = float(ayar.get("deneme_suresi_sn", 90)); hata_tavan = int(ayar.get("hata_deneme", 3))
    sabit = cikis_havuzu.sabit(ayar) is not None; son_tur = None; kota = 0; son_hata = None; zen_5xx = 0
    while time.time() - t0 < tavan:
        cikis = cikis_havuzu.sec(ayar, denenen, turler)
        if cikis is None:
            if sabit: break
            if son_tur is None: son_tur = cikis_havuzu.son_tur(ayar, denenen, turler)
            if not son_tur: break
            cikis = son_tur.pop(0)
        denenen.add(cikis["ad"]); cikis_havuzu.say(cikis["ad"])
        c = await gonder(cikis); c.cikis = cikis["ad"]
        if c.durum == 429:
            cikis_havuzu.kara_liste(cikis["ad"], c.basliklar); kota += 1; await _bosalt(c); continue
        if getattr(c, "yerel_hata", False):
            cikis_havuzu.dinlendir(cikis["ad"], 60); son_hata = (c.durum, await _bosalt(c), cikis["ad"]); continue
        if c.durum >= 500:
            zen_5xx += 1
            if zen_5xx < hata_tavan: son_hata = (c.durum, await _bosalt(c), cikis["ad"]); continue
        if c.durum == 200 and son_tur is not None: cikis_havuzu.temizle(cikis["ad"])   # kara listedeyken çalıştı: listeden çıkar
        return c
    if son_hata and not kota: return _hazir_cevap(son_hata[0], son_hata[1], cikis=son_hata[2])
    bekle = max(1, int(cikis_havuzu.en_erken_acilis(ayar) - time.time()))
    return _hazir_cevap(429, json.dumps({"error": {"type": "FreeUsageLimitError", "message": f"tüm çıkış noktaları denendi ({len(denenen)} nokta, {kota} kotada); en erken açılış {bekle} sn sonra"}}).encode(), {"retry-after": str(bekle)})

def _proje(ayar: dict) -> str: return hashlib.sha1(f"directory:{ayar.get('proje_dizini', '/root')}".encode()).hexdigest()

def ua(ayar: dict) -> str:
    """UA şablondan (yakalanan gerçek OpenCode sürümü; sistem metniyle AYNI sürüm olmalı). Şablonda yoksa ayar."""
    return sablon.ua() or ayar["ua"]

async def modeller(ayar: dict) -> list:
    """Zen model listesi. SUNUCU IP'sinden çekilir (çıkış noktası harcamaz): model listesi KOTAYA/çıkışa BAĞLI DEĞİL.
    Bir kez alınınca son bilinen liste korunur; yalnız 200 ile başarılı yenilemede güncellenir. Boş yalnız hiç alınamamışsa."""
    if time.time() - _modeller["zaman"] < 600 and _modeller["veri"]: return _modeller["veri"]
    c = await istek.gonder(ayar["zen_host"], sablon.yol() + "/models", ua(ayar), _proje(ayar), {}, metot="GET", cikis={"ad": "Sunucu", "tur": "sunucu", "proxy": ""})
    gov = await _bosalt(c)
    try: veri = [m for m in json.loads(gov).get("data", []) if _free(m, ayar)] if c.durum == 200 else []
    except Exception: veri = []
    if veri: _modeller.update(zaman=time.time(), veri=veri)
    return _modeller["veri"]   # hata: son bilinen liste (kota/çıkış modeli silmez)

async def chat(ayar: dict, govde: dict) -> istek.Cevap:
    """Zen'e her zaman akışla gidilir (OpenCode'un telli şekli); istemci akış istemediyse parçalar tek cevaba birleştirilir."""
    akis_istendi = bool(govde.get("stream"))
    if govde.get("model") in KAPALI or govde.get("model") in set(ayar.get("kapali_modeller") or []):
        c = istek.Cevap(); c.durum = 404; c.cikis = "-"; c.basliklar = {"content-type": "application/json"}
        c.kuyruk.put_nowait(json.dumps({"error": {"type": "model_not_found", "message": f"{govde.get('model')} bu sunucuda kapalı"}}).encode()); c.kuyruk.put_nowait(None); c.hazir.set(); return c
    g = sekil.chat(dict(govde, stream=True))
    c = await her_noktadan(ayar, lambda cikis: istek.gonder(ayar["zen_host"], sablon.yol() + "/chat/completions", ua(ayar), _proje(ayar), g, cikis=cikis))
    if akis_istendi or c.durum != 200: return c
    return await birlestir.tek_cevap(c)


KARAR_MODELLERI = ("jev",)   # chat değil systemone ucu: {model, state, questions} -> {answers, cost}

def karar_modeli_mi(model_id: str) -> bool: return str(model_id).startswith(KARAR_MODELLERI)

async def systemone(ayar: dict, govde: dict) -> istek.Cevap:
    """Jev gibi karar modelleri: /zen/v1/systemone (ölçüldü: 16 Eki 2026 zekproxy). Gövde aynen gider; cevap tek JSON."""
    yol = ayar.get("zen_systemone_yolu", "/zen/v1/systemone")
    c = await her_noktadan(ayar, lambda cikis: istek.gonder(ayar["zen_host"], yol, ua(ayar), _proje(ayar), govde, cikis=cikis, sikistirma=False))
    return c
