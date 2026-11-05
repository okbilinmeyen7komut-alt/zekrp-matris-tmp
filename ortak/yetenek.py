"""Model yetenek ölçümü (sağlayıcıdan bağımsız): metin, görsel (1x1 png), araç çağrısı; gerçek istek, varsayım yok.
olc_ile(chat_fn, model) tek giriş; Taban sağlayıcılar (OpenRouter/Kilo/NIM) kullanır, OpenCode ölçülmez (OLCUM=False)."""
import asyncio, json, time


PNG_1x1 = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
ARAC = [{"type": "function", "function": {"name": "hava", "description": "Sehrin havasi", "parameters": {"type": "object", "properties": {"sehir": {"type": "string"}}, "required": ["sehir"]}}}]

def _sse_oku(metin: str):
    icerik = ""; arac = False
    for l in metin.splitlines():
        if l.startswith("data:") and l[5:].strip().startswith("{"):
            try: j = json.loads(l[5:].strip())
            except Exception: continue
            for ch in j.get("choices") or []:
                d = ch.get("delta") or {}
                icerik += d.get("content") or ""
                if d.get("tool_calls"): arac = True
    return icerik, arac

async def _dene_ile(chat_fn, model, mesajlar, araclar=None):
    """Genel: chat_fn(govde) -> Cevap. 429'da 5/10/20 sn bekleyip yeniden dener; istekler arası 2 sn."""
    g = {"model": model, "messages": mesajlar, "stream": True, "max_tokens": 60}
    if araclar: g["tools"] = araclar; g["tool_choice"] = "auto"
    for bekle in (5, 10, 20, 0):
        t0 = time.time(); c = await chat_fn(g); gov = b""
        while True:
            p = await c.kuyruk.get()
            if p is None: break
            gov += p
        if c.durum != 429 or not bekle: break
        await asyncio.sleep(bekle)
    icerik, arac = _sse_oku(gov.decode(errors="replace")); await asyncio.sleep(2)
    return c.durum, icerik, arac, int((time.time() - t0) * 1000)

async def olc_ile(chat_fn, model_id: str) -> dict:
    """Sağlayıcıdan bağımsız yetenek ölçümü: metin, görsel (1x1 png), araç çağrısı."""
    s, ic, _, ms = await _dene_ile(chat_fn, model_id, [{"role": "user", "content": "Reply with the single word: ok"}])
    metin = s == 200; gorsel = arac = False
    if metin:
        s2, ic2, _, _ = await _dene_ile(chat_fn, model_id, [{"role": "user", "content": [{"type": "text", "text": "What color is this image? One word."}, {"type": "image_url", "image_url": {"url": PNG_1x1}}]}])
        gorsel = s2 == 200 and bool(ic2.strip())
        s3, _, arac, _ = await _dene_ile(chat_fn, model_id, [{"role": "user", "content": "Call the hava tool for Ankara."}], ARAC)
    return {"metin": metin, "gorsel": gorsel, "arac": arac, "sure_ms": ms, "durum": s}
