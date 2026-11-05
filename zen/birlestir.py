"""SSE akışını tek chat.completion cevabına birleştir (istemci stream istemediğinde)."""
import json
from . import istek

async def tek_cevap(c: istek.Cevap) -> istek.Cevap:
    metin = b""
    while True:
        p = await c.kuyruk.get()
        if p is None: break
        metin += p
    icerik = []; dusunce = []; arac: dict = {}; son = {}; kullanim = None; rol = "assistant"
    for satir in metin.decode(errors="replace").split("\n"):
        satir = satir.strip()
        if not satir.startswith("data:") or satir[5:].strip() in ("", "[DONE]"): continue
        try: j = json.loads(satir[5:].strip())
        except Exception: continue
        son = j; kullanim = j.get("usage") or kullanim
        for ch in j.get("choices") or []:
            d = ch.get("delta") or {}
            if d.get("content"): icerik.append(d["content"])
            if d.get("reasoning_content"): dusunce.append(d["reasoning_content"])
            for tc in d.get("tool_calls") or []:
                i = tc.get("index", 0); a = arac.setdefault(i, {"id": tc.get("id"), "type": "function", "function": {"name": "", "arguments": ""}})
                if tc.get("id"): a["id"] = tc["id"]
                f = tc.get("function") or {}
                if f.get("name"): a["function"]["name"] += f["name"]
                if f.get("arguments"): a["function"]["arguments"] += f["arguments"]
    mesaj = {"role": rol, "content": "".join(icerik) or None}
    if dusunce: mesaj["reasoning_content"] = "".join(dusunce)
    if arac: mesaj["tool_calls"] = [arac[k] for k in sorted(arac)]
    govde = {"id": son.get("id", "chatcmpl"), "object": "chat.completion", "created": son.get("created", 0), "model": son.get("model", ""),
             "choices": [{"index": 0, "message": mesaj, "finish_reason": "tool_calls" if arac else "stop"}], "usage": kullanim}
    yeni = istek.Cevap(); yeni.durum = 200; yeni.basliklar = {"content-type": "application/json"}; yeni.hazir.set()
    yeni.kuyruk.put_nowait(json.dumps(govde, ensure_ascii=False).encode()); yeni.kuyruk.put_nowait(None)
    return yeni
