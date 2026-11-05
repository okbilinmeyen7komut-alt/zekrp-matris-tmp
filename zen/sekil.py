"""İsteği OpenCode'un telli şekline getir. Zen free kapısı gövdeyi denetler: sistem metni GÜNCEL OpenCode metni olmalı
(5 Kas 2026 ölçümü: eski metin 429 + IP o gün yanar; güncel metin 200). Metin/araçlar/sıra zen.sablon'dan (gerçek OpenCode'dan
yakalanmış şablon) gelir; burada sabit metin YOK.
Ekler (ölçüldü, 5 Kas 2026 hepsi 200): istemcinin kendi sistem metni ayrı tutulur (şablon + geçit notu + istemci metni), istemci
araçları şablon araçlarından SONRA eklenir, çok turlu mesajlar aynen gider."""
from pathlib import Path
from . import sablon

GECIT_NOTU = (Path(__file__).resolve().parent / "opencode" / "gecit-notu.txt").read_text()


def _ad(model_id: str) -> str:
    """OpenCode'un gösterdiği model adı biçimi: 'deepseek-v4.1-flash-free' -> 'Deepseek V4.1 Flash Free' (yakalamadaki 'Big Pickle')."""
    return " ".join(p.capitalize() if not p[:1].isdigit() else p for p in model_id.replace("-", " ").split())


def preamble(model_id: str) -> str:
    """Şablon sistem metni (model adı/ID, bugünün tarihi doldurulur) + geçit notu (yer tutucu araç adları şablondan)."""
    adlar = sablon.arac_adlari()
    return sablon.sistem(model_id, _ad(model_id)) + GECIT_NOTU.replace("{ARAC_ADLARI}", ", ".join(adlar[:-1]) + " and " + adlar[-1] if len(adlar) > 1 else "".join(adlar))


def chat(govde: dict) -> dict:
    g = dict(govde); mesajlar = list(g.get("messages") or []); pre = preamble(str(g.get("model", "")))
    bas = sablon.oku().get("sistem", "")[:40]
    if mesajlar and mesajlar[0].get("role") == "system" and isinstance(mesajlar[0].get("content"), str):
        if not mesajlar[0]["content"].startswith(bas):
            mesajlar[0] = {"role": "system", "content": pre + "\n\n" + mesajlar[0]["content"]}
    else:
        mesajlar.insert(0, {"role": "system", "content": pre})
    g["messages"] = mesajlar
    sablon_araclar = sablon.araclar(); adlar = set(sablon.arac_adlari())
    g["tools"] = sablon_araclar + [a for a in (g.get("tools") or []) if (a.get("function") or {}).get("name") not in adlar]
    g.setdefault("stream", False)
    if g["stream"]: g.setdefault("stream_options", {"include_usage": True})
    if "max_completion_tokens" not in g: g["max_completion_tokens"] = g.pop("max_tokens", None) or sablon.max_completion_tokens()
    else: g.pop("max_tokens", None)
    # Gövde anahtar sırası gerçek OpenCode'daki gibi; istemcinin ek alanları (temperature vb.) sonda.
    sira = [k for k in sablon.govde_sirasi() if k in g]
    return {**{k: g[k] for k in sira}, **{k: v for k, v in g.items() if k not in sira}}
