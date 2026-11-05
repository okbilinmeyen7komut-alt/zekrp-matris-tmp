"""Zen'e giden isteğin OpenCode şablonu: sistem metni, araçlar, yol, UA, başlık ve gövde sırası.

Kaynak: zen/sablon_yakala.py gerçek OpenCode'dan yakalar (Zen'e istek atmadan) ve veri/opencode-sablon.json'a yazar;
yoksa ürünle gelen varsayılan zen/opencode/opencode-sablon.json kullanılır. Dosya değişince (günlük tazeleme) servis
yeniden başlatılmadan yeni şablon okunur.
Neden şart: Zen free kapısı sistem metninin güncel OpenCode metni olmasını denetler; eski metinle giden TEK istek o IP'yi
günün geri kalanında yakar (5 Kas 2026: eski preamble 429, aynı dakikada aynı IP'de güncel metin 200).
"""
import json, time
from pathlib import Path

CANLI = Path(__file__).resolve().parent.parent / "veri" / "opencode-sablon.json"
VARSAYILAN = Path(__file__).resolve().parent / "opencode" / "opencode-sablon.json"
_on: dict = {"yol": None, "mtime": 0.0, "veri": {}}


def oku() -> dict:
    yol = CANLI if CANLI.exists() else VARSAYILAN
    try: mt = yol.stat().st_mtime
    except OSError: return _on["veri"]
    if yol != _on["yol"] or mt != _on["mtime"]:
        try: _on.update(yol=yol, mtime=mt, veri=json.loads(yol.read_text()))
        except Exception as e: print("opencode şablonu okunamadı:", yol, e, flush=True)
    return _on["veri"]


def sistem(model_id: str, model_ad: str) -> str:
    return (oku()["sistem"].replace("{MODEL_AD}", model_ad).replace("{MODEL_ID}", model_id)
            .replace("{TARIH}", time.strftime("%a %b %d %Y")))


def araclar() -> list: return oku().get("araclar") or []
def arac_adlari() -> list: return [(a.get("function") or {}).get("name", "") for a in araclar()]
def yol() -> str: return oku().get("yol") or "/zen/v1"
def ua() -> str: return oku().get("ua") or ""
def accept() -> str: return oku().get("accept") or "*/*"
def baslik_sirasi() -> list: return oku().get("baslik_sirasi") or []
def govde_sirasi() -> list: return oku().get("govde_sirasi") or ["model", "messages", "tools", "stream", "stream_options", "max_completion_tokens"]
def max_completion_tokens() -> int: return int(oku().get("max_completion_tokens") or 32000)
def bilgi() -> dict:
    v = oku(); return {"surum": v.get("surum", ""), "yakalama": v.get("yakalama", ""), "kaynak": "canli" if CANLI.exists() else "varsayilan", "arac": len(v.get("araclar") or [])}
