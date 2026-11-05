"""Human-ready biçimlendirme: teknik model kimliklerini kullanıcıya gösterilecek güzel ada çevirir.
Kural: '-free'/'_free' eki atılır (ayrı 'ücretsiz' etiketi var), tire/alt çizgi boşluk olur, her kelime baş harfi büyük;
marka/kısaltma yazımları (GLM, DeepSeek, MiMo, VL, GPT...) ÖZEL tablosundan korunur. Teknik id arka planda kalır (API çağrısı onunla)."""
import re

OZEL = {
    "glm": "GLM", "vl": "VL", "mimo": "MiMo", "deepseek": "DeepSeek", "40b": "40B",
    "gpt": "GPT", "api": "API", "ai": "AI", "vlm": "VLM", "oss": "OSS", "qwen": "Qwen",
    "gemini": "Gemini", "claude": "Claude", "grok": "Grok", "kimi": "Kimi", "minimax": "MiniMax",
    "openrouter": "OpenRouter", "opencode": "OpenCode", "nim": "NIM", "lfm": "LFM", "lm": "LM",
}

def _kelime(p: str) -> str:
    pl = p.lower()
    if pl in OZEL: return OZEL[pl]
    if len(p) > 1 and p[0] in "vV" and p[1].isdigit(): return "V" + p[1:]   # v4.1 -> V4.1
    if p[:1].isdigit(): return p.upper()                                    # 3.5, 40b -> 40B
    return p[:1].upper() + p[1:]

def model_ad(model_id: str) -> str:
    """'big-pickle' -> 'Big Pickle', 'kilo/kilo-auto/free' -> 'Kilo Auto', 'nim/minimaxai/minimax-m3.1-flash' -> 'MiniMax M3.1 Flash'.
    'free' segmentleri ve sağlayıcı kimliği öneki atılır, kalan son anlamlı segment human-ready olur."""
    parcalar = [p for p in str(model_id).split("/") if p and p.lower() != "free"]
    if len(parcalar) > 1: parcalar = parcalar[1:]   # ilk segment sağlayıcı kimliği (kilo/openrouter/nim) -> at
    s = parcalar[-1] if parcalar else str(model_id)
    s = re.sub(r"[-_: ]?free$", "", s, flags=re.I)
    return " ".join(_kelime(p) for p in re.split(r"[-_ ]+", s) if p) or str(model_id)
