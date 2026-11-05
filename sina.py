#!/usr/bin/env python3
"""ZekRP çıkış sondası: bir ücretsiz platformda (GitHub Actions, HF Space, Koyeb, Cloud Shell, VM…) çalışır; platformun kendi
IPv4 ve IPv6 çıkışından Zen'e (doğru OpenCode şablonuyla) birer istek atar ve TEK satır JSON basar.
Kullanım: python3 sonda.py [--http PORT]   (--http: sonucu GET / ile de sunar; platform günlüğü okunamıyorsa)
Gereken: python3.9+, `pip install kyber-py`, ZekRP kodunun zen/ ortak/ cikis/tunel.py + cikis/__init__.py (boş) klasörleri."""
import asyncio, json, os, platform, re, socket, sys, threading, time, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from zen import istek, sekil, sablon
from ortak.cevap import Cevap


def _ip(ho: str) -> str:
    try: return urllib.request.urlopen(f"https://{ho}", timeout=12).read().decode().strip()[:45]
    except Exception: return ""


def _org(ip: str) -> str:
    try: return (json.loads(urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=12).read()).get("org") or "")[:34]
    except Exception: return ""


async def _zen(v6: bool) -> str:
    g = sekil.chat({"model": "deepseek-v4.1-flash-free", "stream": True, "max_tokens": 40, "messages": [{"role": "user", "content": "2+2 kaç? tek kelime"}]})
    gov = json.dumps(g, separators=(",", ":"), ensure_ascii=False).encode()
    ham = istek.baslik("opencode.ai", sablon.yol() + "/chat/completions", sablon.ua(), "126081a8b4a7ae6fdc5ae2610bb98b1f8a10c8e0", gov)
    c = Cevap(); loop = asyncio.get_running_loop()
    threading.Thread(target=istek._kos, args=("opencode.ai", ham, c, loop, "", v6), daemon=True).start()
    await c.hazir.wait(); b = bytearray()
    while True:
        p = await c.kuyruk.get()
        if p is None: break
        b += p
    if c.durum == 200: return "200"
    try: return f"{c.durum} " + json.loads(b).get("error", {}).get("message", "")[:50]
    except Exception: return f"{c.durum} " + bytes(b[:80]).decode("utf-8", "replace")


def calis() -> dict:
    r: dict = {"zaman": time.strftime("%F %T"), "sistem": f"{platform.system()} {platform.machine()}", "host": socket.gethostname()}
    v4 = _ip("api.ipify.org"); r["v4"] = {"ip": v4, "org": _org(v4) if v4 else "", "zen": asyncio.run(_zen(False)) if v4 else "ipv4 yok"}
    v6 = _ip("api6.ipify.org"); r["v6"] = {"ip": v6, "zen": asyncio.run(_zen(True)) if v6 else "ipv6 yok"}
    return r


if __name__ == "__main__":
    s = calis(); print(json.dumps(s, ensure_ascii=False), flush=True)
    if "--http" in sys.argv:
        from http.server import BaseHTTPRequestHandler, HTTPServer
        port = int(sys.argv[sys.argv.index("--http") + 1])
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(json.dumps(calis(), ensure_ascii=False).encode())
            def log_message(self, *a): pass
        HTTPServer(("0.0.0.0", port), H).serve_forever()
