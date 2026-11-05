"""Çıkış proxy: hedefe ham TCP soket aç; proxy verilmişse HTTP CONNECT ya da SOCKS5 tüneli kurar (kullanıcı:parola destekli).
TLS bu soketin üstünde kurulur; parmak izi değişmez. URL: http://[k:p@]host:port | socks5://[k:p@]host:port | boş = doğrudan.
v6=True (yalnız socks5): hedef IPv6 adresine bağlanılır (SOCKS5 ATYP 4). Zen IPv4 ve IPv6 için AYRI sayaç tutar (5 Kas 2026 ölçümü:
Tor çıkışlarında IPv4 1/73, IPv6 11/30 başarı); adres host'un AAAA kayıtlarından seçilir (önbellek 10 dk), SNI/Host değişmez."""
import base64, random, socket, struct, time
from urllib.parse import urlparse

_aaaa_on: dict = {}   # host -> (zaman, [adresler])

def aaaa(host: str) -> list:
    """host'un IPv6 adresleri (yerel IPv6 gerekmez, yalnız DNS AAAA). Boşsa ConnectionError."""
    z, v = _aaaa_on.get(host, (0, []))
    if v and time.time() - z < 600: return v
    try: v = sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM)})
    except OSError: v = []
    if not v:
        if _aaaa_on.get(host, (0, []))[1]: return _aaaa_on[host][1]   # DNS geçici yoksa son bilinen
        raise ConnectionError(f"{host} için IPv6 (AAAA) adresi yok")
    _aaaa_on[host] = (time.time(), v); return v

def ac(host: str, port: int, proxy_url: str, timeout: float, v6: bool = False) -> socket.socket:
    if not proxy_url:
        if v6:   # doğrudan IPv6: platformun kendi IPv6 çıkışı (adres AAAA'dan, SNI/Host host kalır)
            return socket.create_connection((random.choice(aaaa(host)), port), timeout)
        return socket.create_connection((host, port), timeout)
    u = urlparse(proxy_url); s = socket.create_connection((u.hostname, u.port), timeout)
    if u.scheme in ("http", "https"):
        if v6: s.close(); raise ValueError("v6 yalnız socks5 proxy ile")
        yetki = f"\r\nProxy-Authorization: Basic {base64.b64encode(f'{u.username}:{u.password}'.encode()).decode()}" if u.username else ""
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}{yetki}\r\n\r\n".encode())
        cevap = b""
        while b"\r\n\r\n" not in cevap:
            p = s.recv(4096)
            if not p: raise ConnectionError("proxy kapattı")
            cevap += p
        if b" 200" not in cevap.split(b"\r\n")[0]: raise ConnectionError("proxy CONNECT reddetti: " + cevap.split(b"\r\n")[0].decode(errors="replace"))
        return s
    if u.scheme in ("socks5", "socks5h"):
        try:
            s.sendall(b"\x05\x02\x00\x02" if u.username else b"\x05\x01\x00")
            y = s.recv(2)
            if y[1:2] == b"\x02":
                s.sendall(b"\x01" + bytes([len(u.username)]) + u.username.encode() + bytes([len(u.password or "")]) + (u.password or "").encode())
                if s.recv(2)[1:2] != b"\x00": raise ConnectionError("socks5 kimlik reddedildi")
            elif y[1:2] != b"\x00": raise ConnectionError("socks5 yöntem reddedildi")
            if v6: istek = b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, random.choice(aaaa(host))) + struct.pack(">H", port)
            else: h = host.encode(); istek = b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port)
            s.sendall(istek)
            c = s.recv(4)
            if c[1:2] != b"\x00": raise ConnectionError(f"socks5 bağlantı reddedildi (kod {c[1]})")
            n = {1: 4, 3: None, 4: 16}[c[3]]; s.recv((s.recv(1)[0] if n is None else n) + 2)
            return s
        except Exception:
            s.close(); raise
    s.close(); raise ValueError("proxy şeması: http/https/socks5")
