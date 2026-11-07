"""Vault bot server.  Run start.bat (Windows) or: pip install flask requests && python vault_server.py
Open http://localhost:8787 (or the address it prints, from your phone on the same Wi-Fi).
Your token and channel are entered once in the page and saved in vault_config.json next to this file.
Everything is encrypted in the browser; this server only handles encrypted bytes."""
import base64, json, os, re, secrets, socket, threading, time
from collections import OrderedDict
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, Response, abort, jsonify, request, send_from_directory

API = "https://discord.com/api/v10"
HERE = os.path.dirname(os.path.abspath(__file__))
CFG = os.path.join(HERE, "vault_config.json")
S = requests.Session()
S.headers["User-Agent"] = "DiscordBot (https://localhost, 1.0)"
CH = ""
app = Flask(__name__)


def apply(token, channel):
    global CH
    S.headers["Authorization"] = "Bot " + token
    CH = channel


# Defaults: fill these in once and the page never asks for them.
DEFAULT_TOKEN = os.environ.get("DISCORD_TOKEN", "")
DEFAULT_CHANNEL = os.environ.get("DISCORD_CHANNEL", "")

if DEFAULT_TOKEN and DEFAULT_CHANNEL:
    apply(DEFAULT_TOKEN, DEFAULT_CHANNEL)
elif os.path.exists(CFG):
    c = json.load(open(CFG))
    apply(c["token"], c["channel"])


def fail(msg, code=502):
    abort(Response(msg, code))


def dc(method, path, **kw):
    if not CH:
        fail("Not set up yet.", 400)
    for _ in range(8):
        r = S.request(method, API + path, timeout=300, **kw)
        if r.status_code == 429:
            time.sleep(r.json().get("retry_after", 1) + 0.25)
            continue
        if not r.ok:
            fail(f"Discord {r.status_code}: {r.text[:140]}")
        return r
    fail("Rate limited, try again in a minute", 429)


@app.get("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.get("/api/status")
def status():
    return jsonify(ready=bool(CH))


@app.post("/api/config")
def config():
    d = request.get_json()
    token, channel = d["token"].strip(), d["channel"].strip()
    r = requests.get(f"{API}/channels/{channel}", headers={"Authorization": "Bot " + token, "User-Agent": S.headers["User-Agent"]}, timeout=30)
    if not r.ok:
        fail("Discord rejected that token or channel ID (" + str(r.status_code) + "). Check both, and that the bot is in the server.", 400)
    json.dump({"token": token, "channel": channel}, open(CFG, "w"))
    try:
        os.chmod(CFG, 0o600)
    except OSError:
        pass
    apply(token, channel)
    return "", 204


@app.get("/api/list")
def list_files():
    out, before = [], None
    while True:
        params = {"limit": 100, **({"before": before} if before else {})}
        msgs = dc("GET", f"/channels/{CH}/messages", params=params).json()
        for m in msgs:
            if m["content"].startswith("v1 ") and m["attachments"]:
                out.append({"id": m["id"], "c": m["content"], "u": m["attachments"][0]["url"]})
        if len(msgs) < 100:
            return jsonify(out)
        before = msgs[-1]["id"]


@app.get("/api/blob")
def blob():
    u = request.args["u"]
    if urlparse(u).hostname not in ("cdn.discordapp.com", "media.discordapp.net"):
        abort(400)
    r = requests.get(u, timeout=300)
    if not r.ok:
        fail(f"Download failed ({r.status_code})")
    return Response(r.content, mimetype="application/octet-stream")


@app.post("/api/send")
def send():
    r = dc("POST", f"/channels/{CH}/messages", data={"content": request.args["c"]},
           files={"files[0]": (request.args["name"], request.get_data())})
    return jsonify(id=r.json()["id"])


@app.delete("/api/msg/<int:mid>")
def delete(mid):
    dc("DELETE", f"/channels/{CH}/messages/{mid}")
    return "", 204


# ---------- streaming (RAM only, nothing is ever written to disk) ----------
CHUNK = 9 * 1024 * 1024            # must match the uploader (index.html / vault_mcp.py)
CACHE_MAX = 50 * 1024 * 1024       # hard cap on decrypted data kept in RAM
PREFETCH = 2                       # chunks fetched ahead of the playhead
KEY = {"aes": None, "token": None} # lives in RAM only, set by the page after you unlock
_cache = OrderedDict()             # (file id, chunk index) -> decrypted bytes, oldest first
_cache_bytes = 0
_clock = threading.Lock()
_inflight = {}
_files = {}
_flock = threading.Lock()


def clear_stream_state():
    global _cache_bytes
    with _clock:
        _cache.clear()
        _cache_bytes = 0
    with _flock:
        _files.clear()


def unseal(b):
    return KEY["aes"].decrypt(b[:12], b[12:], None)


def scan():
    found, before = {}, None
    while True:
        params = {"limit": 100, **({"before": before} if before else {})}
        msgs = dc("GET", f"/channels/{CH}/messages", params=params).json()
        for m in msgs:
            p = m["content"].split(" ")
            if p[0] != "v1" or len(p) < 4 or not m["attachments"]:
                continue
            f = found.setdefault(p[1], {"chunks": {}, "n": int(p[3])})
            if p[2] == "m":
                f["meta"] = m["attachments"][0]["url"]
            else:
                f["chunks"][int(p[2][1:])] = m["attachments"][0]["url"]
        if len(msgs) < 100:
            return found
        before = msgs[-1]["id"]


def get_info(fid, refresh=False):
    with _flock:
        hit = _files.get(fid)
        if hit and not refresh and time.time() - hit[0] < 600:
            return hit[1]
    f = scan().get(fid)
    if not f or "meta" not in f or len(f["chunks"]) != f["n"]:
        abort(404)
    meta = json.loads(unseal(requests.get(f["meta"], timeout=60).content))
    info = {"chunks": f["chunks"], "n": f["n"], "size": meta["size"], "type": meta.get("type") or ""}
    with _flock:
        _files[fid] = (time.time(), info)
    return info


def get_chunk(fid, idx):
    """Decrypted chunk from RAM, or downloaded + decrypted. Keeps total RAM under CACHE_MAX."""
    global _cache_bytes
    k = (fid, idx)
    with _clock:
        if k in _cache:
            _cache.move_to_end(k)
            return _cache[k]
        lk = _inflight.setdefault(k, threading.Lock())
    with lk:
        with _clock:
            if k in _cache:
                _cache.move_to_end(k)
                return _cache[k]
        data = None
        for attempt in (0, 1):   # second try re-reads Discord for fresh CDN links
            info = get_info(fid, refresh=bool(attempt))
            r = requests.get(info["chunks"][idx], timeout=300)
            if r.ok:
                data = unseal(r.content)
                break
        if data is None:
            fail("Discord download failed", 502)
        with _clock:
            _cache[k] = data
            _cache_bytes += len(data)
            while _cache_bytes > CACHE_MAX and len(_cache) > 1:
                _, old = _cache.popitem(last=False)   # drop the oldest chunk
                _cache_bytes -= len(old)
            _inflight.pop(k, None)
        return data


def prefetch(fid, idx, n):
    if idx >= n:
        return
    try:
        get_chunk(fid, idx)
    except BaseException:
        pass


@app.post("/api/key")
def set_key():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403)
    raw = base64.b64decode(request.get_json()["k"])
    if len(raw) != 32:
        abort(400)
    clear_stream_state()
    KEY["aes"], KEY["token"] = AESGCM(raw), secrets.token_urlsafe(18)
    return jsonify(t=KEY["token"])


@app.delete("/api/key")
def drop_key():
    KEY["aes"] = KEY["token"] = None
    clear_stream_state()
    return "", 204


@app.get("/api/stream/<fid>")
def stream(fid):
    if not KEY["aes"] or not secrets.compare_digest(request.args.get("t", ""), KEY["token"] or "x"):
        abort(403)
    info = get_info(fid)
    size, n = info["size"], info["n"]
    start, end = 0, size - 1
    rng = request.headers.get("Range", "")
    m = re.match(r"bytes=(\d*)-(\d*)$", rng)
    if m and (m.group(1) or m.group(2)):
        if m.group(1) == "":
            start = max(0, size - int(m.group(2)))
        else:
            start = int(m.group(1))
            if m.group(2):
                end = min(int(m.group(2)), size - 1)
    if start >= size or start > end:
        return Response(status=416, headers={"Content-Range": f"bytes */{size}"})

    def gen():
        pos = start
        while pos <= end:
            idx = pos // CHUNK
            for j in range(1, PREFETCH + 1):
                threading.Thread(target=prefetch, args=(fid, idx + j, n), daemon=True).start()
            data = get_chunk(fid, idx)
            off = pos - idx * CHUNK
            piece = data[off:off + (end - pos + 1)]
            yield piece
            pos += len(piece)

    h = {"Accept-Ranges": "bytes", "Content-Length": str(end - start + 1), "Cache-Control": "no-store"}
    if m:
        h["Content-Range"] = f"bytes {start}-{end}/{size}"
    return Response(gen(), status=206 if m else 200, mimetype=info["type"] or "application/octet-stream", headers=h)


if __name__ == "__main__":
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        ip = "your-pc-ip"
    print(f"\nOn this PC:  http://localhost:8787\nOn your phone (same Wi-Fi):  http://{ip}:8787\n")
    app.run(host="0.0.0.0", port=8787, threaded=True)
