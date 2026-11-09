"""One-shot Cloud Run Job: download an authorized HTTP(S) URL or magnet, encrypt it,
and upload it to the existing Discord Vault. No web server or always-on worker."""
import json
import mimetypes
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import secrets
from email.message import Message
from urllib.parse import urljoin, urlparse, unquote

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import vault_server as V

MAX_BYTES = int(float(os.environ.get("MAX_DOWNLOAD_GB", "8")) * 1024**3)
TIMEOUT = int(os.environ.get("JOB_TIMEOUT_SECONDS", "7200"))
UA = "VaultCloudLeech/1.0"


def public_http_url(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Direct links must be public HTTP(S) URLs.")
    try:
        addresses = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    except OSError as exc:
        raise ValueError("Could not resolve the download host.") from exc
    if not addresses:
        raise ValueError("Download host has no public address.")
    import ipaddress
    for item in addresses:
        ip = item[4][0].split("%", 1)[0]
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError("Private or local network URLs are blocked.")
    return url


def safe_name(value, fallback="download.bin"):
    value = os.path.basename(str(value or "").replace("\\", "/")).strip()
    value = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", value)
    return value[:180] or fallback


def direct_download(url, folder):
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    current = url
    response = None
    for _ in range(6):
        public_http_url(current)
        response = session.get(current, stream=True, allow_redirects=False, timeout=(20, 90))
        if response.is_redirect or response.is_permanent_redirect:
            nxt = response.headers.get("Location")
            response.close()
            if not nxt:
                raise RuntimeError("Download redirect had no destination.")
            current = urljoin(current, nxt)
            continue
        response.raise_for_status()
        break
    else:
        raise RuntimeError("Too many download redirects.")
    cd = Message()
    cd["content-disposition"] = response.headers.get("Content-Disposition", "")
    name = safe_name(cd.get_filename() or unquote(urlparse(current).path.rsplit("/", 1)[-1]))
    path = os.path.join(folder, name)
    declared = int(response.headers.get("Content-Length", "0") or 0)
    if declared > MAX_BYTES:
        response.close()
        raise RuntimeError("File exceeds the configured download-size limit.")
    total = 0
    try:
        with open(path, "wb") as out:
            for block in response.iter_content(1024 * 1024):
                if not block:
                    continue
                total += len(block)
                if total > MAX_BYTES:
                    raise RuntimeError("File exceeded the configured download-size limit.")
                out.write(block)
    finally:
        response.close()
    if total == 0:
        raise RuntimeError("The download was empty.")
    print(f"Downloaded {name}: {total} bytes", flush=True)
    return [path]


def folder_bytes(folder):
    total = 0
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for filename in files:
            path = os.path.join(root, filename)
            if not os.path.islink(path) and os.path.isfile(path):
                total += os.path.getsize(path)
    return total


def torrent_download(link, folder):
    if not link.startswith("magnet:?") or not re.search(r"xt=urn:bt(?:ih|mh):", link, re.I):
        raise ValueError("Use a valid magnet link containing a BitTorrent info hash.")
    cmd = [
        "aria2c", "--dir=" + folder, "--seed-time=0", "--summary-interval=5",
        "--console-log-level=notice", "--file-allocation=none",
        "--max-connection-per-server=8", "--split=8", "--bt-max-peers=40",
        "--enable-dht=true", "--follow-torrent=true", "--auto-file-renaming=false",
        "--allow-overwrite=true", "--max-tries=5", "--retry-wait=5",
        "--connect-timeout=20", "--timeout=60", "--bt-stop-timeout=600",
        "--check-certificate=true", link
    ]
    print("Starting magnet download (authorized content only).", flush=True)
    log_path = os.path.join(folder, ".aria2-job.log")
    started = time.time()
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)
        try:
            while p.poll() is None:
                if time.time() - started > TIMEOUT:
                    p.terminate()
                    raise TimeoutError("Download exceeded the job time limit.")
                if folder_bytes(folder) > MAX_BYTES:
                    p.terminate()
                    raise RuntimeError("Torrent exceeded MAX_DOWNLOAD_GB; download stopped.")
                time.sleep(5)
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
        rc = p.returncode
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as log:
            tail = log.readlines()[-8:]
        for line in tail:
            if "DL:" in line or "ETA:" in line:
                print(line.strip()[:240], flush=True)
    finally:
        try:
            os.remove(log_path)
        except OSError:
            pass
    if rc:
        raise RuntimeError("aria2 download failed: " + " | ".join(x.strip() for x in tail)[-500:])
    paths = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for filename in files:
            path = os.path.join(root, filename)
            if filename.endswith((".aria2", ".torrent")) or os.path.islink(path):
                continue
            if os.path.isfile(path) and os.path.getsize(path):
                paths.append(path)
    return sorted(paths)


def seal(aes, data):
    iv = os.urandom(12)
    return iv + aes.encrypt(iv, data, None)


def send_to_vault(aes, path, name):
    size = os.path.getsize(path)
    chunks = max(1, (size + V.CHUNK - 1) // V.CHUNK)
    fid = secrets.token_hex(6)
    mime = mimetypes.guess_type(name)[0] or ""
    meta = json.dumps({
        "name": name, "type": mime, "size": size,
        "t": int(time.time() * 1000)
    }).encode()
    V.dc("POST", f"/channels/{V.CH}/messages",
         data={"content": f"v1 {fid} m {chunks}"},
         files={"files[0]": (f"m{fid}.bin", seal(aes, meta))})
    sent = 0
    with open(path, "rb") as source:
        for index in range(chunks):
            block = source.read(V.CHUNK)
            V.dc("POST", f"/channels/{V.CH}/messages",
                 data={"content": f"v1 {fid} c{index} {chunks}"},
                 files={"files[0]": (f"{fid}.{index}.bin", seal(aes, block))})
            sent += len(block)
            print(f"Vault upload: {name} {sent}/{size} bytes", flush=True)
    return size


def main():
    link = sys.argv[1].strip() if len(sys.argv) > 1 else os.environ.get("LEECH_LINK", "").strip()
    if not link:
        raise SystemExit("Provide a magnet or direct URL as the job argument.")
    password = os.environ.get("VAULT_PASSWORD", "")
    if not password or not V.CH or not V.S.headers.get("Authorization"):
        raise SystemExit("Missing VAULT_PASSWORD, DISCORD_TOKEN, or DISCORD_CHANNEL.")
    aes_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=b"vault-v1", iterations=300000
    ).derive(password.encode())
    aes = AESGCM(aes_key)

    with tempfile.TemporaryDirectory(prefix="vault-leech-") as folder:
        files = torrent_download(link, folder) if link.startswith("magnet:") else direct_download(link, folder)
        if not files:
            raise RuntimeError("No completed files were found.")
        total = sum(os.path.getsize(p) for p in files)
        if total > MAX_BYTES:
            raise RuntimeError("Download exceeds MAX_DOWNLOAD_GB.")
        for path in files:
            send_to_vault(aes, path, safe_name(os.path.basename(path)))
            os.remove(path)
        print(f"Completed: {len(files)} file(s), {total} bytes uploaded to the encrypted vault.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"LEECH FAILED: {str(exc)[:500]}", file=sys.stderr, flush=True)
        raise
