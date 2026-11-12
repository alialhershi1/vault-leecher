import os, re, json, time, uuid, queue, threading, tempfile, mimetypes, socket, ipaddress
from urllib.parse import urlparse, unquote
import requests
from flask import Flask, request, jsonify, Response, abort
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
CHUNK = 9 * 1024 * 1024
jobs, order, q = {}, [], queue.Queue()
lock = threading.Lock()
aes = None

def config():
    global aes
    password = os.environ.get("VAULT_PASSWORD", "")
    token = os.environ.get("DISCORD_TOKEN", "")
    channel = os.environ.get("DISCORD_CHANNEL", "")
    key = os.environ.get("LEECH_KEY", "")
    if not all((password, token, channel, key)) or len(key) < 16:
        raise RuntimeError("Set VAULT_PASSWORD, DISCORD_TOKEN, DISCORD_CHANNEL and LEECH_KEY (16+ chars).")
    k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"vault-v1", iterations=300000).derive(password.encode())
    aes = AESGCM(k)
    r = requests.get(f"https://discord.com/api/v10/channels/{channel}", headers={"Authorization":"Bot "+token}, timeout=20)
    r.raise_for_status()
    return token, channel, key

def auth():
    key = os.environ.get("LEECH_KEY", "")
    if not key or not __import__("hmac").compare_digest(request.headers.get("X-Key",""), key):
        abort(401)

def safe_url(raw):
    u = urlparse(raw)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise ValueError("Use a public HTTPS direct-download URL.")
    try:
        infos = socket.getaddrinfo(u.hostname, 443, type=socket.SOCK_STREAM)
        ips = {ipaddress.ip_address(x[4][0]) for x in infos}
    except Exception:
        raise ValueError("The download host could not be resolved.")
    if not ips or any(not ip.is_global for ip in ips):
        raise ValueError("Private or local network addresses are blocked.")
    return u

def seal(data):
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data, None)

def discord_send(token, channel, content, filename, data):
    r = requests.post(f"https://discord.com/api/v10/channels/{channel}/messages",
        headers={"Authorization":"Bot "+token},
        data={"content":content},
        files={"files[0]":(filename,data,"application/octet-stream")}, timeout=180)
    r.raise_for_status()

def public(j):
    return {k:j.get(k) for k in ("id","name","status","pct","error","size")}

def process(j):
    token, channel, _ = config()
    tmp = None
    try:
        j["status"] = "downloading"
        u = safe_url(j["url"])
        with requests.get(j["url"], stream=True, timeout=(20,90), allow_redirects=False,
                          headers={"User-Agent":"VaultMediaWorker/1.0"}) as r:
            if r.is_redirect:
                raise ValueError("Redirects are disabled. Use the final HTTPS download URL.")
            r.raise_for_status()
            length = int(r.headers.get("Content-Length") or 0)
            name = unquote(os.path.basename(u.path)) or "download.bin"
            name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)[:120] or "download.bin"
            total = 0
            fd, tmp = tempfile.mkstemp(prefix="vault-media-")
            with os.fdopen(fd,"wb") as f:
                for block in r.iter_content(256*1024):
                    if not block: continue
                    total += len(block)
                    f.write(block)
                    j["pct"] = min(95, int(total*95/max(1,length))) if length else 0
        if total <= 0: raise ValueError("The URL returned an empty file.")
        j.update(status="uploading",name=name,pct=95,size=total)
        fid = uuid.uuid4().hex[:12]
        count = max(1,(total+CHUNK-1)//CHUNK)
        with open(tmp,"rb") as f:
            for i in range(count):
                data = f.read(CHUNK)
                discord_send(token,channel,f"v1 {fid} c{i} {count}",f"{fid}.{i}.bin",seal(data))
                j["pct"] = 95 + int((i+1)*4/count)
        meta = json.dumps({"name":name,"type":mimetypes.guess_type(name)[0] or "",
                           "size":total,"t":int(time.time()*1000)}).encode()
        discord_send(token,channel,f"v1 {fid} m {count}",f"m{fid}.bin",seal(meta))
        j.update(status="done",pct=100)
    except Exception as e:
        j.update(status="error",error=str(e)[:500])
    finally:
        if tmp:
            try: os.remove(tmp)
            except OSError: pass

def worker():
    while True:
        j=q.get()
        process(j)

@app.get("/")
def home():
    return Response(PAGE,mimetype="text/html",headers={"Cache-Control":"no-store"})

@app.get("/health")
def health():
    return jsonify(ok=True)

@app.post("/api/add")
def add():
    auth()
    d=request.get_json(silent=True) or {}
    url=str(d.get("url","")).strip()
    if len(url)>4096: return "URL too long",400
    try: safe_url(url)
    except Exception as e: return str(e),400
    j={"id":uuid.uuid4().hex[:10],"url":url,"name":"Direct download","status":"queued","pct":0}
    with lock:
        jobs[j["id"]]=j; order.insert(0,j["id"])
        for old in order[50:]: jobs.pop(old,None)
        del order[50:]
    q.put(j)
    return jsonify(public(j)),202

@app.get("/api/jobs")
def list_jobs():
    auth()
    with lock: return jsonify([public(jobs[i]) for i in order if i in jobs])

PAGE = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Vault Media</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b111b;color:#e8eef8;font:15px system-ui}
main{max-width:720px;margin:40px auto;padding:0 18px}h1{font-size:27px;margin:0}p{color:#94a3b8;line-height:1.5}
.panel,.job{background:#141e2c;border:1px solid #29384c;border-radius:14px;padding:16px;margin:14px 0}
input{width:100%;padding:13px;border-radius:9px;border:1px solid #34445a;background:#0b111b;color:white;font:inherit}
button{padding:11px 17px;border:0;border-radius:9px;background:#79d6c3;color:#06211d;font-weight:700;margin-top:10px;cursor:pointer}
.small{font-size:13px;color:#94a3b8}.error{color:#ff8989}.name{font-weight:650;overflow-wrap:anywhere}
.bar{height:6px;background:#29384c;border-radius:6px;margin:9px 0}.bar span{display:block;height:100%;background:#79d6c3;border-radius:6px}
</style></head><body><main><h1>Vault Media</h1><p>Send a direct HTTPS download that you own or are authorized to save. The worker transfers it into your encrypted Discord Vault.</p>
<div class=panel><input id=key type=password placeholder='Worker access key' autocomplete=off><br><br>
<input id=url placeholder='https://… direct file URL' autocomplete=off><button id=add>Download to Vault</button>
<p class=small id=msg>No application-level file-size limit. Public HTTPS hosts only; redirects and private network addresses are blocked.</p></div><div id=jobs></div></main>
<script>
const $=s=>document.querySelector(s);let key='';
async function api(path,opts={}){key=$('#key').value;const r=await fetch(path,{...opts,headers:{'Content-Type':'application/json','X-Key':key}});if(!r.ok)throw Error(await r.text());return r}
$('#add').onclick=async()=>{try{await api('/api/add',{method:'POST',body:JSON.stringify({url:$('#url').value.trim()})});$('#url').value='';$('#msg').textContent='Queued.';load()}catch(e){$('#msg').textContent=e.message;$('#msg').className='small error'}};
async function load(){if(!$('#key').value)return;try{const data=await(await api('/api/jobs')).json(),box=$('#jobs');box.replaceChildren();for(const j of data){const d=document.createElement('div');d.className='job';const n=document.createElement('div');n.className='name';n.textContent=j.name||'Download';const s=document.createElement('div');s.className='small'+(j.error?' error':'');s.textContent=j.status+' · '+(j.pct||0)+'%'+(j.error?' · '+j.error:'');const b=document.createElement('div');b.className='bar';const v=document.createElement('span');v.style.width=(j.pct||0)+'%';b.append(v);d.append(n,b,s);box.append(d)}}catch(e){$('#msg').textContent=e.message}}
setInterval(load,2500);</script></body></html>"""

threading.Thread(target=worker,daemon=True).start()
