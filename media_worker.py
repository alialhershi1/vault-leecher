import os, re, json, time, uuid, queue, threading, tempfile, mimetypes, socket, ipaddress
from datetime import timedelta
from urllib.parse import urlparse, unquote
import requests
from flask import Flask, request, jsonify, Response, abort, session, redirect
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or os.environ.get("LEECH_KEY", "change-this-session-secret")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(days=30))
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
    if not session.get("worker_authenticated"):
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

@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    supplied = str(d.get("key", ""))
    expected = os.environ.get("LEECH_KEY", "")
    if not expected or not __import__("hmac").compare_digest(supplied, expected):
        return jsonify(error="Invalid worker access key."), 401
    session.clear()
    session["worker_authenticated"] = True
    session.permanent = True
    return jsonify(ok=True, expires_in_days=30)

@app.post("/api/logout")
def logout():
    session.clear()
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


@app.get("/api/source/archive")
def source_archive():
    qtext = request.args.get("q","").strip()[:120]
    if len(qtext) < 2: return jsonify(results=[])
    try:
        r = requests.get("https://archive.org/advancedsearch.php",
            params={"q":f'mediatype:movies AND ({qtext})',
                    "fl[]":["identifier","title","year","licenseurl","description"],
                    "rows":8,"page":1,"output":"json"},
            timeout=18, headers={"User-Agent":"VaultMediaWorker/1.0"})
        r.raise_for_status()
        docs = r.json().get("response",{}).get("docs",[])
        out=[]
        for d in docs:
            ident=d.get("identifier","")
            if not ident: continue
            page="https://archive.org/details/"+ident
            direct=""
            try:
                mr=requests.get("https://archive.org/metadata/"+ident,timeout=12,
                               headers={"User-Agent":"VaultMediaWorker/1.0"})
                mr.raise_for_status()
                files=mr.json().get("files",[])
                candidates=[x for x in files if str(x.get("name","")).lower().endswith((".mp4",".m4v"))]
                if candidates:
                    fn=candidates[0].get("name","")
                    direct="https://archive.org/download/"+ident+"/"+requests.utils.requote_uri(fn)
            except Exception:
                pass
            out.append({"title":d.get("title") or ident,"year":d.get("year"),
                        "license":d.get("licenseurl") or "Rights not specified — verify before downloading",
                        "url":direct,"page":page,"identifier":ident})
        return jsonify(results=out)
    except Exception:
        return jsonify(error="Archive search is temporarily unavailable.",results=[]),502

@app.get("/api/source/commons")
def source_commons():
    qtext=request.args.get("q","").strip()[:120]
    if len(qtext)<2: return jsonify(results=[])
    try:
        r=requests.get("https://commons.wikimedia.org/w/api.php",
            params={"action":"query","format":"json","generator":"search",
                    "gsrsearch":"filetype:video "+qtext,"gsrnamespace":6,"gsrlimit":8,
                    "prop":"imageinfo","iiprop":"url|extmetadata"},
            timeout=18,headers={"User-Agent":"VaultMediaWorker/1.0"})
        r.raise_for_status()
        pages=r.json().get("query",{}).get("pages",{})
        out=[]
        for p in pages.values():
            info=(p.get("imageinfo") or [{}])[0]
            meta=info.get("extmetadata") or {}
            license=(meta.get("LicenseShortName") or {}).get("value","")
            out.append({"title":p.get("title","Video"),"license":license or "Check file page for license",
                        "url":info.get("url",""),"page":"https://commons.wikimedia.org/wiki/"+p.get("title","").replace(" ","_")})
        return jsonify(results=out)
    except Exception:
        return jsonify(error="Wikimedia search is temporarily unavailable.",results=[]),502

@app.get("/api/subtitles")
def subtitles():
    query=request.args.get("q","").strip()[:120]
    lang=request.args.get("lang","en").strip()[:8]
    api_key=os.environ.get("OPEN_SUBTITLES_API_KEY","")
    if not query: return jsonify(results=[])
    if not api_key:
        return jsonify(error="Add OPEN_SUBTITLES_API_KEY in the worker's Render environment to enable subtitle search.",results=[]),503
    try:
        r=requests.get("https://api.opensubtitles.com/api/v1/subtitles",
            params={"query":query,"languages":lang,"order_by":"download_count","order_direction":"desc"},
            headers={"Api-Key":api_key,"User-Agent":"VaultMediaWorker v1.0"},
            timeout=18)
        r.raise_for_status()
        out=[]
        for item in r.json().get("data",[])[:10]:
            a=item.get("attributes",{})
            files=a.get("files") or [{}]
            out.append({"name":a.get("feature_details",{}).get("title") or query,
                        "language":a.get("language",""),"release":a.get("release",""),
                        "downloads":a.get("download_count",0),
                        "url":"https://www.opensubtitles.com/en/subtitles/"+str(item.get("id",""))})
        return jsonify(results=out)
    except Exception:
        return jsonify(error="Subtitle search failed. Check the API key and try again.",results=[]),502


PAGE = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Vault Media</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b111b;color:#e8eef8;font:15px system-ui}
main{max-width:760px;margin:34px auto;padding:0 18px}h1{font-size:27px;margin:0}h2{font-size:18px;margin:0 0 12px}
p{color:#94a3b8;line-height:1.5}.panel,.job,.result{background:#141e2c;border:1px solid #29384c;border-radius:14px;padding:16px;margin:14px 0}
input,select{width:100%;padding:13px;border-radius:9px;border:1px solid #34445a;background:#0b111b;color:white;font:inherit;margin:5px 0}
button,.tab{padding:10px 14px;border:0;border-radius:9px;background:#79d6c3;color:#06211d;font-weight:700;margin:5px 5px 5px 0;cursor:pointer}
.tab{background:#29384c;color:#e8eef8}.tab.active{background:#79d6c3;color:#06211d}
.small{font-size:13px;color:#94a3b8}.error{color:#ff8989}.name{font-weight:650;overflow-wrap:anywhere}
.bar{height:6px;background:#29384c;border-radius:6px;margin:9px 0}.bar span{display:block;height:100%;background:#79d6c3;border-radius:6px}
a{color:#79d6c3;overflow-wrap:anywhere}.result{margin:9px 0}.hidden{display:none}
</style></head><body><main><h1>Vault Media</h1><p>Find openly licensed media and transfer direct files you own or are authorized to save into your encrypted Vault.</p>
<div class=panel id=loginPanel><label class=small>Worker access key (one-time login)</label><input id=key type=password placeholder='Enter key once' autocomplete=current-password><button id=login>Unlock worker</button><span id=loginStatus class=small></span></div>
<div class=panel id=appPanel style='display:none'><div class=small>Worker unlocked · session lasts up to 30 days <button id=logout class=tab>Log out</button></div>
<div><button class='tab active' data-tab='sources'>Sources</button><button class=tab data-tab='subs'>Subtitles</button><button class=tab data-tab='transfer'>Direct transfer</button></div></div>
<section id=sources>
<div class=panel><h2>Open media sources</h2><p class=small>Search Wikimedia Commons and Internet Archive. Check the license and rights on the source page before transferring anything.</p>
<input id=sq placeholder='Search title or topic'><button id=search>Search sources</button><div id=sourceResults></div></div>
</section>
<section id=subs class=hidden><div class=panel><h2>OpenSubtitles</h2><p class=small>Search subtitles for a video you own or are authorized to use. Requires OPEN_SUBTITLES_API_KEY in Render environment.</p>
<input id=subq placeholder='Movie or episode title'><select id=lang><option value=en>English</option><option value=ar>Arabic</option><option value=fr>French</option><option value=es>Spanish</option><option value=de>German</option></select><button id=subsearch>Search subtitles</button><div id=subResults></div></div></section>
<section id=transfer class=hidden><div class=panel><h2>Direct transfer</h2><input id=url placeholder='https://… direct file URL'><button id=add>Send to Vault</button><p class=small id=msg>No application-level file-size limit. Public HTTPS only; redirects and private network addresses are blocked. Hosting and Discord limits still apply.</p></div></section>
<div id=jobs></div></div></main>
<script>
const $=s=>document.querySelector(s);
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{document.querySelectorAll('[data-tab]').forEach(x=>x.classList.toggle('active',x===b));['sources','subs','transfer'].forEach(id=>$('#'+id).classList.toggle('hidden',id!==b.dataset.tab));});
async function api(path,opts={}){const r=await fetch(path,{...opts,credentials:'same-origin',headers:{'Content-Type':'application/json',...(opts.headers||{})}});if(!r.ok)throw Error(await r.text());return r}
function unlock(){ $('#loginPanel').style.display='none'; $('#appPanel').style.display='block'; load(); }
$('#login').onclick=async()=>{const status=$('#loginStatus');status.textContent='Checking…';try{const r=await fetch('/api/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:$('#key').value})});const d=await r.json();if(!r.ok)throw Error(d.error||'Login failed');$('#key').value='';unlock();}catch(e){status.textContent=e.message;status.className='small error'}};
$('#logout').onclick=async()=>{await fetch('/api/logout',{method:'POST',credentials:'same-origin'});$('#appPanel').style.display='none';$('#loginPanel').style.display='block';$('#loginStatus').textContent='Logged out.'};
(async()=>{try{const r=await api('/api/jobs');if(r.ok)unlock()}catch(e){}})();
function card(item,kind){const d=document.createElement('div');d.className='result';const n=document.createElement('div');n.className='name';n.textContent=item.title||item.name;const p=document.createElement('p');p.className='small';p.textContent=(item.year||'')+' · '+(item.license||item.language||'')+(item.release?' · '+item.release:'');const a=document.createElement('a');a.href=item.page||item.url;a.target='_blank';a.rel='noopener';a.textContent='Open source / details';d.append(n,p,a);
if(kind==='file'&&item.url){const b=document.createElement('button');b.textContent='Use direct file';b.onclick=()=>{document.querySelectorAll('[data-tab]').forEach(x=>x.classList.toggle('active',x.dataset.tab==='transfer'));['sources','subs','transfer'].forEach(id=>$('#'+id).classList.toggle('hidden',id!=='transfer'));$('#url').value=item.url;};d.append(b)}return d}
$('#search').onclick=async()=>{const q= $('#sq').value.trim(),box=$('#sourceResults');box.replaceChildren();if(!q)return;box.textContent='Searching…';try{const [a,w]=await Promise.all([fetch('/api/source/archive?q='+encodeURIComponent(q)).then(r=>r.json()),fetch('/api/source/commons?q='+encodeURIComponent(q)).then(r=>r.json())]);box.replaceChildren();for(const x of (a.results||[])){const d=card(x,x.url?'file':'page');box.append(d)}for(const x of (w.results||[])){const d=card(x,'file');box.append(d)}if(!box.children.length)box.textContent=a.error||w.error||'No results found.'}catch(e){box.textContent=e.message}};
$('#subsearch').onclick=async()=>{const box=$('#subResults');box.textContent='Searching…';try{const d=await(await fetch('/api/subtitles?q='+encodeURIComponent($('#subq').value)+'&lang='+$('#lang').value)).json();box.replaceChildren();if(d.error){box.textContent=d.error;return}for(const x of d.results||[])box.append(card(x,'page'));if(!box.children.length)box.textContent='No subtitles found.'}catch(e){box.textContent=e.message}};
$('#add').onclick=async()=>{try{await api('/api/add',{method:'POST',body:JSON.stringify({url:$('#url').value.trim()})});$('#url').value='';$('#msg').textContent='Queued.';load()}catch(e){$('#msg').textContent=e.message;$('#msg').className='small error'}};
async function load(){if($('#appPanel').style.display==='none')return;try{const data=await(await api('/api/jobs')).json(),box=$('#jobs');box.replaceChildren();for(const j of data){const d=document.createElement('div');d.className='job';const n=document.createElement('div');n.className='name';n.textContent=j.name||'Download';const s=document.createElement('div');s.className='small'+(j.error?' error':'');s.textContent=j.status+' · '+(j.pct||0)+'%'+(j.error?' · '+j.error:'');const b=document.createElement('div');b.className='bar';const v=document.createElement('span');v.style.width=(j.pct||0)+'%';b.append(v);d.append(n,b,s);box.append(d)}}catch(e){}}
setInterval(load,2500);</script></body></html>"""

threading.Thread(target=worker,daemon=True).start()
