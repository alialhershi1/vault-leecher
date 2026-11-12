import os, re, json, time, uuid, queue, threading, tempfile, mimetypes, socket, ipaddress
from datetime import timedelta
from urllib.parse import urlparse, unquote, urljoin, quote
import requests
from flask import Flask, request, jsonify, Response, abort, session, redirect
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from media_providers import get_provider, public_providers, ProviderError

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or os.environ.get("LEECH_KEY", "change-this-session-secret")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(days=30))
CHUNK = 9 * 1024 * 1024
jobs, order, q = {}, [], queue.Queue()
lock = threading.Lock()
aes = None
TORRENT_LEECH_URL = os.environ.get("TORRENT_LEECH_URL", "https://vault-leech-2ls7.onrender.com").strip().rstrip("/")

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
        download_url = j["url"]
        response = None
        for _hop in range(6):
            safe_url(download_url)
            response = requests.get(download_url, stream=True, timeout=(20,90), allow_redirects=False,
                                    headers={"User-Agent":"VaultMediaWorker/1.0"})
            if response.is_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    raise ValueError("The download source returned an invalid redirect.")
                download_url = urljoin(download_url, location)
                continue
            break
        else:
            raise ValueError("Too many download redirects.")
        with response as r:
            r.raise_for_status()
            length = int(r.headers.get("Content-Length") or 0)
            url_path = urlparse(download_url).path
            name = j.get("name") or unquote(os.path.basename(url_path)) or "download.bin"
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
    name = str(d.get("name") or "Direct download").strip()[:180]
    j={"id":uuid.uuid4().hex[:10],"url":url,"name":name,"status":"queued","pct":0}
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



# ---------------------------------------------------------------------------
# Openly licensed film catalogue (Internet Archive metadata)
_CC_RE = re.compile(
    r"^https?://creativecommons[.]org/licenses/(?:by|by-sa|by-nc|by-nc-sa|by-nd|by-nc-nd)/[0-9.]+/?$",
    re.I
)
_VIDEO_EXTS = (".mp4", ".mkv", ".webm", ".mov", ".m4v", ".avi", ".ogv")


def _cc_license(value):
    return bool(_CC_RE.match(str(value or "").strip()))


def _ia_metadata(identifier):
    identifier = str(identifier or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,180}", identifier):
        raise ValueError("Invalid archive item identifier.")
    response = requests.get("https://archive.org/metadata/" + quote(identifier, safe="._-"),
                            timeout=25, headers={"User-Agent":"VaultMediaWorker/1.0"})
    response.raise_for_status()
    data = response.json()
    metadata = data.get("metadata") or {}
    license_url = metadata.get("licenseurl") or metadata.get("license_url") or ""
    if not _cc_license(license_url):
        raise ValueError("This item does not declare a supported Creative Commons licence.")
    if str(metadata.get("access-restricted-item", "")).lower() in ("true", "1", "yes"):
        raise ValueError("This archive item is access restricted.")
    return data, metadata, license_url


@app.get("/api/providers")
def providers_list():
    auth()
    return jsonify(providers=public_providers())


@app.get("/api/providers/<provider_id>/search")
def provider_search(provider_id):
    auth()
    try:
        provider = get_provider(provider_id)
        return jsonify(items=provider.search(request.args.get("q", "").strip()[:100]))
    except ProviderError as exc:
        return jsonify(error=str(exc), items=[]), 400
    except Exception:
        return jsonify(error="The selected catalogue is temporarily unavailable.", items=[]), 502


@app.get("/api/providers/<provider_id>/item/<identifier>")
def provider_item(provider_id, identifier):
    auth()
    try:
        provider = get_provider(provider_id)
        return jsonify(provider.item(identifier))
    except ProviderError as exc:
        return jsonify(error=str(exc)), 403
    except Exception:
        return jsonify(error="Could not load this catalogue item."), 502


@app.get("/api/movies/search")
def movie_search():
    auth()
    raw = request.args.get("q", "").strip()[:100]
    terms = re.findall(r"[A-Za-z0-9]+", raw)
    if not terms:
        return jsonify(items=[])
    query = "mediatype:movies AND licenseurl:* AND title:(" + " AND ".join(terms) + ")"
    try:
        response = requests.get("https://archive.org/advancedsearch.php",
            params={"q":query,"fl[]":["identifier","title","year","licenseurl","creator","description"],
                    "rows":30,"page":1,"output":"json","sort[]":"downloads desc"},
            timeout=25, headers={"User-Agent":"VaultMediaWorker/1.0"})
        response.raise_for_status()
        docs = response.json().get("response",{}).get("docs",[])
        items = []
        for item in docs:
            lic = item.get("licenseurl") or ""
            if not _cc_license(lic):
                continue
            ident = str(item.get("identifier") or "")
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,180}", ident):
                continue
            creator = item.get("creator") or ""
            if isinstance(creator, list):
                creator = ", ".join(str(x) for x in creator[:2])
            description = item.get("description") or ""
            if isinstance(description, list):
                description = " ".join(str(x) for x in description[:2])
            items.append({"id":ident,"title":str(item.get("title") or ident)[:180],
                          "year":str(item.get("year") or "")[:12],
                          "creator":str(creator)[:120],"description":str(description)[:260],
                          "license":lic,"poster":"https://archive.org/services/img/"+ident,
                          "page":"https://archive.org/details/"+ident})
        return jsonify(items=items[:24])
    except Exception:
        return jsonify(error="Open-licence film search is temporarily unavailable.",items=[]),502


@app.get("/api/movies/item/<identifier>")
def movie_item(identifier):
    auth()
    try:
        data, metadata, lic = _ia_metadata(identifier)
        files = []
        for item in data.get("files") or []:
            filename = str(item.get("name") or "")
            lower = filename.lower()
            is_torrent = lower.endswith(".torrent")
            is_video = lower.endswith(_VIDEO_EXTS)
            if not (is_torrent or is_video):
                continue
            try:
                size = int(item.get("size") or 0)
            except (TypeError, ValueError):
                size = 0
            if size <= 0:
                continue
            files.append({"name":filename,"size":size,"kind":"torrent" if is_torrent else "video",
                          "format":str(item.get("format") or "")[:80]})
        files.sort(key=lambda x: (x["kind"] != "video", -x["size"]))
        creator = metadata.get("creator") or ""
        if isinstance(creator,list):
            creator = ", ".join(str(x) for x in creator[:3])
        desc = metadata.get("description") or ""
        if isinstance(desc,list):
            desc = " ".join(str(x) for x in desc[:3])
        return jsonify(item={"id":identifier,"title":str(metadata.get("title") or identifier)[:180],
                             "year":str(metadata.get("year") or metadata.get("date") or "")[:20],
                             "creator":str(creator)[:160],"description":str(desc)[:1800],
                             "license":lic,"page":"https://archive.org/details/"+identifier},
                       files=files)
    except ValueError as exc:
        return jsonify(error=str(exc)),403
    except Exception:
        return jsonify(error="Could not load the source files for this archive item."),502


def _upstream_torrent(link):
    key = os.environ.get("TORRENT_LEECH_KEY") or os.environ.get("LEECH_KEY", "")
    if not key:
        raise RuntimeError("Torrent worker access key is not configured.")
    response = requests.post(TORRENT_LEECH_URL + "/api/add",
        headers={"X-Key":key,"User-Agent":"VaultMediaWorker/1.0"},
        json={"link":link}, timeout=35)
    if response.status_code == 401:
        raise RuntimeError("The torrent worker rejected its access key. Set TORRENT_LEECH_KEY to the key configured on vault-leech.")
    response.raise_for_status()
    return response.json()


@app.post("/api/movies/download")
def movie_download():
    auth()
    body = request.get_json(silent=True) or {}
    identifier = str(body.get("id") or "")
    filename = str(body.get("filename") or "")
    kind = str(body.get("kind") or "")
    try:
        data, metadata, _lic = _ia_metadata(identifier)
        match = next((x for x in (data.get("files") or []) if str(x.get("name") or "") == filename), None)
        if not match:
            return jsonify(error="That file is not part of the selected archive item."),400
        lower = filename.lower()
        if kind == "torrent" and lower.endswith(".torrent"):
            link = "https://archive.org/download/" + quote(identifier, safe="._-") + "/" + quote(filename, safe="/")
            job = _upstream_torrent(link)
            return jsonify(mode="torrent",job=job),202
        if kind != "video" or not lower.endswith(_VIDEO_EXTS):
            return jsonify(error="Unsupported source file."),400
        link = "https://archive.org/download/" + quote(identifier, safe="._-") + "/" + quote(filename, safe="/")
        safe_url(link)
        job = {"id":uuid.uuid4().hex[:10],"url":link,"name":os.path.basename(filename),
               "status":"queued","pct":0}
        with lock:
            jobs[job["id"]]=job; order.insert(0,job["id"])
            for old in order[50:]: jobs.pop(old,None)
            del order[50:]
        q.put(job)
        return jsonify(mode="direct",job=public(job)),202
    except ValueError as exc:
        return jsonify(error=str(exc)),403
    except Exception as exc:
        return jsonify(error=str(exc)[:260]),502


@app.post("/api/torrents/add")
def torrent_add():
    auth()
    body = request.get_json(silent=True) or {}
    link = str(body.get("link") or "").strip()
    if link.startswith("magnet:?"):
        if not body.get("authorized"):
            return jsonify(error="Confirm that you have permission to download this content."),400
    else:
        try:
            parsed = safe_url(link)
        except Exception as exc:
            return jsonify(error=str(exc)),400
        if not parsed.path.lower().endswith(".torrent"):
            return jsonify(error="Provide a magnet link or a .torrent file URL."),400
        if (parsed.hostname or "").lower() not in ("archive.org","www.archive.org"):
            return jsonify(error="For file-based torrent sources, use a verified Archive item shown in Movies & Series."),400
        if not body.get("authorized"):
            return jsonify(error="Confirm that you have permission to download this content."),400
    try:
        return jsonify(job=_upstream_torrent(link)),202
    except Exception as exc:
        return jsonify(error=str(exc)[:260]),502


@app.get("/api/torrents/jobs")
def torrent_jobs():
    auth()
    key = os.environ.get("TORRENT_LEECH_KEY") or os.environ.get("LEECH_KEY", "")
    try:
        response = requests.get(TORRENT_LEECH_URL + "/api/jobs",
            headers={"X-Key":key,"User-Agent":"VaultMediaWorker/1.0"},timeout=20)
        if response.status_code == 401:
            return jsonify(error="The torrent worker rejected its access key. Set TORRENT_LEECH_KEY to the key configured on vault-leech.",items=[]),502
        response.raise_for_status()
        return jsonify(items=response.json())
    except Exception as exc:
        return jsonify(error=str(exc)[:240],items=[]),502


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
<div><button class='tab active' data-tab='sources'>Movies &amp; Series</button><button class=tab data-tab='subs'>Subtitles</button><button class=tab data-tab='transfer'>Direct transfer</button></div>
<section id=sources>
<div class=panel><h2>Browse openly licensed movies &amp; series</h2><p class=small>Search verified Creative Commons catalogue entries. Open a title to see its available video files and any archive torrent file.</p>
<select id=providerSelect aria-label='Media catalogue'><option value='archive_cc'>Source 1 · Internet Archive (Creative Commons)</option><option value='source_2' disabled>Source 2 · Reserved</option></select><input id=movieQuery placeholder='Search movie or series title'><button id=movieSearch>Search</button><div id=providerStatus class=small>Source 1 · openly licensed catalogue</div><div id=movieResults></div>
<div id=movieDetail></div>
</div>
<div class=panel><h2>Magnet link</h2><p class=small>For a magnet link to content you are authorized to download, paste it here. The existing torrent server downloads it and uploads the files into your Vault.</p>
<input id=magnetInput placeholder='magnet:?xt=urn:btih:…'><label class=small><input id=magnetAuthorized type=checkbox style='width:auto'> I have permission to download this content</label><br><button id=magnetAdd>Send magnet to server</button><div id=magnetStatus class=small></div>
</div>
<div class=panel><h2>Torrent downloads</h2><div id=torrentJobs class=small>Loading torrent queue…</div></div>
</section>
<section id=subs class=hidden><div class=panel><h2>OpenSubtitles</h2><p class=small>Search subtitles for a video you own or are authorized to use. Requires OPEN_SUBTITLES_API_KEY in Render environment.</p>
<input id=subq placeholder='Movie or episode title'><select id=lang><option value=en>English</option><option value=ar>Arabic</option><option value=fr>French</option><option value=es>Spanish</option><option value=de>German</option></select><button id=subsearch>Search subtitles</button><div id=subResults></div></div></section>
<section id=transfer class=hidden><div class=panel><h2>Direct transfer</h2><input id=url placeholder='https://… direct file URL'><button id=add>Send to Vault</button><p class=small id=msg>No application-level file-size limit. Public HTTPS only; redirects are followed only after each destination is checked. Hosting and Discord limits still apply.</p></div></section>
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
function fmtSize(n){n=Number(n)||0;for(const u of ['B','KB','MB','GB','TB']){if(n<1024||u==='TB')return (u==='B'?Math.round(n):n.toFixed(1))+' '+u;n/=1024}}
function safeText(el,tag,cls,value){const x=document.createElement(tag);if(cls)x.className=cls;x.textContent=value||'';el.append(x);return x}
async function findMovies(){const q=$('#movieQuery').value.trim(),box=$('#movieResults');$('#movieDetail').replaceChildren();box.textContent='Searching…';if(!q){box.textContent='Enter a title.';return}
try{const provider=$('#providerSelect').value;const d=await(await api('/api/providers/'+encodeURIComponent(provider)+'/search?q='+encodeURIComponent(q))).json();if(d.error)throw Error(d.error);box.replaceChildren();if(!(d.items||[]).length){box.textContent='No clearly licensed matches found. Try another title.';return}
for(const it of d.items){const card=document.createElement('div');card.className='result';const row=document.createElement('div');row.style.cssText='display:flex;gap:12px;align-items:flex-start';const img=document.createElement('img');img.src=it.poster;img.alt='';img.loading='lazy';img.style.cssText='width:76px;height:108px;object-fit:cover;border-radius:8px;background:#0b111b';const info=document.createElement('div');info.style.minWidth='0';safeText(info,'div','name',it.title);safeText(info,'div','small',(it.year||'')+(it.creator?' · '+it.creator:''));safeText(info,'div','small','Creative Commons licence');const b=document.createElement('button');b.textContent='Show sources';b.onclick=()=>openMovie(it.id);info.append(b);row.append(img,info);card.append(row);box.append(card)}}catch(e){box.textContent=e.message}}
async function openMovie(id){const box=$('#movieDetail');box.textContent='Loading source files…';try{const provider=$('#providerSelect').value;const d=await(await api('/api/providers/'+encodeURIComponent(provider)+'/item/'+encodeURIComponent(id))).json();if(!d.item)throw Error(d.error||'Could not load title');box.replaceChildren();const panel=document.createElement('div');panel.className='result';safeText(panel,'div','name',d.item.title+' · '+(d.item.year||''));safeText(panel,'p','small',d.item.description||'No description supplied.');const lic=document.createElement('a');lic.href=d.item.license;lic.target='_blank';lic.rel='noopener';lic.textContent='View Creative Commons licence';panel.append(lic);safeText(panel,'h3','', 'Available files');if(!d.files.length)safeText(panel,'p','small','No video or torrent files are listed for this item.');
for(const f of d.files){const row=document.createElement('div');row.className='result';const title=document.createElement('div');title.className='name';title.textContent=f.name;const detail=document.createElement('div');detail.className='small';detail.textContent=(f.kind==='torrent'?'Archive torrent':'Video file')+' · '+fmtSize(f.size)+(f.format?' · '+f.format:'');const b=document.createElement('button');b.textContent=f.kind==='torrent'?'Download via torrent server':'Download to Vault';b.onclick=async()=>{b.disabled=true;try{const r=await api('/api/movies/download',{method:'POST',body:JSON.stringify({id,filename:f.name,kind:f.kind})});const result=await r.json();if(!r.ok)throw Error(result.error||'Could not queue this source');b.textContent=result.mode==='torrent'?'Torrent queued':'Queued for Vault';load();loadTorrentJobs()}catch(e){b.disabled=false;detail.textContent=e.message}};row.append(title,detail,b);panel.append(row)}
box.append(panel)}catch(e){box.textContent=e.message}}
async function addMagnet(){const link=$('#magnetInput').value.trim(),status=$('#magnetStatus');if(!link)return;try{const r=await api('/api/torrents/add',{method:'POST',body:JSON.stringify({link,authorized:$('#magnetAuthorized').checked})});const d=await r.json();if(!r.ok)throw Error(d.error||'Could not queue magnet');$('#magnetInput').value='';status.textContent='Torrent queued on the server.';loadTorrentJobs()}catch(e){status.textContent=e.message}}
async function loadTorrentJobs(){const box=$('#torrentJobs');try{const r=await api('/api/torrents/jobs');const d=await r.json();if(!r.ok)throw Error(d.error||'Torrent queue unavailable');box.replaceChildren();if(!d.items.length){box.textContent='No torrent jobs yet.';return}
for(const j of d.items){const row=document.createElement('div');row.className='result';safeText(row,'div','name',j.name||'Torrent job');const state=(j.status||'unknown')+' · '+(j.pct||0)+'%'+(j.speed?' · '+j.speed:'')+(j.error?' · '+j.error:'');safeText(row,'div','small',state);box.append(row)}}catch(e){box.textContent=e.message}}
$('#movieSearch').onclick=findMovies;$('#movieQuery').onkeydown=e=>{if(e.key==='Enter')findMovies()};$('#magnetAdd').onclick=addMagnet;
$('#subsearch').onclick=async()=>{const box=$('#subResults');box.textContent='Searching…';try{const d=await(await fetch('/api/subtitles?q='+encodeURIComponent($('#subq').value)+'&lang='+$('#lang').value)).json();box.replaceChildren();if(d.error){box.textContent=d.error;return}for(const x of d.results||[])box.append(card(x,'page'));if(!box.children.length)box.textContent='No subtitles found.'}catch(e){box.textContent=e.message}};
$('#add').onclick=async()=>{try{await api('/api/add',{method:'POST',body:JSON.stringify({url:$('#url').value.trim()})});$('#url').value='';$('#msg').textContent='Queued.';load()}catch(e){$('#msg').textContent=e.message;$('#msg').className='small error'}};
async function load(){if($('#appPanel').style.display==='none')return;try{const data=await(await api('/api/jobs')).json(),box=$('#jobs');box.replaceChildren();for(const j of data){const d=document.createElement('div');d.className='job';const n=document.createElement('div');n.className='name';n.textContent=j.name||'Download';const s=document.createElement('div');s.className='small'+(j.error?' error':'');s.textContent=j.status+' · '+(j.pct||0)+'%'+(j.error?' · '+j.error:'');const b=document.createElement('div');b.className='bar';const v=document.createElement('span');v.style.width=(j.pct||0)+'%';b.append(v);d.append(n,b,s);box.append(d)}}catch(e){}loadTorrentJobs();}
setInterval(load,2500);</script></body></html>"""

threading.Thread(target=worker,daemon=True).start()
