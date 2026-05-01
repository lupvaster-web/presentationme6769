import os
import sys
import json
import time
import subprocess
import urllib.parse
import requests
import threading
import re
import urllib3
import socket
import webbrowser
from flask import Flask, Response, render_template_string, jsonify
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()

IS_WINDOWS = sys.platform == "win32"
IS_ANDROID = os.path.exists("/data/data/com.termux")

if IS_WINDOWS:
    BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
    XRAY_PATH    = os.path.join(BASE_DIR, "xray.exe")
    RESULTS_FILE = os.path.join(BASE_DIR, "results.txt")
else:
    HOME         = os.path.expanduser("~")
    XRAY_PATH    = os.path.join(HOME, "xray_folder", "xray")
    RESULTS_FILE = os.path.join(HOME, "results.txt")
    BASE_DIR     = HOME

TIMEOUT         = 10
MAX_THREADS     = 5 if IS_WINDOWS else 3
START_PORT      = 10800
XRAY_START_WAIT = 4 if IS_WINDOWS else 5

GITHUB_FILES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt",
]

TEST_URLS = ["https://t.me", "https://telegram.org", "https://www.google.com"]

RUS_SNI_WHITELIST = [
    "yandex.ru", "api-maps.yandex.ru", "travel.yandex.ru",
    "vk.com", "eh.vk.com", "www.vk.com", "m.vk.ru",
    "sun6-22.userapi.com", "sun6-21.userapi.com",
    "api.vk.com", "stats.vk-portal.net", "web.max.ru",
    "ok.ru", "mail.ru", "max.ru", "gosuslugi.ru",
    "tinkoff.ru", "tbank.ru", "rbc.ru", "ads.x5.ru",
    "ozon.ru", "avito.ru", "01.img.avito.st",
    "sber.ru", "vtb.ru", "nalog.ru", "mos.ru", "mvd.ru", "2gis.ru",
]

state = {
    "running": False,
    "events":  [],
    "results": [],
    "total":   0,
    "checked": 0,
    "found":   0,
}
state_lock = threading.Lock()

def push_event(data):
    with state_lock:
        state["events"].append(json.dumps(data, ensure_ascii=False))

def extract_ping(key):
    m = re.search(r'%5B(\d+)ms', key, re.IGNORECASE) or re.search(r'\[(\d+)ms', key)
    return int(m.group(1)) if m else 9999

def parse_vless(link):
    link = link.strip()
    if not link.startswith("vless://"): return None
    try:
        p = urllib.parse.urlparse(link)
        q = urllib.parse.parse_qs(p.query)
        host, port, uuid = p.hostname, p.port, p.username
        if not all([host, port, uuid]): return None
        security = q.get("security", ["none"])[0]
        network  = q.get("type",     ["tcp"])[0]
        sni      = q.get("sni",      [""])[0].lower()
        flow     = q.get("flow",     [""])[0]
        if not any(sni == w or sni.endswith("." + w) for w in RUS_SNI_WHITELIST):
            return None
        ss = {"network": network, "security": security}
        if security == "reality":
            ss["realitySettings"] = {
                "publicKey": q.get("pbk",[""])[0], "fingerprint": q.get("fp",["chrome"])[0],
                "serverName": sni, "shortId": q.get("sid",[""])[0], "spiderX": q.get("spx",["/"])[0],
            }
        elif security == "tls":
            ss["tlsSettings"] = {"serverName": sni, "fingerprint": q.get("fp",["chrome"])[0], "allowInsecure": False}
        if network == "ws":
            ss["wsSettings"] = {"path": urllib.parse.unquote(q.get("path",["/"])[0]), "headers": {"Host": q.get("host",[sni])[0]}}
        elif network == "xhttp":
            ss["xhttpSettings"] = {"path": urllib.parse.unquote(q.get("path",["/"])[0]), "mode": q.get("mode",["auto"])[0]}
        elif network == "grpc":
            ss["grpcSettings"] = {"serviceName": q.get("serviceName",[""])[0]}
        return {"protocol":"vless","settings":{"vnext":[{"address":host,"port":int(port),"users":[{"id":uuid,"encryption":"none","flow":flow}]}]},"streamSettings":ss}, sni
    except: return None

def wait_port(port, timeout=5):
    t0 = time.time()
    while time.time()-t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5): return True
        except: time.sleep(0.3)
    return False

def ping_url(proxies, url):
    try:
        t0 = time.time()
        r = requests.get(url, proxies=proxies, timeout=(5,TIMEOUT), allow_redirects=True, verify=False)
        if r.status_code in (200,301,302,403): return int((time.time()-t0)*1000)
    except: pass
    return None

def fetch_keys():
    push_event({"type":"log","msg":"Загружаю ключи с GitHub..."})
    keys = []
    for url in GITHUB_FILES:
        fname = url.split("/")[-1]
        try:
            r = requests.get(url, timeout=20)
            lines = [l.strip() for l in r.text.splitlines() if l.strip().startswith("vless://")]
            keys.extend(lines)
            push_event({"type":"log","msg":f"{fname}: {len(lines)} ключей"})
        except Exception as e:
            push_event({"type":"log","msg":f"{fname}: ошибка"})
    return keys

def check_key(key, idx):
    data = parse_vless(key)
    if not data: return None
    outbound, sni = data
    port = START_PORT + idx
    cfg_path = os.path.join(BASE_DIR, f"config_{port}.json")
    cfg = {
        "log":{"loglevel":"none"},
        "inbounds":[{"port":port,"listen":"127.0.0.1","protocol":"socks","settings":{"auth":"noauth","udp":True}}],
        "outbounds":[outbound]
    }
    proc = None
    try:
        with open(cfg_path,"w",encoding="utf-8") as f: json.dump(cfg,f)
        proc = subprocess.Popen([XRAY_PATH,"-c",cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_port(port, XRAY_START_WAIT): return None
        proxies = {"http":f"socks5h://127.0.0.1:{port}","https":f"socks5h://127.0.0.1:{port}"}
        for url in TEST_URLS:
            p = ping_url(proxies, url)
            if p: return {"key":key,"sni":sni,"ping":p,"declared":extract_ping(key)}
    except: pass
    finally:
        if proc:
            try: proc.terminate(); proc.wait(timeout=3)
            except:
                try: proc.kill()
                except: pass
        if os.path.exists(cfg_path):
            try: os.remove(cfg_path)
            except: pass
    return None

def run_checker():
    with state_lock:
        state.update({"running":True,"results":[],"events":[],"total":0,"checked":0,"found":0})
    push_event({"type":"start"})
    for f in os.listdir(BASE_DIR):
        if f.startswith("config_") and f.endswith(".json"):
            try: os.remove(os.path.join(BASE_DIR,f))
            except: pass
    keys = fetch_keys()
    if not keys:
        push_event({"type":"log","msg":"Нет ключей"})
        push_event({"type":"done","found":0,"total":0})
        with state_lock: state["running"] = False
        return
    filtered = sorted([(k,extract_ping(k)) for k in keys if parse_vless(k)], key=lambda x:x[1])
    keys_only = [k for k,_ in filtered]
    with state_lock: state["total"] = len(keys_only)
    push_event({"type":"log","msg":f"Всего загружено: {len(keys)}, с RU SNI: {len(keys_only)}"})
    push_event({"type":"total","total":len(keys_only)})
    for bs in range(0, len(keys_only), MAX_THREADS):
        if not state["running"]: break
        batch = keys_only[bs:bs+MAX_THREADS]
        with ThreadPoolExecutor(max_workers=len(batch)) as ex:
            futures = {ex.submit(check_key,k,i):k for i,k in enumerate(batch)}
            for future in as_completed(futures):
                res = future.result()
                with state_lock:
                    state["checked"] += 1
                    ch, tot = state["checked"], state["total"]
                if res:
                    with state_lock:
                        state["found"] += 1
                        state["results"].append(res)
                    push_event({"type":"key_found","key":res["key"],"sni":res["sni"],"ping":res["ping"],"checked":ch,"total":tot})
                else:
                    push_event({"type":"progress","checked":ch,"total":tot})
    results = sorted(state["results"], key=lambda x:x["ping"])
    with open(RESULTS_FILE,"w",encoding="utf-8") as f:
        f.write(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Рабочих: {len(results)}\n\n")
        for r in results:
            f.write(f"# {r['ping']}мс | {r['sni']}\n{r['key']}\n\n")
    push_event({"type":"done","found":len(results),"total":state["total"]})
    with state_lock: state["running"] = False

app = Flask(__name__)

HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>VLESS</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:       #0c0c0e;
  --s1:       #111114;
  --s2:       #18181d;
  --border:   #222228;
  --border2:  #2a2a32;
  --text:     #e8e8f0;
  --muted:    #555560;
  --muted2:   #383842;
  --accent:   #5b8dee;
  --green:    #3ecf8e;
  --red:      #e05c5c;
  --yellow:   #e0a535;
  --radius:   12px;
}

body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Inter', sans-serif;
  font-size: 14px;
  min-height: 100vh;
  padding: 0;
  -webkit-font-smoothing: antialiased;
}

/* ШАПКА */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  background: rgba(12,12,14,.92);
  backdrop-filter: blur(12px);
  z-index: 100;
}
.topbar-left { display: flex; align-items: center; gap: 10px; }
.logo {
  width: 28px; height: 28px;
  background: var(--accent);
  border-radius: 7px;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px;
}
.topbar h1 {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  letter-spacing: -.3px;
}
.topbar-right { display: flex; align-items: center; gap: 8px; }
.badge-platform {
  font-size: 10px;
  font-family: 'JetBrains Mono', monospace;
  color: var(--muted);
  background: var(--s2);
  border: 1px solid var(--border);
  padding: 3px 8px;
  border-radius: 99px;
  letter-spacing: .5px;
}

/* КОНТЕНТ */
.content { padding: 20px; max-width: 680px; margin: 0 auto; }

/* КНОПКА */
.btn-main {
  width: 100%;
  height: 52px;
  border: none;
  border-radius: var(--radius);
  background: var(--accent);
  color: #fff;
  font-family: 'Inter', sans-serif;
  font-size: 14px;
  font-weight: 600;
  letter-spacing: .2px;
  cursor: pointer;
  transition: background .15s, transform .1s, opacity .15s;
  display: flex; align-items: center; justify-content: center; gap: 8px;
  margin-bottom: 16px;
}
.btn-main:active { transform: scale(.99); }
.btn-main:disabled { opacity: .4; cursor: not-allowed; }
.btn-main.stop { background: var(--s2); border: 1px solid var(--border2); color: var(--red); }
.btn-main .ico { font-size: 16px; }

/* СТАТЫ */
.stats-row {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 8px;
  margin-bottom: 12px;
}
.stat {
  background: var(--s1);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 12px;
  text-align: center;
}
.stat .v {
  font-family: 'JetBrains Mono', monospace;
  font-size: 22px;
  font-weight: 500;
  color: var(--text);
  line-height: 1;
  margin-bottom: 5px;
}
.stat .v.green { color: var(--green); }
.stat .l { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }

/* ПРОГРЕСС */
.progress-wrap { margin-bottom: 12px; display: none; }
.progress-wrap.on { display: block; }
.progress-bg { height: 2px; background: var(--border); border-radius: 99px; overflow: hidden; }
.progress-fill {
  height: 100%; width: 0%;
  background: var(--accent);
  border-radius: 99px;
  transition: width .3s ease;
}
.progress-label {
  display: flex; justify-content: space-between;
  font-size: 11px; color: var(--muted); margin-top: 6px;
  font-family: 'JetBrains Mono', monospace;
}

/* ЛОГ */
.log-wrap {
  background: var(--s1);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
  margin-bottom: 12px;
  display: none;
}
.log-wrap.on { display: block; }
.log-inner {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--muted);
  max-height: 80px;
  overflow-y: auto;
  line-height: 1.9;
}
.log-inner div { border-bottom: none; }
.log-inner div::before { content: '> '; color: var(--muted2); }

/* ФИЛЬТРЫ */
.filters {
  display: none;
  margin-bottom: 12px;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
}
.filters.on { display: flex; }
.filter-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-right: 4px; }

.filter-btn {
  background: var(--s1);
  border: 1px solid var(--border);
  color: var(--muted);
  border-radius: 8px;
  padding: 5px 12px;
  font-family: 'Inter', sans-serif;
  font-size: 12px;
  cursor: pointer;
  transition: all .15s;
  white-space: nowrap;
}
.filter-btn.active {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
.filter-btn:active { transform: scale(.97); }

.sort-select {
  background: var(--s1);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 8px;
  padding: 5px 10px;
  font-family: 'Inter', sans-serif;
  font-size: 12px;
  cursor: pointer;
  outline: none;
  margin-left: auto;
}

/* ЗАГОЛОВОК СЕКЦИИ */
.section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
  display: none;
}
.section-head.on { display: flex; }
.section-title { font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 1.5px; }
.count-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--green);
  background: rgba(62,207,142,.1);
  border: 1px solid rgba(62,207,142,.2);
  padding: 2px 8px;
  border-radius: 99px;
}

.btn-copy-all {
  background: transparent;
  border: 1px solid var(--border2);
  color: var(--muted);
  border-radius: 8px;
  padding: 5px 12px;
  font-family: 'Inter', sans-serif;
  font-size: 12px;
  cursor: pointer;
  transition: all .15s;
}
.btn-copy-all:hover { border-color: var(--accent); color: var(--accent); }
.btn-copy-all:active { transform: scale(.97); }

/* СПИСОК КЛЮЧЕЙ */
#keys-list { display: flex; flex-direction: column; gap: 6px; }

.kcard {
  background: var(--s1);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
  cursor: pointer;
  transition: border-color .15s, background .15s;
  animation: fadeIn .25s ease both;
  position: relative;
}
.kcard:active { background: var(--s2); }
.kcard.copied { border-color: var(--green); }
@keyframes fadeIn { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:translateY(0); } }

.kcard-top {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 8px;
  flex-wrap: wrap;
}
.tag {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  padding: 2px 7px;
  border-radius: 5px;
  font-weight: 500;
  letter-spacing: .3px;
}
.tag-ping { background: rgba(91,141,238,.12); color: var(--accent); }
.tag-ping.fast { background: rgba(62,207,142,.12); color: var(--green); }
.tag-ping.slow { background: rgba(224,165,53,.1); color: var(--yellow); }
.tag-sni { background: var(--s2); color: var(--muted); border: 1px solid var(--border2); }

.kcard-key {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: var(--muted2);
  word-break: break-all;
  line-height: 1.6;
}
.kcard-hint {
  font-size: 10px;
  color: var(--muted2);
  margin-top: 6px;
  transition: color .2s;
}
.kcard.copied .kcard-hint { color: var(--green); }

/* ИТОГ */
.done-block {
  display: none;
  background: var(--s1);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  text-align: center;
  margin-top: 16px;
}
.done-block.on { display: block; }
.done-block.ok { border-color: rgba(62,207,142,.3); }
.done-block.bad { border-color: rgba(224,92,92,.2); }
.done-title { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
.done-block.ok .done-title { color: var(--green); }
.done-block.bad .done-title { color: var(--red); }
.done-sub { font-size: 11px; color: var(--muted); font-family: 'JetBrains Mono', monospace; }

/* Скроллбар */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 99px; }
</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-left">
    <div class="logo">🛡</div>
    <h1>VLESS Checker</h1>
  </div>
  <div class="topbar-right">
    <span class="badge-platform" id="platform-badge">—</span>
  </div>
</div>

<div class="content">

  <button class="btn-main" id="btn-main" onclick="toggle()">
    <span class="ico">▶</span>
    <span id="btn-txt">Начать проверку</span>
  </button>

  <div class="stats-row">
    <div class="stat"><div class="v" id="s-total">—</div><div class="l">ключей</div></div>
    <div class="stat"><div class="v" id="s-checked">—</div><div class="l">проверено</div></div>
    <div class="stat"><div class="v green" id="s-found">—</div><div class="l">рабочих</div></div>
  </div>

  <div class="progress-wrap" id="pw">
    <div class="progress-bg"><div class="progress-fill" id="pf"></div></div>
    <div class="progress-label">
      <span id="p-pct">0%</span>
      <span id="p-eta"></span>
    </div>
  </div>

  <div class="log-wrap" id="lw">
    <div class="log-inner" id="log"></div>
  </div>

  <!-- Фильтры и сортировка -->
  <div class="filters" id="filters">
    <span class="filter-label">SNI</span>
    <button class="filter-btn active" onclick="setFilter('all',this)">Все</button>
    <button class="filter-btn" onclick="setFilter('vk',this)">VK</button>
    <button class="filter-btn" onclick="setFilter('yandex',this)">Яндекс</button>
    <button class="filter-btn" onclick="setFilter('x5',this)">X5</button>
    <button class="filter-btn" onclick="setFilter('other',this)">Другие</button>
    <select class="sort-select" id="sort-sel" onchange="applySort()">
      <option value="ping">↑ Пинг</option>
      <option value="ping-desc">↓ Пинг</option>
      <option value="sni">A–Z SNI</option>
    </select>
  </div>

  <div class="section-head" id="sec-head">
    <span class="section-title">Рабочие ключи</span>
    <div style="display:flex;gap:8px;align-items:center">
      <span class="count-badge" id="count-badge">0</span>
      <button class="btn-copy-all" onclick="copyAll()">Копировать все</button>
    </div>
  </div>

  <div id="keys-list"></div>

  <div class="done-block" id="done">
    <div class="done-title" id="done-title"></div>
    <div class="done-sub" id="done-sub"></div>
  </div>

</div>

<script>
// Определяем платформу
const ua = navigator.userAgent;
document.getElementById('platform-badge').textContent =
  /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : 'Desktop';

let es = null, running = false;
let allResults = []; // {key, sni, ping}
let filterMode = 'all';
let startTime = null;
let total = 0, checked = 0, found = 0;

function toggle() { running ? doStop() : doStart(); }

function doStart() {
  running = true; allResults = []; total = checked = found = 0;
  startTime = Date.now();
  const btn = document.getElementById('btn-main');
  btn.classList.add('stop');
  btn.querySelector('.ico').textContent = '■';
  document.getElementById('btn-txt').textContent = 'Остановить';
  document.getElementById('keys-list').innerHTML = '';
  document.getElementById('log').innerHTML = '';
  document.getElementById('done').className = 'done-block';
  document.getElementById('sec-head').classList.remove('on');
  document.getElementById('filters').classList.remove('on');
  document.getElementById('pw').classList.add('on');
  document.getElementById('lw').classList.add('on');
  updStats();
  fetch('/start',{method:'POST'}).then(()=>{
    if(es) es.close();
    es = new EventSource('/stream');
    es.onmessage = e => handle(JSON.parse(e.data));
  });
}

function doStop() {
  fetch('/stop',{method:'POST'});
  finishUI();
}

function finishUI() {
  running = false;
  const btn = document.getElementById('btn-main');
  btn.classList.remove('stop');
  btn.querySelector('.ico').textContent = '▶';
  document.getElementById('btn-txt').textContent = 'Начать проверку';
  if(es){es.close();es=null;}
}

function handle(d) {
  if(d.type==='log') addLog(d.msg);
  else if(d.type==='total') { total=d.total; updStats(); }
  else if(d.type==='progress') { checked=d.checked; total=d.total; updStats(); }
  else if(d.type==='key_found') {
    checked=d.checked; total=d.total; found++;
    allResults.push({key:d.key, sni:d.sni, ping:d.ping});
    updStats();
    renderKeys();
  } else if(d.type==='done') {
    finishUI();
    showDone(d.found, d.total);
  }
}

function updStats() {
  const pct = total>0 ? Math.round(checked/total*100) : 0;
  document.getElementById('pf').style.width = pct+'%';
  document.getElementById('p-pct').textContent = pct+'%';
  document.getElementById('s-total').textContent   = total||'—';
  document.getElementById('s-checked').textContent = checked||'—';
  document.getElementById('s-found').textContent   = found||'—';
  // ETA
  if(checked>5 && startTime && total>0) {
    const elapsed = (Date.now()-startTime)/1000;
    const rate = checked/elapsed;
    const left = Math.round((total-checked)/rate);
    document.getElementById('p-eta').textContent = left>0 ? `~${left}с` : '';
  }
}

function addLog(msg) {
  const log = document.getElementById('log');
  const d = document.createElement('div');
  d.textContent = msg;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
}

// Фильтрация
function setFilter(mode, el) {
  filterMode = mode;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  renderKeys();
}

function getFiltered() {
  let list = [...allResults];
  if(filterMode==='vk')     list = list.filter(r=>r.sni.includes('vk'));
  else if(filterMode==='yandex') list = list.filter(r=>r.sni.includes('yandex'));
  else if(filterMode==='x5') list = list.filter(r=>r.sni.includes('x5'));
  else if(filterMode==='other') list = list.filter(r=>!r.sni.includes('vk')&&!r.sni.includes('yandex')&&!r.sni.includes('x5'));
  return list;
}

function applySort() { renderKeys(); }

function renderKeys() {
  const sortVal = document.getElementById('sort-sel').value;
  let list = getFiltered();
  if(sortVal==='ping')      list.sort((a,b)=>a.ping-b.ping);
  else if(sortVal==='ping-desc') list.sort((a,b)=>b.ping-a.ping);
  else if(sortVal==='sni')  list.sort((a,b)=>a.sni.localeCompare(b.sni));

  const container = document.getElementById('keys-list');
  container.innerHTML = '';

  if(list.length>0) {
    document.getElementById('sec-head').classList.add('on');
    document.getElementById('filters').classList.add('on');
    document.getElementById('count-badge').textContent = list.length;
  }

  list.forEach(r => {
    const card = document.createElement('div');
    card.className = 'kcard';
    const pingClass = r.ping<500 ? 'fast' : r.ping>1500 ? 'slow' : '';
    card.innerHTML = `
      <div class="kcard-top">
        <span class="tag tag-ping ${pingClass}">${r.ping}мс</span>
        <span class="tag tag-sni">${r.sni}</span>
      </div>
      <div class="kcard-key">${r.key.substring(0,110)}…</div>
      <div class="kcard-hint">нажми чтобы скопировать</div>`;
    card.onclick = () => {
      navigator.clipboard.writeText(r.key).then(()=>{
        card.classList.add('copied');
        card.querySelector('.kcard-hint').textContent = '✓ скопировано';
        setTimeout(()=>{
          card.classList.remove('copied');
          card.querySelector('.kcard-hint').textContent = 'нажми чтобы скопировать';
        }, 1800);
      });
    };
    container.appendChild(card);
  });
}

function copyAll() {
  const list = getFiltered();
  navigator.clipboard.writeText(list.map(r=>r.key).join('\n')).then(()=>{
    const btn = document.querySelector('.btn-copy-all');
    btn.textContent = '✓ Скопировано';
    setTimeout(()=>btn.textContent='Копировать все', 2000);
  });
}

function showDone(f, t) {
  const d = document.getElementById('done');
  d.className = 'done-block on ' + (f>0?'ok':'bad');
  document.getElementById('done-title').textContent = f>0 ? `Найдено ${f} рабочих ключей` : 'Рабочих ключей не найдено';
  document.getElementById('done-sub').textContent = `проверено ${t} · сохранено в results.txt`;
}
</script>
</body>
</html>"""

@app.route("/")
def index(): return render_template_string(HTML)

@app.route("/start", methods=["POST"])
def start():
    if state["running"]: return jsonify({"status":"already running"})
    threading.Thread(target=run_checker, daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/stop", methods=["POST"])
def stop():
    with state_lock: state["running"] = False
    return jsonify({"status":"stopped"})

@app.route("/stream")
def stream():
    def gen():
        sent = 0
        while True:
            with state_lock:
                new  = state["events"][sent:]
                sent = len(state["events"])
                r    = state["running"]
            for ev in new: yield f"data: {ev}\n\n"
            if not r and not new: break
            time.sleep(0.25)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

if __name__ == "__main__":
    plat = "Windows" if IS_WINDOWS else ("Android" if IS_ANDROID else "Linux")
    print(f"\n  VLESS Checker  |  {plat}")
    print(f"  xray : {XRAY_PATH}")
    if not os.path.exists(XRAY_PATH):
        print("  ⚠  xray не найден!")
    print("  → http://127.0.0.1:5000\n")
    if IS_WINDOWS:
        threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
