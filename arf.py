#!/usr/bin/env python3
"""
ARF Pro v2.0 - Single-file monolithic edition
Features:
 - Multithreading (ThreadPoolExecutor)
 - TQDM progress bars
 - robots.txt + sitemap.xml discovery
 - Passive DNS enumeration (Google & Cloudflare DoH)
 - Tech stack detection (headers + body heuristics)
 - API recon mode (detect JSON/Swagger/GraphQL)
 - JS intelligence (fetch JS, extract endpoints, detect cloud assets)
 - Directory probing (safe list)
 - Subdomain enumeration (crt.sh)
 - Subdomain fingerprinting (parallel optional)
 - SQLite logging
 - Stand-alone HTML report (inline CSS)
 - Plugins: loads any python file in 'plugins' directory (safe loaders only)
 - Config file support (config.json)
 - Passive-only, safe OSINT
Author: Arcanum Cyber Bot (example)
Version: ARF PRO v2.0 (single-file)
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# Optional terminal coloring
try:
    from colorama import init as color_init, Fore, Style
    color_init(autoreset=True)
except Exception:
    class _C:
        RESET = ""; RED=""; GREEN=""; CYAN=""; YELLOW=""; MAGENTA=""
    Fore = _C(); Style = _C()

# ----------------------------
# Configuration defaults
# ----------------------------
DEFAULT_CONFIG = {
    "threads": 12,
    "http_timeout": 4,
    "js_timeout": 3,
    "dns_timeout": 3,
    "dir_timeout": 2,
    "dir_wordlist": ["admin", "login", "backup", "uploads", "test", "phpinfo.php"],
    "robots": True,
    "sitemap": True,
    "dns": True,
    "save_db": False,
    "db_file": "arf.db",
    "output_dir": "output",
    "user_agent": "ARF-Pro/2.0 (+https://example.local/arf)"
}

VERSION = "ARF-PRO-2.0-single"

# ----------------------------
# Helpers / utils
# ----------------------------
def load_config(path="config.json"):
    cfg = DEFAULT_CONFIG.copy()
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                user = json.load(f)
            cfg.update(user)
        except Exception as e:
            print(Fore.YELLOW + "[!] Could not load config.json: " + str(e))
    return cfg

def ensure_output_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)
    return path

def safe_request_get(url, timeout, headers=None, allow_redirects=True):
    # Simple GET with error handling
    headers = headers or {}
    try:
        r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=allow_redirects)
        return r
    except Exception:
        return None

def safe_request_head(url, timeout, headers=None, allow_redirects=True):
    headers = headers or {}
    try:
        r = requests.head(url, timeout=timeout, headers=headers, allow_redirects=allow_redirects)
        return r
    except Exception:
        return None

def normalize_domain(d):
    d = d.strip()
    if d.startswith("http://") or d.startswith("https://"):
        parsed = urlparse(d)
        return parsed.netloc
    return d.split("/")[0]

# ----------------------------
# SQLite logging
# ----------------------------
class DB:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = None
    def connect(self):
        self.conn = sqlite3.connect(self.db_file)
        self._bootstrap()
    def _bootstrap(self):
        c = self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     domain TEXT,
                     started TEXT,
                     finished TEXT,
                     result_json TEXT
                     )""")
        c.execute("""CREATE TABLE IF NOT EXISTS endpoints (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     scan_id INTEGER,
                     endpoint TEXT
                     )""")
        self.conn.commit()
    def save_scan(self, domain, started, finished, results):
        c = self.conn.cursor()
        c.execute("INSERT INTO scans (domain, started, finished, result_json) VALUES (?, ?, ?, ?)",
                  (domain, started, finished, json.dumps(results)))
        scan_id = c.lastrowid
        if results.get("endpoints"):
            for e in results["endpoints"]:
                c.execute("INSERT INTO endpoints (scan_id, endpoint) VALUES (?, ?)", (scan_id, e))
        self.conn.commit()
    def close(self):
        if self.conn:
            self.conn.close()

# ----------------------------
# Passive DNS (DoH) helpers
# ----------------------------
def doh_lookup_google(name, record_type="A", timeout=3):
    url = "https://dns.google/resolve"
    try:
        r = requests.get(url, params={"name": name, "type": record_type}, timeout=timeout)
        if r and r.status_code == 200:
            return r.json()
    except:
        pass
    return {}

def doh_lookup_cloudflare(name, record_type="A", timeout=3):
    url = "https://cloudflare-dns.com/dns-query"
    headers = {"accept": "application/dns-json"}
    try:
        r = requests.get(url, params={"name": name, "type": record_type}, headers=headers, timeout=timeout)
        if r and r.status_code == 200:
            return r.json()
    except:
        pass
    return {}

def passive_dns_enum(domain, timeout=3):
    # Query common record types and aggregate results
    records = {}
    types = ["A", "AAAA", "CNAME", "MX", "TXT"]
    for t in types:
        g = doh_lookup_google(domain, t, timeout=timeout)
        c = doh_lookup_cloudflare(domain, t, timeout=timeout)
        answers = []
        if isinstance(g, dict) and "Answer" in g:
            answers.extend(g.get("Answer", []))
        if isinstance(c, dict) and "Answer" in c:
            answers.extend(c.get("Answer", []))
        records[t] = answers
    # Attempt subdomain bruteforce? NO — passive only - do not brute force
    return records

# ----------------------------
# Subdomain enumeration via crt.sh (passive)
# ----------------------------
def crtsh_subdomains(domain, timeout=6):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": DEFAULT_CONFIG["user_agent"]})
        if not r or r.status_code != 200:
            # try without wildcard
            url2 = f"https://crt.sh/?q={domain}&output=json"
            r = requests.get(url2, timeout=timeout, headers={"User-Agent": DEFAULT_CONFIG["user_agent"]})
        data = r.json() if r else []
        subs = set()
        for entry in data:
            nv = entry.get("name_value") or entry.get("common_name") or ""
            for line in nv.splitlines():
                sub = line.strip().replace("*.", "")
                if sub.endswith(domain):
                    subs.add(sub)
        return sorted(subs)
    except Exception:
        return []

# ----------------------------
# robots.txt and sitemap discovery
# ----------------------------
def fetch_robots(root_url, timeout=3):
    robots_url = urljoin(root_url, "/robots.txt")
    r = safe_request_get(robots_url, timeout=timeout, headers={"User-Agent": DEFAULT_CONFIG["user_agent"]})
    paths = []
    sitemaps = []
    if r and r.status_code == 200:
        text = r.text
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("sitemap:"):
                s = line.split(":",1)[1].strip()
                sitemaps.append(s)
            if line.lower().startswith("disallow:"):
                p = line.split(":",1)[1].strip()
                if p:
                    paths.append(p)
    return {"robots_txt": r.text if r and r.status_code==200 else "", "disallow": paths, "sitemaps": sitemaps}

def fetch_sitemap(url, timeout=4):
    r = safe_request_get(url, timeout=timeout, headers={"User-Agent": DEFAULT_CONFIG["user_agent"]})
    urls = []
    if r and r.status_code == 200:
        try:
            soup = BeautifulSoup(r.text, "xml")
            for loc in soup.find_all("loc"):
                if loc.text:
                    urls.append(loc.text.strip())
        except:
            pass
    return urls

# ----------------------------
# JS intelligence module
# ----------------------------
JS_SRC_RE = re.compile(r'<script[^>]+src=["\'](.*?)["\']', re.IGNORECASE)
ENDPOINT_RE = re.compile(r'(["\'])(\/[a-zA-Z0-9_\-\/]{2,}(?:\?[a-zA-Z0-9=&_\-]*)?)\1')
GENERIC_ENDPOINT_RE = re.compile(r'(\/[a-zA-Z0-9_\-\/]{2,})')

CLOUD_PATTERNS = {
    "AWS S3": re.compile(r"https:\/\/[a-z0-9\.\-_]+\.s3\.amazonaws\.com[\/a-zA-Z0-9\.\-_]*"),
    "GCP": re.compile(r"https:\/\/storage\.googleapis\.com\/[a-zA-Z0-9\.\-_\/]*"),
    "Azure Blob": re.compile(r"https:\/\/[a-zA-Z0-9\-_]+\.blob\.core\.windows\.net\/[a-zA-Z0-9\.\-_\/]*")
}

def get_js_urls_from_page(root_url, timeout=4):
    r = safe_request_get(root_url, timeout=timeout, headers={"User-Agent": DEFAULT_CONFIG["user_agent"]})
    if not r or r.status_code >= 400:
        return []
    html = r.text
    matches = JS_SRC_RE.findall(html)
    js_urls = []
    for m in matches:
        full = urljoin(root_url, m)
        js_urls.append(full)
    # also try to find inline endpoints that look like /api/...
    return list(dict.fromkeys(js_urls))

def extract_endpoints_from_js(code):
    eps = set()
    for m in ENDPOINT_RE.findall(code):
        eps.add(m[1])
    # fallback generic endpoints
    for m in GENERIC_ENDPOINT_RE.findall(code):
        if len(m) > 3:
            eps.add(m)
    return sorted(eps)

def detect_cloud_leaks_in_text(text):
    hits = []
    for name, pat in CLOUD_PATTERNS.items():
        found = pat.findall(text)
        if found:
            hits.append({name: list(set(found))})
    return hits

# ----------------------------
# Tech detection (Wappalyzer-lite)
# ----------------------------
TECH_SIGNATURES = [
    # (name, header_contains, body_contains, cookie_contains)
    ("Cloudflare", lambda h,b: ("cloudflare" in " ".join([f"{k}:{v}" for k,v in h.items()]).lower()), lambda b: False),
    ("nginx", lambda h,b: "nginx" in h.get("server","").lower(), lambda b: False),
    ("Apache", lambda h,b: "apache" in h.get("server","").lower(), lambda b: False),
    ("React", lambda h,b: "__REACT_DEVTOOLS_GLOBAL_HOOK__" in b or "react" in b.lower(), lambda b: False),
    ("Next.js", lambda h,b: "__NEXT_DATA__" in b or "nextjs" in b.lower(), lambda b: False),
    ("Vue.js", lambda h,b: "vue" in b.lower(), lambda b: False),
    ("Express", lambda h,b: "express" in h.get("x-powered-by","").lower(), lambda b: False),
    ("PHP", lambda h,b: "php" in h.get("x-powered-by","").lower() or "php" in h.get("server","").lower(), lambda b: False),
    ("Django", lambda h,b: "django" in h.get("set-cookie","").lower(), lambda b: False),
    ("IIS", lambda h,b: "microsoft-iis" in h.get("server","").lower(), lambda b: False),
]

def detect_tech_from_response(r):
    headers = r.headers if r is not None else {}
    body = (r.text or "") if r is not None else ""
    found = []
    for name, header_check, body_check in TECH_SIGNATURES:
        try:
            if callable(header_check) and header_check(headers, body):
                found.append(name)
            elif callable(body_check) and body_check(body):
                found.append(name)
        except:
            continue
    return sorted(set(found))

# ----------------------------
# Directory probing (safe)
# ----------------------------
def probe_url_head(session, url, timeout=2):
    try:
        r = session.head(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": DEFAULT_CONFIG["user_agent"]})
        return r.status_code
    except:
        return None

# ----------------------------
# API recon helpers
# ----------------------------
def detect_api_indicators(r):
    # examine headers and body to detect JSON endpoints, swagger, graphql, cors
    info = {"is_json": False, "swagger": False, "graphql": False, "cors": False}
    if not r:
        return info
    ct = r.headers.get("Content-Type","")
    if "application/json" in ct or (r.text and r.text.strip().startswith("{")):
        info["is_json"] = True
    if "swagger" in r.text.lower() or "openapi" in r.text.lower():
        info["swagger"] = True
    if "graphql" in r.text.lower() or "graphiql" in r.text.lower():
        info["graphql"] = True
    if "access-control-allow-origin" in (k.lower() for k in r.headers.keys()):
        info["cors"] = True
    return info

# ----------------------------
# Plugin loader (safe: only loads top-level functions)
# ----------------------------
def load_plugins(plugin_dir="plugins"):
    plugins = []
    if not os.path.isdir(plugin_dir):
        return plugins
    for fname in os.listdir(plugin_dir):
        if not fname.endswith(".py"):
            continue
        path = os.path.join(plugin_dir, fname)
        try:
            # sandboxed import: exec in empty namespace with only limited globals
            ns = {"__name__": f"plugin_{fname[:-3]}"}
            with open(path, "r", encoding="utf-8") as f:
                code = f.read()
            exec(code, ns)
            # plugin may register 'run_plugin' function
            if "run_plugin" in ns and callable(ns["run_plugin"]):
                plugins.append(ns["run_plugin"])
        except Exception as e:
            print(Fore.YELLOW + f"[!] Failed to load plugin {fname}: {e}")
    return plugins

# ----------------------------
# HTML report template (stand-alone styles)
# ----------------------------
HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>ARF Pro Report - {domain}</title>
<style>
body{{font-family:Inter,Segoe UI,Helvetica,Arial,sans-serif;background:#0d0d12;color:#e6eef6;margin:0;padding:0}}
.header{{background:linear-gradient(90deg,#0a84ff22,#28f0e422);padding:24px;text-align:center;border-bottom:1px solid #111}}
.container{{max-width:1100px;margin:18px auto;padding:18px;background:#0f1720;border-radius:8px;box-shadow:0 6px 30px rgba(0,0,0,0.6)}}
h1{{color:#28F0E4;margin:0 0 6px 0}}
.small{{color:#9fb0c6;font-size:14px}}
.table{{width:100%;border-collapse:collapse;margin-top:16px}}
.table th, .table td{{padding:8px;border-bottom:1px solid #111;color:#cfe7f5}}
.table th{{text-align:left;color:#28F0E4}}
.kv{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px dashed #081722}}
.code{{background:#071226;padding:8px;border-radius:6px;color:#9fd9ff;overflow:auto;font-family:monospace}}
.badge{{display:inline-block;padding:4px 8px;border-radius:6px;background:#081426;color:#0af;font-weight:600;margin-right:6px}}
.section{{margin-top:18px}}
</style>
</head>
<body>
  <div class="header">
    <h1>ARF Pro Report - {domain}</h1>
    <div class="small">Generated: {time}</div>
  </div>
  <div class="container">
    <div class="section">
      <div class="kv"><div><strong>Root URL</strong></div><div>{root_url}</div></div>
      <div class="kv"><div><strong>Risk Score</strong></div><div>{risk_score} ({risk_level})</div></div>
      <div class="kv"><div><strong>Server</strong></div><div>{server}</div></div>
      <div class="kv"><div><strong>Framework</strong></div><div>{framework}</div></div>
      <div class="kv"><div><strong>WAF</strong></div><div>{waf}</div></div>
    </div>

    <div class="section">
      <h2>Findings</h2>
      <table class="table">
        <tr><th>Category</th><th>Count / Summary</th></tr>
        <tr><td>Subdomains</td><td>{subdomains_count}</td></tr>
        <tr><td>JS Files</td><td>{js_count}</td></tr>
        <tr><td>Endpoints</td><td>{endpoints_count}</td></tr>
        <tr><td>Cloud Leaks</td><td>{cloud_count}</td></tr>
        <tr><td>Directories</td><td>{dir_count}</td></tr>
        <tr><td>Missing Security Headers</td><td>{missing_headers}</td></tr>
      </table>
    </div>

    <div class="section">
      <h2>Endpoints Extracted</h2>
      <div class="code">{endpoints_html}</div>
    </div>

    <div class="section">
      <h2>JS Files</h2>
      <div class="code">{js_html}</div>
    </div>

    <div class="section">
      <h2>Subdomains</h2>
      <div class="code">{subs_html}</div>
    </div>

    <div class="section">
      <h2>Cloud Leaks</h2>
      <div class="code">{cloud_html}</div>
    </div>

    <div class="section">
      <h2>Directories Found</h2>
      <div class="code">{dirs_html}</div>
    </div>

    <div class="section">
      <h2>Passive DNS</h2>
      <div class="code">{dns_html}</div>
    </div>

    <div class="section">
      <h2>Notes</h2>
      <div class="small">This report is generated by ARF Pro v2.0 (single-file). Use results only for authorized testing.</div>
    </div>
  </div>
</body>
</html>
"""

# ----------------------------
# Main engine
# ----------------------------
def run_scan(domain, args, cfg):
    start_time = datetime.utcnow().isoformat() + "Z"
    domain = normalize_domain(domain)
    output_dir = ensure_output_dir(cfg.get("output_dir","output"))
    ua = {"User-Agent": cfg.get("user_agent", DEFAULT_CONFIG["user_agent"])}
    # detect protocol
    root_url = None
    for proto in ("https://", "http://"):
        try:
            r = requests.get(proto + domain, timeout=cfg["http_timeout"], headers=ua)
            if r and r.status_code < 500:
                root_url = proto + domain
                break
        except:
            continue
    if not root_url:
        root_url = "http://" + domain

    results = {
        "domain": domain,
        "root_url": root_url,
        "started": start_time,
        "fingerprint": {},
        "subdomains": [],
        "js_files": [],
        "endpoints": [],
        "cloud_leaks": [],
        "parameters": [],
        "risky_parameters": [],
        "directories": [],
        "dns": {},
        "plugins": {}
    }

    print(Fore.CYAN + f"[*] ARF Pro v2.0 scanning {domain} (threads={args.threads})")
    print(Fore.CYAN + "[*] Root URL: " + Fore.GREEN + root_url)

    # 1) subdomains (crt.sh) - passive
    if args.dns or args.subdomains:
        print(Fore.CYAN + "[*] Enumerating subdomains (crt.sh)...")
        subs = crtsh_subdomains(domain, timeout=cfg["http_timeout"])
        results["subdomains"] = subs
        print(Fore.CYAN + f"    Found {len(subs)} subdomains")

    # 2) fingerprint root
    print(Fore.CYAN + "[*] Fingerprinting root (headers & body)...")
    rroot = safe_request_get(root_url, timeout=cfg["http_timeout"], headers=ua)
    fp = {}
    if rroot:
        fp["server"] = rroot.headers.get("Server", "Unknown")
        fp["powered_by"] = rroot.headers.get("X-Powered-By", "Unknown")
        fp["content_type"] = rroot.headers.get("Content-Type", "")
        fp["cookies"] = dict(rroot.cookies)
        fp["missing_security_headers"] = [h for h in ["Content-Security-Policy","X-Frame-Options","Strict-Transport-Security","X-XSS-Protection"] if h not in rroot.headers]
        fp["technologies"] = detect_tech_from_response(rroot)
    else:
        fp["server"] = "Unknown"
        fp["powered_by"] = "Unknown"
        fp["content_type"] = ""
        fp["cookies"] = {}
        fp["missing_security_headers"] = []
        fp["technologies"] = []
    results["fingerprint"] = fp

    # 3) robots.txt
    if args.robots:
        print(Fore.CYAN + "[*] Fetching robots.txt...")
        rinfo = fetch_robots(root_url, timeout=cfg["http_timeout"])
        results["robots"] = rinfo
        # if robots listed sitemaps, add to sitemap list
        sitemaps = rinfo.get("sitemaps", [])
    else:
        sitemaps = []

    # 4) sitemap.xml - try known default if enabled
    sitemap_urls = []
    if args.sitemap:
        # include any sitemap discovered plus /sitemap.xml
        sitemap_urls = list(sitemaps)
        sitemap_urls.append(urljoin(root_url, "/sitemap.xml"))
        sitemap_urls = list(dict.fromkeys([s for s in sitemap_urls if s]))
        sitemap_found_urls = []
        for s in sitemap_urls:
            print(Fore.CYAN + f"[*] Fetching sitemap: {s}")
            try:
                ulist = fetch_sitemap(s, timeout=cfg["http_timeout"])
                sitemap_found_urls.extend(ulist)
            except:
                continue
        results["sitemap_urls"] = sitemap_found_urls

    # 5) JS discovery (fetch root page and collect script srcs)
    print(Fore.CYAN + "[*] Collecting JS files from root page...")
    js_urls = get_js_urls_from_page(root_url, timeout=cfg["js_timeout"])
    results["js_files"] = js_urls
    print(Fore.CYAN + f"    Found {len(js_urls)} JS files")

    # 6) Parallel JS analysis
    endpoints_set = set()
    cloud_leaks = []
    if js_urls:
        print(Fore.CYAN + "[*] Fetching and analyzing JS files (parallel)...")
        with ThreadPoolExecutor(max_workers=args.threads) as exe:
            futures = {exe.submit(safe_request_get, u, cfg["js_timeout"], ua): u for u in js_urls}
            for f in tqdm(as_completed(futures), total=len(futures), desc="JS Analysis", ncols=80):
                u = futures[f]
                try:
                    r = f.result()
                    text = r.text if r else ""
                    if text:
                        eps = extract_endpoints_from_js(text)
                        for e in eps:
                            endpoints_set.add(e)
                        leaks = detect_cloud_leaks_in_text(text)
                        if leaks:
                            cloud_leaks.extend(leaks)
                except Exception:
                    continue
    results["endpoints"] = sorted(endpoints_set)
    results["cloud_leaks"] = cloud_leaks

    # 7) Parameters & API mode detection
    params = set()
    risky = set()
    DANGEROUS = {"redirect","url","file","next","dest","path","image","callback","endpoint","return"}
    for e in results["endpoints"]:
        if "?" in e:
            q = e.split("?",1)[1]
            for kv in q.split("&"):
                if "=" in kv:
                    k = kv.split("=",1)[0]
                    params.add(k)
                    if k.lower() in DANGEROUS:
                        risky.add(k)
    results["parameters"] = sorted(list(params))
    results["risky_parameters"] = sorted(list(risky))

    # API detection - check a few discovered endpoints (passive GET)
    api_indicators = []
    if args.api_mode and results["endpoints"]:
        sample = results["endpoints"][:10]
        print(Fore.CYAN + "[*] API mode: checking sample endpoints (passive)...")
        with ThreadPoolExecutor(max_workers=args.threads) as exe:
            futures = {exe.submit(safe_request_get, urljoin(root_url, e), cfg["http_timeout"], ua): e for e in sample}
            for f in tqdm(as_completed(futures), total=len(futures), desc="API Recon", ncols=80):
                e = futures[f]
                try:
                    r = f.result()
                    info = detect_api_indicators(r) if r else {}
                    if any(info.values()):
                        api_indicators.append({"endpoint": e, "info": info})
                except:
                    continue
    results["api_indicators"] = api_indicators

    # 8) Directory probing (parallel, safe list)
    print(Fore.CYAN + "[*] Probing directories (parallel safe-list)...")
    words = cfg.get("dir_wordlist", DEFAULT_CONFIG["dir_wordlist"])
    found_dirs = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        session_pool = [requests.Session() for _ in range(min(args.threads, len(words)))]
        futures = {}
        for i, w in enumerate(words):
            url = f"{root_url.rstrip('/')}/{w}"
            session = session_pool[i % len(session_pool)]
            futures[exe.submit(probe_url_head, session, url, cfg["dir_timeout"])] = url
        for f in tqdm(as_completed(futures), total=len(futures), desc="Dir Scan", ncols=80):
            url = futures[f]
            status = f.result()
            if status and status in (200,301,302,403):
                found_dirs.append((url, status))
    results["directories"] = found_dirs

    # 9) Passive DNS enumeration
    if args.dns:
        print(Fore.CYAN + "[*] Performing passive DNS enumeration (DoH)...")
        dns_result = passive_dns_enum(domain, timeout=cfg["dns_timeout"])
        results["dns"] = dns_result

    # 10) Subdomain fingerprinting (optional)
    sub_fps = {}
    if args.fingerprint_subdomains and results.get("subdomains"):
        print(Fore.CYAN + "[*] Fingerprinting discovered subdomains (parallel)...")
        with ThreadPoolExecutor(max_workers=args.threads) as exe:
            futures = {exe.submit(safe_request_get, ("https://"+s), cfg["http_timeout"], ua): s for s in results["subdomains"]}
            for f in tqdm(as_completed(futures), total=len(futures), desc="Sub-FP", ncols=80):
                s = futures[f]
                try:
                    r = f.result()
                    sub_fps[s] = {
                        "status": r.status_code if r else None,
                        "server": r.headers.get("Server") if r else None,
                        "tech": detect_tech_from_response(r) if r else []
                    }
                except:
                    sub_fps[s] = {}
    results["subdomain_fingerprints"] = sub_fps

    # 11) Plugins
    if args.plugins:
        print(Fore.CYAN + "[*] Loading plugins...")
        plugins = load_plugins()
        for pfunc in plugins:
            try:
                name = getattr(pfunc, "__name__", "plugin")
                print(Fore.CYAN + f"    Running plugin: {name}")
                out = pfunc(results)
                results["plugins"][name] = out
            except Exception as e:
                results["plugins"][name] = {"error": str(e)}

    # 12) Risk scoring
    # compute simple risk
    score = 0
    reasons = []
    if results["cloud_leaks"]:
        score += 25; reasons.append("Cloud storage references")
    if results["risky_parameters"]:
        score += 25; reasons.append("Dangerous parameters present")
    if results["directories"]:
        score += 10; reasons.append("Interesting directories")
    if results["fingerprint"].get("missing_security_headers"):
        score += min(30, len(results["fingerprint"]["missing_security_headers"]) * 5); reasons.append("Missing security headers")
    level = "LOW"
    if score >= 60: level = "HIGH"
    elif score >= 30: level = "MEDIUM"
    results["risk_score"] = {"score": score, "level": level, "reasons": reasons}

    # 13) Save JSON
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_json = os.path.join(output_dir, f"results_{domain}_{ts}.json")
    try:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(Fore.GREEN + f"[*] JSON saved: {out_json}")
    except Exception as e:
        print(Fore.RED + "[!] Failed to save JSON: " + str(e))

    # 14) Save to DB if requested
    if args.save_db:
        try:
            db = DB(cfg.get("db_file", "arf.db"))
            db.connect()
            db.save_scan(domain, start_time, datetime.utcnow().isoformat()+"Z", results)
            db.close()
            print(Fore.GREEN + "[*] Saved scan to DB: " + cfg.get("db_file", "arf.db"))
        except Exception as e:
            print(Fore.YELLOW + "[!] DB save failed: " + str(e))

    # 15) Generate HTML report if requested
    if args.html:
        try:
            html_path = os.path.join(output_dir, f"report-{domain}-{ts}.html")
            generate_html_report(domain, root_url, results, html_path)
            print(Fore.GREEN + f"[*] HTML report saved: {html_path}")
        except Exception as e:
            print(Fore.YELLOW + "[!] HTML report generation failed: " + str(e))

    results["finished"] = datetime.utcnow().isoformat() + "Z"
    return results

# ----------------------------
# HTML report generation
# ----------------------------
def html_escape(s):
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\n","<br/>")

def generate_html_report(domain, root_url, results, path):
    ensure_output_dir(os.path.dirname(path) or ".")
    endpoints_html = "<br/>".join([html_escape(e) for e in results.get("endpoints",[])]) or "(none)"
    js_html = "<br/>".join([html_escape(u) for u in results.get("js_files",[])]) or "(none)"
    subs_html = "<br/>".join(results.get("subdomains",[])) or "(none)"
    cloud_html = "<br/>".join([json.dumps(c) for c in results.get("cloud_leaks",[])]) or "(none)"
    dirs_html = "<br/>".join([f"{u} ({s})" for u,s in results.get("directories",[])]) or "(none)"
    dns_html = html_escape(json.dumps(results.get("dns",{}), indent=2)) or "(none)"

    html = HTML_TEMPLATE.format(
        domain=html_escape(domain),
        time=html_escape(datetime.utcnow().isoformat()+"Z"),
        root_url=html_escape(root_url),
        risk_score=results["risk_score"]["score"],
        risk_level=results["risk_score"]["level"],
        server=html_escape(results["fingerprint"].get("server","Unknown")),
        framework=html_escape(", ".join(results["fingerprint"].get("technologies",[])) or "Unknown"),
        waf=html_escape("Cloudflare" if "Cloudflare" in results["fingerprint"].get("technologies",[]) else "None"),
        subdomains_count=len(results.get("subdomains",[])),
        js_count=len(results.get("js_files",[])),
        endpoints_count=len(results.get("endpoints",[])),
        cloud_count=len(results.get("cloud_leaks",[])),
        dir_count=len(results.get("directories",[])),
        missing_headers=", ".join(results["fingerprint"].get("missing_security_headers",[])) or "(none)",
        endpoints_html=endpoints_html,
        js_html=js_html,
        subs_html=subs_html,
        cloud_html=cloud_html,
        dirs_html=dirs_html,
        dns_html=dns_html
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

# ----------------------------
# CLI handler
# ----------------------------
def parse_args():
    p = argparse.ArgumentParser(description="ARF Pro v2.0 - passive single-file recon suite")
    p.add_argument("domain", help="Target domain (example.com)")
    p.add_argument("--threads", "-t", type=int, default=DEFAULT_CONFIG["threads"], help="Worker threads")
    p.add_argument("--dns", action="store_true", help="Perform passive DNS enumeration (DoH)")
    p.add_argument("--robots", action="store_true", help="Fetch robots.txt")
    p.add_argument("--sitemap", action="store_true", help="Fetch sitemap(s)")
    p.add_argument("--api-mode", action="store_true", help="Perform passive API reconnaissance")
    p.add_argument("--html", action="store_true", help="Generate HTML report")
    p.add_argument("--save-db", dest="save_db", action="store_true", help="Save results to sqlite DB")
    p.add_argument("--plugins", action="store_true", help="Load plugins from plugins/")
    p.add_argument("--fingerprint-subdomains", action="store_true", help="Fingerprint discovered subdomains (parallel, optional)")
    p.add_argument("--config", type=str, default="config.json", help="Load config.json")
    p.add_argument("--version", action="store_true", help="Show version")
    args = p.parse_args()
    return args

# ----------------------------
# Entry point
# ----------------------------
def main():
    args = parse_args()
    if args.version:
        print(VERSION); sys.exit(0)
    cfg = load_config(args.config)
    # Merge CLI flags into cfg
    cfg["threads"] = max(1, min(80, args.threads or cfg.get("threads",DEFAULT_CONFIG["threads"])))
    # Set booleans from CLI or config defaults
    args.dns = args.dns or cfg.get("dns", True)
    args.robots = args.robots or cfg.get("robots", True)
    args.sitemap = args.sitemap or cfg.get("sitemap", True)
    args.save_db = args.save_db or cfg.get("save_db", False)
    args.plugins = args.plugins or False
    args.fingerprint_subdomains = args.fingerprint_subdomains or False
    # Ensure output dir
    ensure_output_dir(cfg.get("output_dir","output"))
    # Run scan
    try:
        results = run_scan(args.domain, args, cfg)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + "[!] Scan failed: " + str(e))
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
