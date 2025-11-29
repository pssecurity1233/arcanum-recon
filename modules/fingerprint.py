# modules/fingerprint.py
import requests

def detect_framework(body):
    b = body.lower()
    if "__next_data__" in b or "nextjs" in b:
        return "Next.js"
    if "react" in b and "react-dom" in b:
        return "React"
    if "angular" in b:
        return "Angular"
    if "vue" in b:
        return "Vue.js"
    if "svelte" in b:
        return "Svelte"
    return "Unknown"

def detect_waf(headers):
    header_string = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower()
    waf_signatures = {
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "incapsula": "Imperva Incapsula",
        "sucuri": "Sucuri",
        "barracuda": "Barracuda"
    }
    for key, name in waf_signatures.items():
        if key in header_string:
            return name
    return "None Detected"

def fingerprint(url):
    try:
        r = requests.get(url, timeout=8)
        body = r.text or ""
        headers = r.headers or {}
        missing = []
        for h in ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-XSS-Protection"]:
            if h not in headers:
                missing.append(h)
        return {
            "url": url,
            "server": headers.get("Server", "Unknown"),
            "powered_by": headers.get("X-Powered-By", "Unknown"),
            "framework": detect_framework(body),
            "waf": detect_waf(headers),
            "cookies": dict(r.cookies),
            "content_type": headers.get("Content-Type", "Unknown"),
            "missing_security_headers": missing
        }
    except Exception:
        return {}
