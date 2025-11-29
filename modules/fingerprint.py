import requests

def detect_framework(body):
    b = body.lower()
    if "react" in b: return "React"
    if "__next_data__" in b: return "Next.js"
    if "angular" in b: return "Angular"
    if "vue" in b: return "Vue.js"
    return "Unknown"

def detect_waf(headers):
    h = " ".join([f"{k}:{v}".lower() for k,v in headers.items()])
    if "cloudflare" in h: return "Cloudflare"
    if "akamai" in h: return "Akamai"
    if "incapsula" in h: return "Imperva Incapsula"
    return "None Detected"

def fingerprint(url):
    try:
        r = requests.get(url, timeout=3)
        body = r.text
        headers = r.headers
        
        missing = []
        for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]:
            if h not in headers:
                missing.append(h)

        return {
            "server": headers.get("Server", "Unknown"),
            "powered_by": headers.get("X-Powered-By", "Unknown"),
            "framework": detect_framework(body),
            "waf": detect_waf(headers),
            "missing_security_headers": missing
        }
    except:
        return {
            "server": "Unknown",
            "framework": "Unknown",
            "waf": "Unknown",
            "missing_security_headers": []
        }
