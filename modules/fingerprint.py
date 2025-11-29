import requests

def fingerprint(url):
    try:
        r = requests.get(url, timeout=5)
        return {
            "url": url,
            "server": r.headers.get("Server"),
            "powered_by": r.headers.get("X-Powered-By"),
            "cookies": dict(r.cookies),
            "content_type": r.headers.get("Content-Type"),
            "security_headers": [h for h in r.headers if "sec" in h.lower()],
        }
    except:
        return {}
