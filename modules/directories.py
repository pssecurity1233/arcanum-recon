import requests

def brute_dirs(base, words):
    found = []
    for w in words:
        url = f"{base.rstrip('/')}/{w}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code in [200, 301, 302, 403]:
                found.append((url, r.status_code))
        except:
            pass
    return found
