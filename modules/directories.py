import requests

def brute_dirs(base_url, wordlist):
    results = []
    for entry in wordlist:
        path = entry.strip()
        url = f"{base_url}/{path}"
        try:
            r = requests.get(url, timeout=4)
            if r.status_code in [200, 301, 302, 403]:
                results.append((url, r.status_code))
        except:
            pass
    return results
