import requests

def crtsh_enum(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    subs = set()

    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
        for entry in data:
            name = entry["name_value"].replace("*.", "")
            subs.add(name)
    except Exception:
        pass

    return list(subs)
