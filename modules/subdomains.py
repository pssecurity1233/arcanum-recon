import requests

def crtsh_enum(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code != 200:
            return []
        data = r.json()
        subs = list(set([d["name_value"].replace("*.", "") for d in data]))
        return subs
    except:
        return []
