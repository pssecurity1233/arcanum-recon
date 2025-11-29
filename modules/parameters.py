# modules/parameters.py
DANGEROUS_PARAMS = [
    "redirect", "url", "next", "dest", "path",
    "file", "image", "callback", "endpoint", "return"
]

def extract_params(endpoints):
    params = set()
    risky = set()
    for e in endpoints:
        if "?" in e:
            try:
                qs = e.split("?", 1)[1]
                for pair in qs.split("&"):
                    if "=" in pair:
                        key = pair.split("=")[0]
                        params.add(key)
                        if key.lower() in DANGEROUS_PARAMS:
                            risky.add(key)
            except Exception:
                continue
    return list(params), list(risky)
