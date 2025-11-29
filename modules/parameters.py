DANGEROUS = ["redirect", "url", "file", "next", "dest", "path", "image"]

def extract_params(endpoints):
    params = set()
    risky = set()

    for e in endpoints:
        if "?" not in e:
            continue
        q = e.split("?", 1)[1]
        for p in q.split("&"):
            if "=" in p:
                key = p.split("=", 1)[0]
                params.add(key)
                if key.lower() in DANGEROUS:
                    risky.add(key)

    return list(params), list(risky)
