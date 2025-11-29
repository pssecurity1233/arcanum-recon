def extract_params(endpoints):
    params = set()
    for e in endpoints:
        if "?" in e:
            qs = e.split("?")[1]
            for pair in qs.split("&"):
                if "=" in pair:
                    params.add(pair.split("=")[0])
    return list(params)
