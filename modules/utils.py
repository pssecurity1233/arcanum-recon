import json

def save_json(data, path="output/results.json"):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
