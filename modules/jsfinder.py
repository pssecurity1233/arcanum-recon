import re
import requests
from urllib.parse import urljoin

def detect_cloud_assets(text):
    leaks = []
    patterns = {
        "AWS S3": r"https:\/\/[a-zA-Z0-9\._-]+\.s3\.amazonaws\.com\/?[^\s\"']*",
        "GCP Storage": r"https:\/\/storage\.googleapis\.com\/[^\s\"']*",
        "Azure Blob": r"https:\/\/[a-zA-Z0-9_-]+\.blob\.core\.windows\.net\/[^\s\"']*"
    }
    for cloud, pat in patterns.items():
        found = re.findall(pat, text)
        if found:
            leaks.append({cloud: found})
    return leaks

def get_js_files(url):
    try:
        r = requests.get(url, timeout=3)
        scripts = re.findall(r'src=["\'](.*?)["\']', r.text)
        return [urljoin(url, s) for s in scripts if s.endswith(".js")]
    except:
        return []

def extract_endpoints(code):
    return list(set(re.findall(r"(\/[a-zA-Z0-9_\-\/]+)", code)))

def analyze_js(js_files):
    endpoints = []
    cloud = []
    for js in js_files:
        try:
            r = requests.get(js, timeout=3)
            code = r.text
            endpoints.extend(extract_endpoints(code))
            cloud.extend(detect_cloud_assets(code))
        except:
            pass
    return list(set(endpoints)), cloud
