import re
import requests
from urllib.parse import urljoin

def detect_cloud_assets(text):
    findings = []

    patterns = {
        "AWS S3": r"https:\/\/[a-zA-Z0-9\.\-_]+\.s3\.amazonaws\.com",
        "GCP Storage": r"https:\/\/storage\.googleapis\.com\/[a-zA-Z0-9\.\-_]+",
        "Azure Blob": r"https:\/\/[a-zA-Z0-9\-_]+\.blob\.core\.windows\.net\/",
        "Firebase": r"https:\/\/[a-zA-Z0-9\-_]+\.firebaseio\.com"
    }

    for cloud, pattern in patterns.items():
        found = re.findall(pattern, text)
        if found:
            findings.append({cloud: found})

    return findings

def get_js_files(url):
    try:
        r = requests.get(url, timeout=6)
        scripts = re.findall(r'<script[^>]+src="(.*?)"', r.text)
        return [urljoin(url, s) for s in scripts]
    except:
        return []

def extract_endpoints(js_code):
    regex = r"(\/[a-zA-Z0-9_\-\/]+(?:\?[a-zA-Z0-9=&_\-]*)?)"
    return list(set(re.findall(regex, js_code)))

def analyze_js(js_files):
    all_endpoints = []
    cloud_leaks = []

    for js in js_files:
        try:
            code = requests.get(js, timeout=6).text
            all_endpoints.extend(extract_endpoints(code))

            cloud_leaks.extend(detect_cloud_assets(code))

        except:
            pass

    return list(set(all_endpoints)), cloud_leaks
