#!/usr/bin/env python3
"""
ARF Pro - Arcanum Recon Framework (Pro)
Passive recon, JS intelligence, cloud detection, parameter risk scoring.
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Local modules (make sure to replace these files with the enhanced versions below)
from modules.subdomains import crtsh_enum
from modules.fingerprint import fingerprint
from modules.jsfinder import get_js_files, analyze_js
from modules.parameters import extract_params
from modules.directories import brute_dirs
from modules.utils import save_json

# Optional coloring
try:
    from colorama import init as color_init, Fore, Style
    color_init(autoreset=True)
except Exception:
    # fallback no-color
    class _C:
        RESET = ""
        RED = ""
        GREEN = ""
        CYAN = ""
        YELLOW = ""
    Fore = _C()
    Style = _C()

VERSION = "1.0.0-pro"

BANNER = r"""
   █████╗ ██████╗  ██████╗ █████╗ ███╗   ██╗██╗   ██╗███╗   ███╗
  ██╔══██╗██╔══██╗██╔════╝██╔══██╗████╗  ██║██║   ██║████╗ ████║
  ███████║██████╔╝██║     ███████║██╔██╗ ██║██║   ██║██╔████╔██║
  ██╔══██║██╔══██╗██║     ██╔══██║██║╚██╗██║██║   ██║██║╚██╔╝██║
  ██║  ██║██║  ██║╚██████╗██║  ██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝

             A R C A N U M   R E C O N   F R A M E W O R K  —  PRO
                  Passive OSINT • JS Intel • API Mapping
"""

USAGE = f"ARF Pro v{VERSION} — Passive recon for lab and authorized testing only"

# Simple risk scoring rules (passive)
def compute_risk_score(results):
    score = 0
    reasons = []

    # Cloud leaks
    cloud_count = len(results.get("cloud_leaks", []))
    if cloud_count:
        score += 30
        reasons.append(f"{cloud_count} cloud asset references")

    # Dangerous params
    risky_params = results.get("risky_parameters", [])
    if risky_params:
        score += min(30, 10 * len(risky_params))
        reasons.append(f"dangerous params: {', '.join(risky_params)}")

    # Missing security headers
    missing = results.get("fingerprint", {}).get("missing_security_headers", [])
    if missing:
        score += min(20, 5 * len(missing))
        reasons.append(f"missing security headers: {', '.join(missing)}")

    # Found admin/forbidden directories
    dirs = results.get("directories", [])
    if dirs:
        score += 10
        reasons.append(f"{len(dirs)} interesting directories")

    # Cap and map to category
    score = min(score, 100)
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level, "reasons": reasons}

def pretty_print_results(results):
    print(Fore.CYAN + "\n[+] Summary")
    print(Fore.CYAN + "Domain: " + Fore.GREEN + results.get("domain", "n/a"))
    fp = results.get("fingerprint", {})
    print(Fore.CYAN + "Server: " + Fore.YELLOW + str(fp.get("server", "Unknown")))
    print(Fore.CYAN + "Framework: " + Fore.YELLOW + str(fp.get("framework", "Unknown")))
    print(Fore.CYAN + "WAF: " + Fore.YELLOW + str(fp.get("waf", "None Detected")))

    print(Fore.CYAN + "\n[+] Findings")
    print(Fore.CYAN + f"Subdomains: {Fore.GREEN}{len(results.get('subdomains', []))}")
    print(Fore.CYAN + f"JS files: {Fore.GREEN}{len(results.get('js_files', []))}")
    print(Fore.CYAN + f"Endpoints discovered: {Fore.GREEN}{len(results.get('endpoints', []))}")
    print(Fore.CYAN + f"Parameters found: {Fore.GREEN}{len(results.get('parameters', []))}")
    print(Fore.CYAN + f"Risky parameters: {Fore.RED}{', '.join(results.get('risky_parameters', [])) or 'None'}")
    print(Fore.CYAN + f"Cloud leaks: {Fore.YELLOW}{len(results.get('cloud_leaks', []))}")
    print(Fore.CYAN + f"Interesting directories: {Fore.GREEN}{len(results.get('directories', []))}")

    score = compute_risk_score(results)
    print(Fore.CYAN + f"\n[+] Risk Score: {Fore.RED if score['level']=='HIGH' else Fore.YELLOW if score['level']=='MEDIUM' else Fore.GREEN}{score['score']} ({score['level']})")
    if score["reasons"]:
        print(Fore.CYAN + "Reasons:")
        for r in score["reasons"]:
            print("  - " + Fore.YELLOW + r)

    print(Fore.CYAN + "\n[+] Output saved to: " + Fore.GREEN + results.get("output_file", "output/results.json"))
    print(Style.RESET_ALL)

def ensure_output_dir(path="output"):
    Path(path).mkdir(parents=True, exist_ok=True)
    return path

def run_recon(domain, output_path="output/results.json", brute_wordlist=None):
    start = time.time()
    print(BANNER)
    print(Fore.CYAN + "[*] Starting ARF Pro recon on: " + Fore.GREEN + domain)

    root_url = f"https://{domain}"

    # 1) subdomains
    print(Fore.CYAN + "[*] Enumerating subdomains (crt.sh)...")
    subs = crtsh_enum(domain)

    # 2) fingerprint
    print(Fore.CYAN + "[*] Fingerprinting root URL...")
    fp = fingerprint(root_url)

    # 3) js files
    print(Fore.CYAN + "[*] Collecting JS files from root page...")
    js_files = get_js_files(root_url)

    # 4) analyze js -> endpoints + cloud leaks
    print(Fore.CYAN + "[*] Analyzing JavaScript files for endpoints & cloud leaks...")
    endpoints, cloud_leaks = analyze_js(js_files)

    # 5) parameter extraction with risk detection
    print(Fore.CYAN + "[*] Extracting parameters and flagging risky ones...")
    params, risky = extract_params(endpoints)

    # 6) directory brute force (safe list)
    print(Fore.CYAN + "[*] Directory discovery (safe checks)...")
    if brute_wordlist is None:
        brute_wordlist = ["admin", "config", "backup", "uploads", "api", "dashboard"]
    directories = brute_dirs(root_url, brute_wordlist)

    # Build results
    results = {
        "domain": domain,
        "subdomains": subs,
        "fingerprint": fp,
        "js_files": js_files,
        "endpoints": endpoints,
        "parameters": params,
        "risky_parameters": risky,
        "cloud_leaks": cloud_leaks,
        "directories": directories,
    }

    # score
    score = compute_risk_score(results)
    results["risk_score"] = score

    ensure_output_dir(Path(output_path).parent)
    results["output_file"] = output_path
    save_json(results, path=output_path)

    elapsed = time.time() - start
    print(Fore.CYAN + f"[*] Run completed in {elapsed:.1f}s")
    pretty_print_results(results)
    return results

def main():
    parser = argparse.ArgumentParser(description=USAGE, add_help=False)
    parser.add_argument("domain", nargs="?", help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Output JSON file path", default="output/results.json")
    parser.add_argument("-w", "--wordlist", help="Comma-separated small wordlist for directory checks",
                        default=None)
    parser.add_argument("-v", "--version", action="store_true", help="Show version")
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    args = parser.parse_args()

    if args.help or not args.domain:
        print(BANNER)
        parser.print_help()
        print("\nExamples:\n  python arf.py example.com\n  python arf.py example.com -o out.json -w admin,api,backup")
        sys.exit(0)

    if args.version:
        print(f"ARF Pro — version {VERSION}")
        sys.exit(0)

    wordlist = args.wordlist.split(",") if args.wordlist else None

    run_recon(args.domain, output_path=args.output, brute_wordlist=wordlist)

if __name__ == "__main__":
    main()
