import sys
from modules.subdomains import crtsh_enum
from modules.fingerprint import fingerprint
from modules.jsfinder import get_js_files, analyze_js
from modules.parameters import extract_params
from modules.directories import brute_dirs
from modules.utils import save_json

VERSION = "1.0.0"

BANNER = r"""
   █████╗ ██████╗  ██████╗ █████╗ ███╗   ██╗██╗   ██╗███╗   ███╗
  ██╔══██╗██╔══██╗██╔════╝██╔══██╗████╗  ██║██║   ██║████╗ ████║
  ███████║██████╔╝██║     ███████║██╔██╗ ██║██║   ██║██╔████╔██║
  ██╔══██║██╔══██╗██║     ██╔══██║██║╚██╗██║██║   ██║██║╚██╔╝██║
  ██║  ██║██║  ██║╚██████╗██║  ██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝

             A R C A N U M   R E C O N   F R A M E W O R K
                  Passive OSINT • JS Intel • API Mapping
"""

HELP = f"""
Arcanum Recon Framework (ARF)
Version: {VERSION}

Usage:
  python arf.py <domain>
  python arf.py --help
  python arf.py --version

Options:
  -h, --help       Show this help menu
  -v, --version    Show tool version
  <domain>         Domain to enumerate (e.g., example.com)

Examples:
  python arf.py example.com
  python arf.py --version
"""

def run(domain):
    print(BANNER)
    print("[+] Starting recon:", domain)

    root_url = f"https://{domain}"

    print("[+] Enumerating subdomains...")
    subs = crtsh_enum(domain)

    print("[+] Fingerprinting target...")
    fp = fingerprint(root_url)

    print("[+] Fetching JavaScript files...")
    js_files = get_js_files(root_url)

    print("[+] Extracting endpoints from JS...")
    endpoints = analyze_js(js_files)

    print("[+] Extracting URL parameters...")
    params = extract_params(endpoints)

    print("[+] Directory brute-force...")
    wordlist = ["admin", "config", "backup", "uploads", "api"]
    dirs = brute_dirs(root_url, wordlist)

    results = {
        "domain": domain,
        "subdomains": subs,
        "fingerprint": fp,
        "js_files": js_files,
        "endpoints": endpoints,
        "parameters": params,
        "directories": dirs,
    }

    save_json(results)
    print("[+] Results written to output/results.json")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print(HELP)
        sys.exit(0)

    if sys.argv[1] in ["-h", "--help"]:
        print(HELP)
        sys.exit(0)

    if sys.argv[1] in ["-v", "--version"]:
        print(f"Arcanum Recon Framework (ARF)\nVersion: {VERSION}")
        sys.exit(0)

    run(sys.argv[1])
