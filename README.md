<p align="center">
  <img src="https://raw.githubusercontent.com/<your-username>/arcanum-recon/main/assets/banner.svg" width="100%" />
</p>

<h1 align="center">🔥 ARF PRO v2.0 — Arcanum Recon Framework</h1>
<p align="center"><strong>Single-File Passive Reconnaissance Suite for AppSec, Red Teaming & OSINT</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-2.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Recon-Passive-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-yellow?style=for-the-badge" />
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/<your-username>/arcanum-recon?style=flat-square&color=gold" />
  <img src="https://img.shields.io/github/forks/<your-username>/arcanum-recon?style=flat-square" />
  <img src="https://img.shields.io/github/issues/<your-username>/arcanum-recon?style=flat-square" />
  <img src="https://img.shields.io/github/last-commit/<your-username>/arcanum-recon?style=flat-square&color=blue" />
</p>

---

## ⚡ Overview

**ARF PRO v2.0 (Arcanum Recon Framework)** is a **single-file passive reconnaissance engine** designed for application security, OSINT, red teaming, and bug bounty reconnaissance.

The framework performs **zero intrusive actions** — only safe, passive HTTP GET/HEAD requests, Certificate Transparency lookups, DNS-over-HTTPS, JS intel, and metadata-based API discovery.

This makes ARF PRO suitable for **professional AppSec workflows**, **pre-engagement recon**, **university research**, **OSINT investigations**, and **CTF practice**.

---

# 🔥 Features

### ✅ Passive Enumeration
- Certificate Transparency subdomains  
- DNS-over-HTTPS (Google + Cloudflare)  
- robots.txt + sitemap.xml extraction  
- Technology fingerprinting  
- Cookie analysis  
- Security header analysis  

### ✅ JavaScript Intelligence
- JS file extraction  
- Endpoint enumeration  
- Cloud asset leak detection  
- Framework detection (React, Vue, Next, Express, etc.)

### ✅ Passive API Recon
- JSON API detection  
- Swagger/OpenAPI signature discovery  
- GraphQL indicators  
- CORS policy exposure  

### ✅ Reporting
- **Stand-alone HTML report** (inline CSS)  
- **JSON structured output**  
- **SQLite optional logging**  

### ✅ Engineering Features
- Multithreading  
- TQDM progress bars  
- Plugin loader  
- config.json support  
- Cross-platform (Linux, Windows, macOS)

---

# 🖼️ ASCII Logo

█████╗ ██████╗ ██████╗ █████╗ ███╗ ██╗██╗ ██╗███╗ ███╗
██╔══██╗██╔══██╗██╔════╝██╔══██╗████╗ ██║██║ ██║████╗ ████║
███████║██████╔╝██║ ███████║██╔██╗ ██║██║ ██║██╔████╔██║
██╔══██║██╔══██╗██║ ██╔══██║██║╚██╗██║██║ ██║██║╚██╔╝██║
██║ ██║██║ ██║╚██████╗██║ ██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
╚═╝ ╚═╝╚═╝ ╚═╝ ╚═════╝╚═╝ ╚═╝╚═╝ ╚═══╝ ╚═════╝ ╚═╝ ╚═╝

mathematica
Copy code
             A R C A N U M   R E C O N   F R A M E W O R K
yaml
Copy code

---

# 🛠 Installation

### 1. Clone Repository
```bash
git clone https://github.com/<your-username>/arcanum-recon
cd arcanum-recon
2. Install Requirements
bash
Copy code
pip install -r requirements.txt
🚀 Usage
Basic Scan
bash
Copy code
python arf.py example.com
Full Recon
bash
Copy code
python arf.py example.com --threads 12 --dns --html --api-mode
Save to SQLite DB
bash
Copy code
python arf.py example.com --save-db
Fingerprint Subdomains
bash
Copy code
python arf.py example.com --fingerprint-subdomains
Per-user Output Structure
bash
Copy code
python arf.py example.com --user prathamesh --html
Output stored in:

bash
Copy code
output/prathamesh/
Show Version
bash
Copy code
python arf.py --version
Full Help Menu
bash
Copy code
python arf.py --help
📦 Output Structure
lua
Copy code
output/
   prathamesh/
       results_example.com_20251129.json
       report-example.com-20251129.html
HTML report includes:

Subdomains

JS intel

Endpoints

API analysis

Cloud leaks

Passive DNS

Risk scoring

Technologies

Missing security headers

⚙️ Config File Example (config.json)
json
Copy code
{
  "threads": 12,
  "http_timeout": 4,
  "dns": true,
  "robots": true,
  "sitemap": true,
  "save_db": false,
  "dir_wordlist": ["admin","test","login","dev","backup"]
}
🧠 Risk Score Logic
Finding	Score
Cloud storage leaks	+25
Dangerous parameters	+25
Interesting directories	+10
Missing security headers	+5 each
Total	→ LOW / MEDIUM / HIGH

🔍 Architecture Diagram (ASCII)
sql
Copy code
           +-----------------------+
           |       Target          |
           +-----------+-----------+
                       |
                       v
        +----------------------------------+
        |         ARF PRO ENGINE           |
        +----------------------------------+
        |  Subdomain Module (crt.sh)       |
        |  DNS Module (DoH)                |
        |  Fingerprint Module              |
        |  JS Intel Module                 |
        |  API Recon                       |
        |  Directory Scanner (Safe)        |
        |  Report Generator                |
        +----------------------------------+
                       |
                       v
         +-----------------------------+
         |   Reports / DB / JSON       |
         +-----------------------------+
🧩 Plugin System
Plugins inside plugins/*.py automatically load.

Example plugin function:

python
Copy code
def run_plugin(results):
    return {"custom": "plugin executed"}
📊 Screenshots
HTML Report
(Insert screenshots here)

⚖️ Legal & Ethical Notice
ARF PRO v2.0 performs strictly passive operations:

✔ No port scanning
✔ No brute force
✔ No intrusion attempts
✔ Only GET/HEAD requests
✔ Safe for OSINT & teaching

Use only on systems you are authorized to test.

🤝 Contributing
PRs and feature suggestions are welcome.

📜 License
MIT License.

