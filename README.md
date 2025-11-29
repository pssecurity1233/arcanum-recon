<!-- Banner -->
<p align="center">
  <img src="banner.svg" width="100%" alt="Arcanum Recon Framework Banner">
</p>

<h1 align="center">🔍 Arcanum Recon Framework (ARF)</h1>
<p align="center">
  <b>Precision OSINT & Passive Reconnaissance for Modern Pentesters</b><br>
  Lightweight • Cross-Platform • Modular • CTF & Authorized Testing Only
</p>

---

## 📘 Overview

Arcanum Recon Framework (**ARF**) is a **passive, safe, OSINT-based reconnaissance toolkit**  
built for **Kali Linux, Windows, and macOS**.

It is designed to support:

- ✔ Bug bounty hunters  
- ✔ CTF players  
- ✔ Red team initial mapping  
- ✔ Security researchers  
- ✔ Ethical penetration testers  

ARF does **not** perform active exploitation.  
It only collects publicly visible information using **safe HTTP requests**.

---

## 🚀 Features

- 🔹 **Subdomain Enumeration** (crt.sh CT logs)  
- 🔹 **Tech Fingerprinting** (server, cookies, headers)  
- 🔹 **JavaScript File Analysis** (auto-discover API endpoints)  
- 🔹 **Endpoint Extraction** (regex-based route analysis)  
- 🔹 **URL Parameter Discovery** (`id`, `redirect`, `file`, etc.)  
- 🔹 **Directory Discovery** (safe 200/301/302/403 detection)  
- 🔹 **JSON Output Report**  
- 🔹 **Cross-platform:** Kali Linux • Windows • macOS  
- 🔹 **Extremely Lightweight** — pure Python, no heavy dependencies  

---

## 📂 Project Structure

arcanum-recon/
│
├── arf.py # Main CLI entry point
├── requirements.txt
│
├── modules/
│ ├── subdomains.py
│ ├── ports.py
│ ├── fingerprint.py
│ ├── jsfinder.py
│ ├── parameters.py
│ ├── directories.py
│ └── utils.py
│
└── output/
└── results.json

yaml
Copy code

---

## 🛠 Installation

### ✔ Kali Linux / Ubuntu

```bash
sudo apt update
sudo apt install python3 python3-pip -y
git clone https://github.com/<your-username>/arcanum-recon.git
cd arcanum-recon
pip3 install -r requirements.txt
✔ Windows (PowerShell)
powershell
Copy code
git clone https://github.com/<your-username>/arcanum-recon.git
cd arcanum-recon
pip install -r requirements.txt
▶️ Usage
Run ARF with:

bash
Copy code
python arf.py <domain>
Example:

bash
Copy code
python arf.py example.com
📄 Output Example (output/results.json)
json
Copy code
{
  "domain": "example.com",
  "subdomains": ["dev.example.com", "api.example.com"],
  "fingerprint": {
    "server": "nginx",
    "cookies": {},
    "powered_by": "Express"
  },
  "js_files": [
    "https://example.com/static/app.js"
  ],
  "endpoints": [
    "/api/v1/login",
    "/admin",
    "/static/js/main.js"
  ],
  "parameters": [
    "id",
    "file",
    "redirect"
  ],
  "directories": [
    ["https://example.com/admin", 403]
  ]
}
🔬 Module Breakdown
🔎 Subdomain Enumeration
Extracts subdomains using certificate transparency (crt.sh).

🔍 Fingerprinting
Identifies server header, cookies, X-Powered-By, security headers.

📜 JS Intelligence Module
Finds public JavaScript and extracts API routes.

🔑 URL Parameter Discovery
Detects common vuln-prone parameters (redirect, file, id).

📁 Directory Discovery
Checks for existence of common folders (admin, backup, uploads…).

🔐 Legal Notice
This tool is for educational, CTF, and authorized security testing only.
You must have permission before scanning any domain.

The author is not responsible for misuse.

🤝 Contributing
Contributions are welcome!

Fork the repo

Create a branch

Make your changes

Submit a pull request

Ideas to contribute:

multithreading

DNS-based subdomain enumeration

cloud asset detection

PDF reporting

web dashboard

⭐ Support the Project
If you like ARF, please ⭐ star the repository — it helps visibility!

📜 License
This project is released under the MIT License, allowing safe reuse and modification.

<p align="center"> Built with ❤️ for Cybersecurity Education </p> ```
