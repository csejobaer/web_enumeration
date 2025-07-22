Here’s a well-structured and professional `README.md` content you can use for your GitHub repository to describe your Kali Linux website enumeration tool:

---

# 🔍 Website Information Enumeration Tool (Kali Linux)

A powerful Python-based information gathering tool built for Kali Linux. It performs website reconnaissance by collecting vital data including WHOIS, IP info, subdomains, port scanning, and more. Special support is included for `.bd` domains via **Bangladesh Telecom (BTCL)** scraping, due to the absence of public WHOIS servers for `.bd` TLDs.

---

## ✨ Features

* ✅ **Domain Parsing & IP Resolution**
* 🌐 **WHOIS Lookup**

  * Standard WHOIS for global TLDs
  * Web scraping-based WHOIS for `.bd` domains from BTCL
* 🧠 **Subdomain Enumeration**

  * Uses `crt.sh` Certificate Transparency logs
  * Optional wordlist-based brute-force (planned)
* 🚪 **Port Scanning**

  * Fast top 1000 port scan using `nmap`
* 📄 **Organized Output**

  * Saves results in per-target folders
  * All results saved in readable `.txt` files
* 💻 **Live Terminal Output**

  * See progress and results in real-time

---

## 🛠 Requirements

* Python 3.x
* Kali Linux (or any Debian-based distro)
* Internet connection
* Required Python modules:

```bash
pip install requests beautifulsoup4
```

* Optional but recommended tools:

  * `nmap` (for port scanning)
  * `whois` CLI tool (`sudo apt install whois`)

---

## 📂 Output Structure

Each scan saves results in a directory like:

```
output/
└── example.com/
    ├── whois_domain.txt
    ├── whois_ip.txt
    ├── subdomains.txt
    ├── port_scan.txt
```

---

## 🧪 Usage

```bash
python3 web_enum.py
```

Enter a target domain (e.g. `example.com` or `emch.com.bd`) when prompted. The tool will perform:

* WHOIS lookup
* IP resolution
* Subdomain enumeration
* Port scanning

All outputs are printed live and saved in files automatically.

---

## 🌍 Special Handling for `.bd` Domains

`.bd` domains do not support standard WHOIS queries. This tool intelligently fetches WHOIS data from:

🔗 [https://bdia.btcl.com.bd](https://bdia.btcl.com.bd)

---

## 📌 Notes

* Ensure you have internet access.
* Avoid overusing against live sites without permission.
* This tool is for **educational and authorized penetration testing** only.

---

## ⚖️ License

MIT License

---

## 🤝 Contributing

Pull requests are welcome! Feel free to open issues or suggest new features.

---

## 👨‍💻 Author

**Md. Jobaer Hossain**
📧 [mlt.jobaer@gmail.com](mailto:mlt.jobaer@gmail.com)
🔗 [LinkedIn](https://www.linkedin.com/in/mdjobaer/)
🔎 [Google Scholar](https://scholar.google.com/citations?user=LvgjubQAAAAJ&hl=en)

---

Let me know if you'd like a logo, badge-style feature icons, or if you want me to help publish the repo to GitHub for you.
