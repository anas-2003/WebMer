# WebMer - The Intelligent Offensive Security Platform

<div align="center">

```
████████╗███████╗███████╗███████╗██████╗ ██████╗ ██╗   ██╗██████╗ ███████╗███████╗
╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔════╝██╔════╝
   ██║   █████╗  ███████╗█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ███████╗
   ██║   ██╔══╝  ╚════██║██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══╝  ╚════██║
   ██║   ███████╗███████║███████╗██║  ██║██║  ██║╚██████╔╝██║  ██║███████╗███████║
   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

**An Advanced, AI-Driven Offensive Security Platform for Web Applications & APIs**

</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Status-Active%20Development-green.svg" alt="Status: Active Development">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/github/stars/anas-2003/WebMer?style=social" alt="GitHub Stars">
</p>

---

## About WebMer

**WebMer** is not just another web vulnerability scanner. It's a next-generation offensive security platform designed to mimic the intelligence and adaptability of a human penetration tester. Built on a fully asynchronous core, WebMer leverages AI-like techniques to discover, confirm, and exploit complex vulnerabilities, while actively evading modern defense systems.

The core philosophy of WebMer is to move beyond static payload lists. It employs a **persistent learning brain (Q-Learning)** and **evolutionary fuzzing algorithms** to develop custom attack vectors tailored to each specific target, enabling the discovery of both known vulnerabilities and potential **Zero-Days**.

---

## Key Features & Capabilities

WebMer is an integrated platform that covers the full attack lifecycle, from reconnaissance to deep exploitation and defense evasion.

#### **Intelligent Attack Engine**
- **Reinforcement Learning (Q-Learning) Brain:** A persistent "brain" that learns from every scan. It maps target technologies and defense postures to the most effective attack modules, becoming smarter and more efficient over time.
- **Genetic Algorithm Fuzzer:** An evolutionary engine that treats payloads as "genes". It evolves highly effective, custom payloads through generations of selection, crossover, and mutation, designed to bypass complex filters and WAFs.
- **Differential Analysis:** Discovers blind vulnerabilities by meticulously analyzing subtle changes in response status, content length, and similarity ratios.

#### 🛡 **Defense Evasion & Bypass**
- **WAF/IPS Fingerprinting:** Automatically identifies common WAFs (Cloudflare, ModSecurity, etc.) and engages an adaptive stealth mode.
- **Adaptive Stealth Mode:** Upon WAF detection, the scanner automatically throttles request concurrency, randomizes delays, and rotates User-Agents to avoid detection.
- **Origin IP Discovery:** Implements automated techniques, including subdomain enumeration via DNS, to uncover the true IP address of servers hidden behind CDNs.

#### **Comprehensive Vulnerability & Exploitation Modules**
- **Pluggable Architecture:** A modular design that allows for easy addition of new vulnerability classes (SQLi, XSS, LFI, and more).
- **Deep SQLi Exploitation:** Goes beyond detection to perform automated UNION-based attacks to determine column count and extract data.
- **Advanced LFI Exploitation:** Attempts to achieve RCE through techniques like `php://filter` and conceptual Log Poisoning.

#### 🛠 **Professional Tooling & Workflow**
- **High-Performance Core:** Fully asynchronous (`asyncio` & `aiohttp`) with `multiprocessing` support to scan multiple targets in parallel across all CPU cores.
- **API Scanning Mode:** Natively parses OpenAPI/Swagger specifications to build a targeted attack surface for modern APIs.
- **Session Management:** Allows for pausing and resuming long-running scans.
- **Proxy Support:** Route all traffic through interception proxies like Burp Suite.
- **System-Wide Command:** Installs as a global `webmer` command, accessible from anywhere in your terminal.

---

## ⚙ Installation

WebMer can be installed as a system-wide command, making it accessible from anywhere.

1.  **Clone the Repository:**
    ```sh
    git clone https://github.com/anas-2003/WebMer.git
    cd WebMer
    ```

2.  **Run the Installer:**
    The installer script handles all dependencies and sets up the command. It will ask for your password for `sudo` operations.
    ```sh
    chmod +x install.sh
    sudo ./install.sh
    ```

That's it! WebMer is now installed.

---

## Usage

After a successful installation, you can run `webmer` directly from your terminal, just like any other professional tool.

#### Basic Examples

```sh
# Scan a single target with verbose output
webmer -u "https://example.com" -v

# Scan a list of targets using 4 parallel processes
webmer --list targets.txt --multi-process 4

# Scan an API using a Swagger file
webmer -u "https://api.example.com" --api-spec ./swagger.json

# Resume a previous scan for a specific target
webmer -u "https://example.com" --resume
```

#### Advanced Usage

```sh
# Scan with a proxy and session cookies
webmer -u "https://example.com" --proxy http://127.0.0.1:8080 --cookies "session_id=12345"

# Attempt to dump the 'users' table after finding an SQLi vulnerability
webmer -u "https://vulnerable.site/item.php?id=1" --dump users
```

---

## ⚠ Legal Disclaimer

**WebMer** is a powerful offensive security tool. It is intended for **authorized security testing and educational purposes only**. Any action and/or activity related to WebMer is solely your responsibility. The misuse of this tool can result in criminal charges. The developer, Anas Erami, assumes no liability and is not responsible for any misuse or damage caused by this program. **Use it ethically.**

---

## Contributing

Contributions are welcome! Whether it's by adding new fuzzing modules, improving the AI engine, or fixing bugs, your help is appreciated. Please fork the repository and submit a pull request.

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Anas Erami - [anaserami17@gmail.com]

Project Link: [https://github.com/anas-2003/WebMer](https://github.com/anas-2003/WebMer)
