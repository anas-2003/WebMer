# Project (WebMer v2.0)

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

## About Project Prometheus

**Project Prometheus** is not just another web vulnerability scanner. It's a next-generation offensive security platform designed to mimic the intelligence and adaptability of a human penetration tester. Built on a fully asynchronous core, Prometheus leverages AI-like techniques to discover, confirm, and exploit complex vulnerabilities, while actively evading modern defense systems.

The core philosophy of Prometheus is to move beyond static payload lists and predefined checks. It employs a **persistent learning brain** and **evolutionary fuzzing algorithms** to develop custom attack vectors tailored to each specific target, enabling the discovery of both known vulnerabilities and potential **Zero-Days**.

---

## Key Features & Capabilities

Prometheus is an integrated platform that covers the full attack lifecycle, from reconnaissance to deep exploitation and defense evasion.

####  **Intelligent Attack Engine**
- **Reinforcement Learning (Q-Learning) Brain:** A persistent "brain" that learns from every scan. It maps target technologies and defense postures to the most effective attack modules, becoming smarter and more efficient over time.
- **Genetic Algorithm Fuzzer:** An evolutionary engine that treats payloads as "genes". It evolves highly effective, custom payloads through generations of selection, crossover, and mutation, designed to bypass complex filters and WAFs.
- **Differential Analysis:** Discovers blind vulnerabilities by meticulously analyzing subtle changes in response status, content length, and similarity ratios (`difflib`).

#### **Defense Evasion & Bypass**
- **WAF/IPS Fingerprinting:** Automatically identifies common WAFs (Cloudflare, ModSecurity, Sucuri, Akamai) and logs their presence.
- **Adaptive Stealth Mode:** Upon WAF detection, the scanner automatically throttles request concurrency, randomizes delays, and rotates User-Agents to avoid detection and blocking.
- **Origin IP Discovery:** Implements automated techniques, including subdomain enumeration via DNS, to uncover the true IP address of servers hidden behind CDN and WAF services like Cloudflare.
- **Full HTTPS/SSL Support:** Seamlessly scans HTTPS targets, automatically ignoring SSL certificate validation errors common in testing environments.

#### **Comprehensive Vulnerability & Exploitation Modules**
- **Pluggable Architecture:** A modular design that allows for easy addition of new vulnerability classes.
- **Deep SQLi Exploitation:** Goes beyond detection to perform automated UNION-based attacks to determine column count and extract data like database versions. Includes time-based blind detection.
- **Advanced LFI/RFI Exploitation:** Attempts to achieve RCE through techniques like `php://filter` for source code disclosure and conceptual Log Poisoning.
- **Header & URL Path Fuzzing:** Extends the attack surface beyond standard parameters to test for vulnerabilities in HTTP headers and URL paths.

#### 🛠 **Professional Tooling & Workflow**
- **High-Performance Core:** Fully asynchronous (`asyncio` & `aiohttp`) for high-speed scanning, with support for `multiprocessing` to scan multiple targets in parallel across all CPU cores.
- **API Scanning Mode:** Natively parses OpenAPI/Swagger and Postman specifications to build and fuzz a targeted attack surface for modern APIs.
- **Session Management:** Allows for pausing and resuming long-running scans, saving progress and discovered endpoints.
- **Terminal Multiplexing:** Optional support for opening new terminal windows (`tmux`, `gnome-terminal`) for intensive operations like data dumping.
- **Proxy Support:** Route all traffic through interception proxies like Burp Suite or OWASP ZAP for debugging and manual analysis.

---

## ⚙ Requirements & Setup

- **System:** A Debian-based Linux distribution (e.g., Ubuntu, Kali Linux) is recommended.
- **Python:** Python 3.9 or higher.
- **Dependencies:** The `setup.sh` script handles all system and Python dependencies.

### Installation

Getting Prometheus ready is straightforward.

1.  **Clone the Repository:**
    ```sh
    git clone https://github.com/anas-2003/WebMer.git
    cd WebMer
    ```

2.  **Run the Setup Script:**
    This script will install system packages, create a Python virtual environment, and install all required libraries. It will ask for your password for `sudo` operations.
    ```sh
    chmod +x setup.sh
    ./setup.sh
    ```

### Running Prometheus

After a successful setup, use the `run.sh` script to launch the platform. **Do not use `sudo` to run it.** The script handles permissions internally.

1.  **Give execution permission to the runner:**
    ```sh
    chmod +x run.sh
    ```

2.  **Launch the Scan:**
    ```sh
    # Scan a single target with verbose output
    ./run.sh -u "https://example.com" -v

    # Scan a list of targets using 4 parallel processes
    ./run.sh --list targets.txt --multi-process 4

    # Scan an API using a Swagger file
    ./run.sh -u "https://api.example.com" --api-spec ./swagger.json

    # Resume a previous scan
    ./run.sh -u "https://example.com" --resume
    ```

---

## ⚠ Legal Disclaimer

**Project Prometheus** is a powerful offensive security tool. It is intended for **authorized security testing and educational purposes only**. Any action and/or activity related to Prometheus is solely your responsibility. The misuse of this tool can result in criminal charges. The developer, Anas Erami, assumes no liability and is not responsible for any misuse or damage caused by this program. **Use it ethically.**

---

## Contributing

Contributions are welcome! Whether it's by adding new fuzzing modules, improving the AI engine, or fixing bugs, your help is appreciated. Please fork the repository and submit a pull request.

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Anas Erami - [anaserami17@gmail.com]

Project Link: [https://github.com/anas-2003/WebMer.git](https://github.com/anas-2003/WebMer.git)
