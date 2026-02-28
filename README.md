# OpenVPN RCE Proof-of-Concept (Windows)

> [!CAUTION]
> **LEGAL DISCLAIMER**: This project is for **EDUCATIONAL AND RESEARCH PURPOSES ONLY**. Unauthorized access to computer systems is illegal. The authors assume no liability for any misuse or damage caused by this tool. Use it only on systems you own or have explicit permission to test.

This repository contains a Proof-of-Concept (PoC) demonstrating a Remote Code Execution (RCE) vulnerability in OpenVPN clients (specifically tested on Windows) by exploiting the `up` script execution directive in `.ovpn` configuration files.

---

## 🛡️ Vulnerability Overview

The vulnerability leverages a legitimate feature of OpenVPN: the ability to execute external scripts/commands when certain events occur (e.g., when the tunnel goes "up").

### The Mechanism
1.  **Directive**: The `up` directive in an OpenVPN configuration file specifies a command to be executed after a successful TUN/TAP device opening.
2.  **Security Setting**: By default, OpenVPN restricts script execution. However, if the configuration includes `script-security 2` (or higher), it allows the execution of user-defined scripts.
3.  **Exploitation**: An attacker can provide a malicious `.ovpn` file that includes both `script-security 2` and an `up` directive pointing to a malicious payload (e.g., `calc.exe` or a reverse shell). When the victim imports and connects using this profile, the payload is executed with the privileges of the OpenVPN process.

---

## 💻 System Compatibility

> [!IMPORTANT]
> **Windows Only**: This PoC is specifically designed and verified for **Windows** environments. It currently does **not** support Linux or macOS.

---

## 🎯 Target Versions

- **Latest Verified**: OpenVPN 2.7.0 (Windows)
- **Affected Range**: This configuration-based exploit is applicable to OpenVPN 2.x and earlier, provided `script-security 2` is enabled.

---

## 🛠️ Prerequisites & Setup

### 1. Python Environment
- **Python 3.8+** is required.
- Install dependencies:
  ```bash
  pip install git+https://github.com/Wang-SecurityResearch/ctf_toolkit.git
  ```

### 2. OpenSSL Configuration
The `poc_generator.py` script requires OpenSSL to generate the necessary CA and client certificates.
- **Requirement**: OpenSSL must be installed (commonly available via [Git for Windows](https://git-scm.com/download/win)).
- **Configuration**: If your OpenSSL configuration file is not at the default path, update the `OPENSSL_CONF` environment variable in `poc_generator.py` (Line 27):
  ```python
  env["OPENSSL_CONF"] = r"C:\path\to\your\openssl.cnf"
  ```

---

## 🚀 Usage Guide

### Step 1: Generate PoC Files
Run the generator script to create a working directory with CA certificates, server configs, and various malicious client profiles.
```bash
python poc_generator.py
```
This will create an `openvpn_poc` folder in your user profile containing:
- `client_rce_calc.ovpn`: Executes Calculator.
- `client_rce_powershell.ovpn`: Executes a PowerShell command.
- ...and more.

### Step 2: Start the Malicious Web Server
The PoC includes a web server to simulate a remote configuration distribution point.
```bash
# This may require Administrative privileges to bind to port 443
python poc_web_server.py
```
Alternatively, use the generated `start.bat` in the output directory.

### Step 3: Trigger the Exploit
1.  Open **OpenVPN GUI** on the target Windows machine.
2.  Right-click the tray icon -> **Import** -> **Import from URL**.
3.  Enter the URL provided by the server (e.g., `https://<your-ip>/vpn.ovpn`).
4.  Connect to the imported profile.
5.  **Result**: Upon connection, the defined payload (e.g., `calc.exe`) will launch.

---

## 📂 Project Structure

- `poc_generator.py`: Generates the PKI infrastructure and malicious `.ovpn` files.
- `poc_web_server.py`: An HTTPS server that serves the malicious profiles.
- `requirements.txt`: Python dependency list.
- `start.bat`: Convenience script to start the server.

---

## 📝 Payload Customization
You can modify the `payloads` dictionary in `poc_generator.py` to test different RCE scenarios:
```python
payloads = {
    "my_payload": '"C:\\path\\to\\malware.exe" --args'
}
```

---
*Created by Antigravity PoC Suite*

