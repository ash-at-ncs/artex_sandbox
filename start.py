#!/usr/bin/env python3
"""
ARTEX Sandbox Launcher
Starts an HTTP server and opens the interactive Wire Diagram Simulation in your default browser.
"""

import sys
import os
import socket
import webbrowser
import http.server
import socketserver
import threading
import time

DEFAULT_PORT = 8080
TARGET_PATH = "/wire.html"

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def find_available_port(start_port=8080, max_attempts=20):
    for port in range(start_port, start_port + max_attempts):
        if not is_port_in_use(port):
            return port
    return None

def main():
    sandbox_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(sandbox_dir)

    print("=" * 64)
    print("  ARTEX | Autonomous Attack & Agentic Defense Sandbox")
    print("  Wire Diagram Simulation v2.4.0")
    print("=" * 64)

    # Check if 8080 is already in use
    if is_port_in_use(DEFAULT_PORT):
        print(f"[!] Port {DEFAULT_PORT} is already active.")
        print(f"[*] Opening browser to existing server: http://localhost:{DEFAULT_PORT}{TARGET_PATH}")
        webbrowser.open(f"http://localhost:{DEFAULT_PORT}{TARGET_PATH}")
        print("\nPress Ctrl+C to exit launcher.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nExiting.")
            sys.exit(0)

    port = find_available_port(DEFAULT_PORT)
    if not port:
        print(f"[-] Could not find an open port starting from {DEFAULT_PORT}.")
        sys.exit(1)

    Handler = http.server.SimpleHTTPRequestHandler
    
    # Configure custom handler to avoid cluttering terminal
    class QuietHandler(Handler):
        def log_message(self, format, *args):
            pass

    httpd = socketserver.TCPServer(("", port), QuietHandler)
    url = f"http://localhost:{port}{TARGET_PATH}"
    table_url = f"http://localhost:{port}/index.html"

    print(f"[+] Serving directory: {sandbox_dir}")
    print(f"[+] Wire Diagram Demo: {url}")
    print(f"[+] Tabular Range View: {table_url}")
    print("[+] Launching web browser...")

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    time.sleep(0.5)
    webbrowser.open(url)

    print("\n[✓] Server is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down ARTEX server.")
        httpd.shutdown()
        sys.exit(0)

if __name__ == "__main__":
    main()
