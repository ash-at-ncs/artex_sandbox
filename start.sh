#!/usr/bin/env bash
# ARTEX Sandbox Launcher for Unix/Linux/macOS

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "================================================================"
echo "  ARTEX | Autonomous Attack & Agentic Defense Sandbox"
echo "  Wire Diagram Simulation v2.4.0"
echo "================================================================"

if command -v python3 >/dev/null 2>&1; then
    exec python3 start.py
elif command -v python >/dev/null 2>&1; then
    exec python start.py
else
    echo "[-] Python is not installed. Trying to open browser to default port 8080..."
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "http://localhost:8080/wire.html"
    elif command -v open >/dev/null 2>&1; then
        open "http://localhost:8080/wire.html"
    fi
fi
