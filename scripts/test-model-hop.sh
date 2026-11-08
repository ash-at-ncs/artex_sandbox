#!/usr/bin/env bash
set -euo pipefail

echo "[*] Verifying container-to-host connectivity to LM Studio (http://host.docker.internal:1234)..."

docker run --rm --add-host host.docker.internal:host-gateway curlimages/curl -s --connect-timeout 4 http://host.docker.internal:1234/v1/models > /dev/null || {
    echo "[-] ERROR: Container failed to reach LM Studio at http://host.docker.internal:1234/v1/models"
    echo "[-] Please verify:"
    echo "    1. LM Studio is running on the Windows host and the server is started on port 1234."
    echo "    2. The model 'openai/gpt-oss-20b' is loaded with --context-length 32768."
    echo "    3. Windows Firewall permits incoming connections from WSL2 to port 1234."
    exit 1
}

echo "[+] SUCCESS: LM Studio endpoint is reachable from the Docker bridge."
