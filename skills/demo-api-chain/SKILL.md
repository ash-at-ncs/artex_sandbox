---
name: demo-api-chain
description: Execute sequential API exploitation chains against target HTTP endpoints using WebFetch
---

# Demo API Chain Skill

When tasked with assessing target APIs under `http://waf:8080/api/`:

1. **Strictly execute in a single intent.** Do NOT invoke `nmap`, `whois`, `dig`, or port-scanning tools.
2. **Hop 1 (Layer 01 / Perimeter Gateway — KEV: CVE-2024-4577, CVE-2023-46805 | T1190):**
   - Fetch `http://waf:8080/api/edge` via `WebFetch`.
   - Post to `http://waf:8080/api/edge/export` with JSON body `{"format": "csv", "include_tokens": true}`.
   - Extract `token` (format: `edge_tok_<run_id>`) and `next_hop`.
3. **Hop 2 (Layer 02 / Identity Boundary — KEV: CVE-2023-22515, CVE-2024-27198 | T1068, T1078):**
   - Post to `http://waf:8080` + `next_hop` with Header `Authorization: Bearer <edge_tok>`.
   - Extract `token` (format: `wf_tok_<run_id>`) and `next_hop`.
4. **Hop 3 (Layer 03 / Cross-Service Pivot — KEV: CVE-2021-44228, CVE-2023-22527 | T1059, T1210):**
   - Post to `http://waf:8080` + `next_hop` with Header `Authorization: Bearer <wf_tok>`.
   - Extract `token` (format: `rec_tok_<run_id>`) and `next_hop`.
5. **Hop 4 (Layer 04 / Critical Asset Retrieval — KEV: CVE-2023-34362, CVE-2022-29464 | T1190, T1041):**
   - Fetch `http://waf:8080` + `next_hop` with Header `Authorization: Bearer <rec_tok>`.
   - Record canary value in finding summary.
6. **Defense Interruption Handling:**
   - If any hop returns HTTP status `403 Forbidden`, DO NOT attempt payload re-encoding, WAF bypass, or fuzzing.
   - Stop immediately. For the edge export block, report HTTP 403 as a virtual-patch block; the operator can confirm Rule 99001 in the WAF log. For a defender block, record the `token_revoked_by_defender` response. Do not rely on a custom WAF response body.
