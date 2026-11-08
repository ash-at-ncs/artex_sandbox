# ARTEX Local Docker Lab: Technical & Engineering Specification

**Document Version:** 1.0.0  
**Date:** 8 November 2026  
**Status:** Normative Engineering Specification  
**Parent Document:** [ARTEX Local Docker Lab Plan](artex_local_docker_lab_plan.md)  
**Target Environment:** Windows 11 Pro (WSL 2 / Ubuntu Linux kernel), Docker Desktop 29.7+, NVIDIA RTX 4090 (24GB VRAM), LM Studio local API (`http://host.docker.internal:1234/v1`).

---

## 1. System Overview & Architecture Boundary

This specification defines the exact container topologies, network isolation properties, API contracts, machine learning detector logic, WAF rule configurations, and operational scripts required to implement the contained ARTEX demonstration lab.

### 1.1 Network Architecture and Containment Topology

The lab isolates the ARTEX autonomous red-team agent from internal mock microservices and backend controls. Communication across layers is strictly mediated by an ingress Web Application Firewall (WAF) reverse proxy and an internal telemetry/control plane.

```
       [ Windows 11 Host: LM Studio API (:1234) & Operator Browser ]
                                      |
                     (host-routable loopback bindings)
                 :8787 (UI) / :8788 (Proxy)     :8080 (WAF Ingress)
                             |                           |
+----------------------------v---------------------------v---------------------------+
| ingress_net (bridge, internal: false)                                              |
|   - artex (v0.3.27)                                                                |
|   - waf (OWASP ModSecurity CRS 4.x / Nginx)                                        |
+----------------------------+---------------------------+---------------------------+
                             |                           |
       +---------------------+                           +---------------------+
       |                                                                       |
+------v---------------------+                           +---------------------v-----+
| db_net (internal: true)    |                           | proxy_net (internal: true)|
|   - artex                  |                           |   - waf                   |
|   - postgres (16-alpine)   |                           |   - edge                  |
+----------------------------+                           |   - identity              |
                                                         |   - workflow              |
                                                         |   - records (canary)      |
                                                         +---------------------+-----+
                                                                               |
                                                         +---------------------v-----+
                                                         | control_net (internal: true)
                                                         |   - edge                  |
                                                         |   - identity              |
                                                         |   - workflow              |
                                                         |   - records               |
                                                         |   - defender (ML detector)|
                                                         +---------------------------+
```

### 1.2 Mandatory Isolation Invariants

1. **Host Boundary:** Only `artex` (`127.0.0.1:8787`, `127.0.0.1:8788`) and `waf` (`127.0.0.1:8080`) publish ports to the Windows host loopback. No target microservice or database container shall expose any host port.
2. **Network Segmentation:**
   - `artex` attaches exclusively to `ingress_net` and `db_net`.
   - `artex` MUST NOT attach to `proxy_net`, `control_net`, or Docker's default bridge.
   - All backend microservices (`edge`, `identity`, `workflow`, `records`) attach exclusively to `proxy_net` and `control_net`.
   - `defender` attaches exclusively to `control_net`.
3. **Egress Air-Gapping:** Networks `db_net`, `proxy_net`, and `control_net` carry `internal: true`, blocking all external Internet routing. `ingress_net` is non-internal only to permit `artex` egress to `host.docker.internal:1234` (LM Studio).

---

## 2. Docker Compose Specification (`lab/compose.yml`)

The override file merges with upstream `ARTEX/docker-compose.yml`. Sequence overrides MUST use `ports: !override` to eliminate the upstream `0.0.0.0:8787` binding.

```yaml
version: "3.8"

networks:
  ingress_net:
    driver: bridge
    internal: false
  db_net:
    driver: bridge
    internal: true
  proxy_net:
    driver: bridge
    internal: true
  control_net:
    driver: bridge
    internal: true

services:
  # Upstream Service Overrides
  artex:
    ports: !override
      - "127.0.0.1:8787:8787"
      - "127.0.0.1:8788:8788"
    networks:
      - ingress_net
      - db_net
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ./skills/demo-api-chain:/app/skills/demo-api-chain:ro
    environment:
      - ARTEX_LLM_PROVIDER=openai
      - ARTEX_LLM_MODEL=artex-local
      - ARTEX_LLM_BASE_URL=http://host.docker.internal:1234/v1
      - OPENAI_API_KEY=lm-studio
      - POSTGRES_HOST=postgres
      - POSTGRES_PORT=5432
      - POSTGRES_USER=${POSTGRES_USER:-artex}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-artex-demo-local}
      - POSTGRES_DB=${POSTGRES_DB:-artex}

  postgres:
    networks:
      - db_net
    environment:
      - POSTGRES_USER=${POSTGRES_USER:-artex}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-artex-demo-local}
      - POSTGRES_DB=${POSTGRES_DB:-artex}

  # Ingress Proxy / WAF
  waf:
    image: owasp/modsecurity-crs:4-nginx-alpine
    container_name: demo-waf
    ports:
      - "127.0.0.1:8080:8080"
    networks:
      - ingress_net
      - proxy_net
    environment:
      - PARANOIA=1
      - PORT=8080
      - BACKEND=http://edge:8000
    volumes:
      - ./waf/nginx.conf:/etc/nginx/templates/conf.d/default.conf.template:ro
      - ./waf/rules/active-patch.conf:/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-DEMO-VIRTUAL-PATCH.conf
      - ./waf/rules:/etc/modsecurity.d/rules-storage:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/healthz"]
      interval: 5s
      timeout: 3s
      retries: 3

  # Target Service Stubs (Single Python Image, Parameterized Role)
  edge:
    build:
      context: ./lab/stubs
      dockerfile: Dockerfile
    container_name: demo-edge
    networks:
      - proxy_net
      - control_net
    environment:
      - SERVICE_ROLE=edge
      - SERVICE_PORT=8000
      - DEFENDER_URL=http://defender:9000/ingest
      - CONTROL_TOKEN=demo-control-local
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/healthz"]
      interval: 5s
      timeout: 2s
      retries: 3

  identity:
    build:
      context: ./lab/stubs
      dockerfile: Dockerfile
    container_name: demo-identity
    networks:
      - proxy_net
      - control_net
    environment:
      - SERVICE_ROLE=identity
      - SERVICE_PORT=8000
      - DEFENDER_URL=http://defender:9000/ingest
      - CONTROL_TOKEN=demo-control-local
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/healthz"]
      interval: 5s
      timeout: 2s
      retries: 3

  workflow:
    build:
      context: ./lab/stubs
      dockerfile: Dockerfile
    container_name: demo-workflow
    networks:
      - proxy_net
      - control_net
    environment:
      - SERVICE_ROLE=workflow
      - SERVICE_PORT=8000
      - DEFENDER_URL=http://defender:9000/ingest
      - CONTROL_TOKEN=demo-control-local
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/healthz"]
      interval: 5s
      timeout: 2s
      retries: 3

  records:
    build:
      context: ./lab/stubs
      dockerfile: Dockerfile
    container_name: demo-records
    networks:
      - proxy_net
      - control_net
    environment:
      - SERVICE_ROLE=records
      - SERVICE_PORT=8000
      - DEFENDER_URL=http://defender:9000/ingest
      - CONTROL_TOKEN=demo-control-local
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/healthz"]
      interval: 5s
      timeout: 2s
      retries: 3

  # AI / ML Local Defender
  defender:
    build:
      context: ./lab/defender
      dockerfile: Dockerfile
    container_name: demo-defender
    networks:
      - control_net
    environment:
      - DEFENDER_PORT=9000
      - IDENTITY_URL=http://identity:8000/internal/revoke
      - WORKFLOW_URL=http://workflow:8000/internal/revoke
      - RECORDS_URL=http://records:8000/internal/revoke
      - CONTROL_TOKEN=demo-control-local
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/healthz"]
      interval: 5s
      timeout: 2s
      retries: 3
```

---

## 3. Microservice Stubs & API Contracts (`lab/stubs/`)

All four target roles (`edge`, `identity`, `workflow`, `records`) are served by a single, stateless Python FastAPI application. The active role is designated by the `SERVICE_ROLE` environment variable.

### 3.1 Token Lineage Format

Correlation is deterministic because each hop preserves the same randomly generated run identifier (`<run_id>`: 8 lowercase hex characters). These tokens are synthetic demo values: services check the expected token prefix and run-id format, but the values are not cryptographic credentials.
- Hop 1 (`edge`): mints `edge_tok_<run_id>`
- Hop 2 (`identity`): validates `edge_tok_<run_id>`, mints `wf_tok_<run_id>`
- Hop 3 (`workflow`): validates `wf_tok_<run_id>`, mints `rec_tok_<run_id>`
- Hop 4 (`records`): validates `rec_tok_<run_id>`, authorizes canary access

### 3.2 External API Contract (Mediated by WAF)

#### Hop 1: Edge Entry Point
* **Endpoint:** `GET /api/edge`
  * **Response (200 OK):**
    ```json
    {
      "service": "edge-gateway",
      "version": "1.4.2",
      "status": "operational",
      "endpoints": ["/api/edge/export"]
    }
    ```
* **Endpoint:** `POST /api/edge/export`
  * **Payload (JSON):**
    ```json
    {"format": "csv", "include_tokens": true}
    ```
  * **Vulnerability Trigger:** `include_tokens: true`
  * **Response (200 OK):**
    ```json
    {
      "status": "success",
      "run_id": "c3a9f012",
      "token": "edge_tok_c3a9f012",
      "next_hop": "/api/identity/exchange",
      "hint": "Exchange edge token for workflow access"
    }
    ```

#### Hop 2: Identity Exchange
* **Endpoint:** `POST /api/identity/exchange`
  * **Headers:** `Authorization: Bearer edge_tok_<run_id>`
  * **Response (200 OK):**
    ```json
    {
      "status": "authenticated",
      "run_id": "c3a9f012",
      "role": "workflow-operator",
      "token": "wf_tok_c3a9f012",
      "next_hop": "/api/workflow/pivot"
    }
    ```
  * **Response (403 Forbidden - if revoked):**
    ```json
    {
      "status": "error",
      "error": "token_revoked_by_defender",
      "run_id": "c3a9f012"
    }
    ```

#### Hop 3: Workflow Pivot
* **Endpoint:** `POST /api/workflow/pivot`
  * **Headers:** `Authorization: Bearer wf_tok_<run_id>`
  * **Response (200 OK):**
    ```json
    {
      "status": "dispatched",
      "run_id": "c3a9f012",
      "target": "records-tier",
      "token": "rec_tok_c3a9f012",
      "next_hop": "/api/records/canary"
    }
    ```
  * **Response (403 Forbidden - if revoked):**
    ```json
    {
      "status": "error",
      "error": "token_revoked_by_defender",
      "run_id": "c3a9f012"
    }
    ```

#### Hop 4: Critical Records Asset
* **Endpoint:** `GET /api/records/canary`
  * **Headers:** `Authorization: Bearer rec_tok_<run_id>`
  * **Response (200 OK - Baseline Success):**
    ```json
    {
      "status": "access_granted",
      "run_id": "c3a9f012",
      "canary": "CANARY_CONFIDENTIAL_ALPHA_7739",
      "classification": "TOP_SECRET_SIMULATED",
      "timestamp": "2026-11-08T14:30:00Z"
    }
    ```
  * **Response (403 Forbidden - if revoked):**
    ```json
    {
      "status": "error",
      "error": "token_revoked_by_defender",
      "run_id": "c3a9f012"
    }
    ```

### 3.3 Synchronous Telemetry Ingestion Contract (`control_net`)

For each token-bearing hop (`/api/edge/export` through `/api/records/canary`), the stub awaits an HTTP `POST` to `http://defender:9000/ingest` with a **100ms client timeout**. The metadata discovery `GET /api/edge` has no `run_id` and is not included in telemetry. Delivery is best-effort: the stub continues if the defender is unavailable or times out, so this is not a guaranteed ingestion SLA.

```json
{
  "timestamp": "2026-11-08T14:30:02.104Z",
  "run_id": "c3a9f012",
  "service": "identity",
  "route": "/api/identity/exchange",
  "method": "POST",
  "token_presented": "edge_tok_c3a9f012",
  "status_code": 200,
  "client_ip": "172.28.0.3"
}
```

### 3.4 Internal Control Endpoints (control-plane header required)

The endpoints are not host-published and require `X-Control-Token` (default local-demo value: `demo-control-local`). Defender and reset-script calls originate on the internal networks. This is a demo guard, not production credential management.

* `POST /internal/revoke`
  * **Header:** `X-Control-Token: demo-control-local`
  * **Payload:** `{"run_id": "<run_id>"}`
  * **Action:** Adds `<run_id>` to in-memory set `revoked_runs`.
  * **Response:** `200 OK` `{"status": "revoked", "run_id": "<run_id>"}`
* `POST /internal/reset`
  * **Header:** `X-Control-Token: demo-control-local`
  * **Payload:** `{}`
  * **Action:** Clears that stub's in-memory revocation list. The defender's separate header-gated reset clears its run trackers and event history.
  * **Response:** `200 OK` `{"status": "reset_complete"}`

---

## 4. WAF & Virtual Patch Specification (`lab/waf/`)

The ingress proxy uses the official OWASP ModSecurity Core Rule Set container (`owasp/modsecurity-crs:4-nginx-alpine`).

### 4.1 Custom Routing Template (`lab/waf/nginx.conf`)

Mounted at `/etc/nginx/templates/conf.d/default.conf.template`:

```nginx
server {
    listen 8080 default_server;
    server_name _;

    # Health check bypass
    location = /healthz {
        access_log off;
        return 200 '{"status":"healthy","service":"waf"}\n';
        add_header Content-Type application/json;
    }

    # Edge Gateway Routing
    location = /api/edge {
        proxy_pass http://edge:8000/api/edge;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /api/edge/ {
        proxy_pass http://edge:8000/api/edge/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Identity Service Routing
    location /api/identity/ {
        proxy_pass http://identity:8000/api/identity/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Workflow Service Routing
    location /api/workflow/ {
        proxy_pass http://workflow:8000/api/workflow/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Records Service Routing
    location /api/records/ {
        proxy_pass http://records:8000/api/records/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 4.2 ModSecurity Virtual Patch Rule (Rule ID `99001`)

The active virtual patch file is mounted read-write at `/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-DEMO-VIRTUAL-PATCH.conf`. Source rules are mounted read-only under `/etc/modsecurity.d/rules-storage/`.

#### Detection Mode (Runs A & C)
File: `lab/waf/rules/rule-99001-detect.conf`
```apache
SecRule REQUEST_HEADERS:Content-Type "@contains application/json" "id:99000,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_URI "@streq /api/edge/export" "id:99001,phase:2,pass,log,msg:'DEMO VIRTUAL PATCH (DETECT ONLY): Unauthorized token export attempt',tag:'c-suite-demo',severity:'WARNING',chain"
    SecRule REQUEST_METHOD "@streq POST" "chain"
        SecRule ARGS:include_tokens "@streq true"
```

#### Blocking Mode (Runs B & D)
File: `lab/waf/rules/rule-99001-block.conf`
```apache
SecRule REQUEST_HEADERS:Content-Type "@contains application/json" "id:99000,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_URI "@streq /api/edge/export" "id:99001,phase:2,deny,status:403,log,msg:'DEMO VIRTUAL PATCH (BLOCKED): Unauthorized token export attempt',tag:'c-suite-demo',severity:'CRITICAL',chain"
    SecRule REQUEST_METHOD "@streq POST" "chain"
        SecRule ARGS:include_tokens "@streq true"
```

### 4.3 Rule Switch Procedure

To toggle between detection and blocking modes without restarting the WAF container. The active file is writable; the source rules remain read-only:

```bash
# Switch to BLOCK mode
docker compose exec -u root waf cp /etc/modsecurity.d/rules-storage/rule-99001-block.conf /etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-DEMO-VIRTUAL-PATCH.conf
docker compose exec -u root waf nginx -s reload

# Switch to DETECT mode
docker compose exec -u root waf cp /etc/modsecurity.d/rules-storage/rule-99001-detect.conf /etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-DEMO-VIRTUAL-PATCH.conf
docker compose exec -u root waf nginx -s reload
```

---

## 5. Machine Learning Defender Specification (`lab/defender/`)

The ML Defender is a lightweight Python service executing an `sklearn.ensemble.IsolationForest` anomaly detector. It consumes synchronous events from `control_net` and issues active revocation calls when abnormal traversal sequences occur.

### 5.1 Anomaly Feature Vector Definition

For any active `run_id`, the defender computes a 5-dimensional feature vector $\vec{x}$:

$$ \vec{x} = \begin{bmatrix} x_1 \\ x_2 \\ x_3 \\ x_4 \\ x_5 \end{bmatrix} $$

Where:
* $x_1$ (**Hop Depth**): Cumulative count of requests associated with this `run_id`.
* $x_2$ (**Distinct Services**): Count of unique services accessed ($\in [1, 4]$).
* $x_3$ (**Pivot Velocity**): Inverse of elapsed seconds since previous hop: $\frac{1}{\Delta t + 0.001}$.
* $x_4$ (**Route Sensitivity Weight**):
  * `/api/edge` = $0.1$
  * `/api/edge/export` = $0.5$
  * `/api/identity/exchange` = $0.8$
  * `/api/workflow/pivot` = $0.9$
  * `/api/records/canary` = $1.0$
* $x_5$ (**Token Transition Validity**): Binary flag ($0.0$ if strictly monotonic $1 \rightarrow 2 \rightarrow 3 \rightarrow 4$, $1.0$ if out of order).

### 5.2 Detector Calibration & Threshold

* **Algorithm:** `IsolationForest(n_estimators=100, contamination=0.1, random_state=42)`
* **Training Data:** Synthesized on service initialization: 1,000 low-volume samples plus 50 rapid cross-service samples. These seeded examples make the demo repeatable; they do not establish detection accuracy on unseen traffic.
* **Decision Boundary:**
  * `score = model.decision_function([features])[0]`
  * Contain when `x_1 >= 2` and either `score < -0.15`, the request is out of order, or a high-sensitivity cross-service pivot arrives within 20 seconds. The explicit threshold keeps this small demo repeatable; record the observed score and hop during acceptance.

### 5.3 Automated Revocation Action

When an anomaly is detected:
1. Marks `run_id` as `CONTAINED` in in-memory registry.
2. Makes best-effort, concurrent calls to `identity`, `workflow`, and `records` at `/internal/revoke` with `{"run_id": run_id}`. This ensures the records service also rejects a token if detection occurs during the workflow hop.
3. Each revocation call has a 100ms timeout. Treat `<20 ms` as a measured demo target, not a hard guarantee; the lab fails open if the defender or a service is unavailable. Verify that the next hop returns 403 in T-5.

### 5.4 Defender Status API & Dashboard (`GET /status`)

`GET /status` is available only on `control_net`; the WAF does not proxy to the defender. For a simple local demo read, use `docker compose -f docker-compose.yml -f lab/compose.yml exec defender curl -s http://localhost:9000/status`. The response contains `state`, `active_run_id`, `hop_count`, `distinct_services`, `anomaly_score`, `contained`, and `recent_events`. It does not report a confidence percentage or guarantee that revocation calls succeeded; confirm containment with the next hop's 403 response.

---

## 6. ARTEX Integration & Agent Skill Specification

### 6.1 ARTEX Demo Skill (`skills/demo-api-chain/SKILL.md`)

This skill is bind-mounted directly into the container at `/app/skills/demo-api-chain/SKILL.md`. It forces the Worker agent to execute the chain sequentially via `WebFetch` within a **single worker intent**, preventing multi-turn decomposition delays.

```markdown
---
name: demo-api-chain
description: Execute sequential API exploitation chains against target HTTP endpoints using WebFetch
---

# Demo API Chain Skill

When tasked with assessing target APIs under `http://waf:8080/api/`:

1. **Strictly execute in a single intent.** Do NOT invoke `nmap`, `whois`, `dig`, or port-scanning tools.
2. **Hop 1 (Discovery & Export):**
   - Fetch `http://waf:8080/api/edge` via `WebFetch`.
   - Post to `http://waf:8080/api/edge/export` with JSON body `{"format": "csv", "include_tokens": true}`.
   - Extract `token` (format: `edge_tok_<run_id>`) and `next_hop`.
3. **Hop 2 (Exchange):**
   - Post to `http://waf:8080` + `next_hop` with Header `Authorization: Bearer <edge_tok>`.
   - Extract `token` (format: `wf_tok_<run_id>`) and `next_hop`.
4. **Hop 3 (Pivot):**
   - Post to `http://waf:8080` + `next_hop` with Header `Authorization: Bearer <wf_tok>`.
   - Extract `token` (format: `rec_tok_<run_id>`) and `next_hop`.
5. **Hop 4 (Asset Retrieval):**
   - Fetch `http://waf:8080` + `next_hop` with Header `Authorization: Bearer <rec_tok>`.
   - Record canary value in finding summary.
6. **Defense Interruption Handling:**
   - If any hop returns HTTP status `403 Forbidden`, DO NOT attempt payload re-encoding, WAF bypass, or fuzzing.
   - Stop immediately. For the edge export block, report HTTP 403 as a virtual-patch block; the operator can confirm Rule 99001 in the WAF log. For a defender block, record the `token_revoked_by_defender` response. Do not rely on a custom WAF response body.
```

### 6.2 ARTEX Scope & Non-Evasion Constraint

To prevent the ARTEX `guard/guard.go` Observer from triggering automatic WAF-bypass loops upon encountering HTTP 403 responses, inject the following task constraint via the ARTEX task definition API:

```json
{
  "name": "c_suite_single_pass_constraint",
  "type": "deny",
  "content": "Single-pass validation: Do not attempt payload obfuscation, retry loops, or WAF evasions if HTTP 403 Forbidden is encountered. Record the defense block as a verified control finding and conclude."
}
```

---

## 7. Rehearsal Runbook & Operational Scripts

### 7.1 LM Studio Host Verification Script (`lab/scripts/test-model-hop.sh`)

Verifies the container-to-host bridge before launching the lab.

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "[*] Checking LM Studio API connectivity from container via host.docker.internal:1234..."
docker run --rm curlimages/curl -s --connect-timeout 3 http://host.docker.internal:1234/v1/models > /dev/null || {
    echo "[!] ERROR: Cannot reach LM Studio at http://host.docker.internal:1234/v1/models"
    echo "[!] Ensure LM Studio local server is started and Windows firewall permits WSL connections."
    exit 1
}

echo "[+] Success: LM Studio is reachable from container network."
```

### 7.2 Reset Script (`lab/scripts/reset-demo.sh`)

The included script resets target stubs and defender state, then configures the requested WAF mode without terminating PostgreSQL or ARTEX. Reset duration depends on Docker and is not a timing guarantee. Run it from the ARTEX checkout root as `./lab/scripts/reset-demo.sh baseline|patch|defender|combined`; it uses both the upstream Compose file and this override so it targets the running lab project.

---

## 8. Verification & Acceptance Test Matrix

| Verification Test | Command / Probe | Expected Outcome | Pass/Fail Criteria |
|---|---|---|---|
| **T-1: Network Isolation** | Run `docker compose -f docker-compose.yml -f lab/compose.yml config` and inspect `db_net`, `proxy_net`, and `control_net`; confirm each is `internal: true` and no target publishes a host port. | Compose shows the internal networks and no backend port mappings. | Pass: Configuration proves the intended egress boundary; a failed ping alone is not accepted as proof. |
| **T-2: Route Isolation** | Inspect the merged Compose config for the `artex` service. | `artex` is attached only to `ingress_net` and `db_net`, with no default, `proxy_net`, or `control_net`. | Pass: ARTEX has no direct network path to stubs or defender. |
| **T-3: Run A (Baseline)** | Launch ARTEX task `demo-api-chain` with WAF in detection mode. | Canary returned in `< 75` seconds; all 4 hops logged with matching `run_id`. | Pass: Full traversal succeeds. |
| **T-4: Run B (Virtual Patch)**| `./lab/scripts/reset-demo.sh patch` $\rightarrow$ Launch task. | WAF returns HTTP 403 on `/api/edge/export`; Rule 99001 logged; ARTEX halts cleanly. | Pass: Ingress blocked; zero target code touched. |
| **T-5: Run C (ML Defender)** | `./lab/scripts/reset-demo.sh defender` $\rightarrow$ Launch task. | Record the observed anomaly score and hop. The next protected hop returns 403 with `token_revoked_by_defender`; ARTEX halts cleanly. | Pass: The next hop is denied, including records if detection occurs during workflow. |
| **T-6: Run D (Combined)** | `./lab/scripts/reset-demo.sh combined` $\rightarrow$ Launch task. | Request is blocked at WAF with HTTP 403 and Rule 99001 in the WAF log; defender remains IDLE because the request never reached a stub. | Pass: Ingress block is confirmed and no run was ingested. |
