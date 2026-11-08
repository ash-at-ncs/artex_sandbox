# ARTEX, contained and observable

## Low-overhead Docker lab for a five-minute C-suite demonstration

Planning document · 8 November 2026

## Decision

Replace the CyberBattleSim-only demo with a real ARTEX run against a small, purpose-built, multi-service lab. CyberBattleSim may remain an optional explainer, but it cannot run ARTEX. The proposed lab uses ARTEX’s real agent and tool-call trace, harmless service stubs, a live reverse-proxy virtual patch, and a small local machine-learning defender.

## Can this meet the three goals?

| Goal | Demo evidence | Scope |
|---|---|---|
| Show spread speed | Real elapsed seconds and time-to-each-service from ARTEX activity plus target audit logs; repeat the same seeded scenario. | Application/service traversal across four containers. It does not claim Windows domain or endpoint compromise. |
| Show what the attack looks like | ARTEX session/tool-call view beside a timestamped event timeline and service map. | Actual ARTEX actions against synthetic targets, not fabricated simulator actions. |
| Counter with defenses | Turn on a ModSecurity virtual patch, then an ML detector that revokes the synthetic session. Show each stopping the same chain. | Controls act on running demo services. They are local lab controls, not production integrations. |

## Workstation check

| Item | Observed | Impact |
|---|---|---|
| Windows 11 Pro | Build 26300 | WSL 2 and Docker Desktop are installed. |
| CPU / memory | Intel i9-13900K; 32 logical CPUs; 63.7 GB RAM | Plenty for a small emulated lab and local inference. |
| GPU | RTX 4090; 24,564 MiB reported by nvidia-smi | Fits GPT-OSS 20B at a 32K context window (~14–16 GiB with KV cache; LM Studio estimates 12.23 GiB at 8K). |
| Disk | E: has 2,246 GB free | Place Linux checkout and Docker data on E: or WSL Linux home. |
| Current readiness | Ubuntu and docker-desktop WSL distros are stopped; Docker CLI 29.7.2 cannot reach its daemon. LM Studio lists 19 local models using 239.08 GB; no model is loaded now. | Start Docker Desktop/WSL and LM Studio’s local API server before rehearsal. No lab containers are running now. |

Recommended initial Docker Desktop budget: 8 vCPU, 12–16 GB RAM, 25 GB free for images/build cache. Leave the LM Studio model on the Windows host and budget its measured GPU memory separately. These are planning allocations; the lab itself should use only a fraction of host capacity.

## 1. Small, real attack surface

Use containers rather than VMs. One small Python image is reused for four service roles, keeping the footprint low while producing separate service identities and audit events. Each stub has deterministic, harmless behavior; no real CVE or host-level exploit is needed.

~~~text
Windows host (localhost only)
  ARTEX UI :8787 / Proxy :8788     WAF demo :8080     LM Studio API :1234
                |                        |                     |
                +----> ingress_net <-----+---------------------+
                |      (host-routable bridge; no stub attachment)
                |                        |
       db_net (internal)        proxy_net (internal)
                |                        |
             Postgres         edge / identity / workflow / records
                                         |
                                control_net (internal)
                                         |
                                    ML defender
~~~

| Service | Role in the story | What it records / exposes |
|---|---|---|
| edge | Initial entry point; mock export/API weakness reveals a synthetic service token (`edge_tok_<run_id>`). | Run ID, route, actor/session, response class, next-hop WAF path. |
| identity | Accepts the demo token and returns a short-lived workflow credential (`wf_tok_<run_id>`). | Token use, failed authentication, revoke state. |
| workflow | Represents an internal service that can reach the records tier (`rec_tok_<run_id>`). | Cross-service call and synthetic privilege boundary. |
| records | Critical asset with one synthetic canary record, no customer data. | Whether the final read was allowed; never returns real secrets. |
| WAF | ModSecurity + OWASP Core Rule Set reverse proxy with path-based Nginx routing to the four stubs. | Detection/block event and rule ID across all four `/api/<role>/` paths. |
| ML defender | Small Python service using scikit-learn IsolationForest over synchronous webhook events on `control_net`. | Anomaly score, reason features, revocation action and time. |

### Network boundaries and safety

The upstream `docker-compose.yml` defines no networks; `artex` and `postgres` share Compose's default bridge, and `artex` publishes `8787:8787` on all interfaces. The segmentation below is therefore work the override file must create, not a setting that already exists. It is described precisely so the claim on screen matches what is actually enforced.

- **Use `!override` on `ports:`**: Docker Compose concatenates sequence fields like `ports:` across override files by default. In `lab/compose.yml`, use `ports: !override` on `artex` (`127.0.0.1:8787:8787` and `127.0.0.1:8788:8788`) so the upstream `0.0.0.0:8787` binding is replaced rather than retained alongside `127.0.0.1:8787`. Bind the WAF demo listener to `127.0.0.1:8080:8080`. No backend service (`edge`, `identity`, `workflow`, `records`, `postgres`, `defender`) publishes any host port.
- **Define four Docker networks (`ingress_net`, `db_net`, `proxy_net`, `control_net`)**:
  1. `ingress_net` (`internal: false`): `artex` and `waf` only. Keeping `ingress_net` non-internal preserves the bridge gateway required for `artex` to reach `host.docker.internal:1234` (LM Studio) and for host loopback port publishing (`127.0.0.1:8787`, `127.0.0.1:8080`).
  2. `db_net` (`internal: true`): `artex` and `postgres` only. Separating `db_net` from `control_net` ensures `artex` never shares a Layer-2/Layer-3 network with the stubs or `defender`.
  3. `proxy_net` (`internal: true`): `waf` and the four stubs (`edge`, `identity`, `workflow`, `records`).
  4. `control_net` (`internal: true`): the four stubs and `defender` (for synchronous telemetry ingestion and token revocation).
  Reassign `artex` and `postgres` onto these networks explicitly so neither attaches to Compose's `default` bridge. ARTEX can reach the WAF (`http://waf:8080`) and PostgreSQL (`postgres:5432`) and nothing else inside the lab; it has zero network route to the stubs or `defender`.
- Mark `db_net`, `proxy_net`, and `control_net` `internal: true` so the database, target stubs, and ML defender have no outbound internet or host route. ARTEX is the one exception on `ingress_net`: it needs a route to the LM Studio API on the Windows host (see below), so it is not fully air-gapped. State this plainly in the demo rather than claiming blanket isolation.
- Do not mount the Docker socket, host files, credentials, or real data into any target or defender container. Use synthetic names and a single canary value.
- Keep model access local. Point ARTEX at LM Studio through the host gateway, and restrict the Windows firewall so port 1234 is reachable only from the WSL/Docker subnet, not the LAN. The one external-facing dependency of the whole lab is this single host-to-host call from ARTEX to the model.

Boundary of the claim: the demo represents application/API trust traversal, with one documented host route (ARTEX to the local model). A later phase is needed for domain, endpoint, or operating-system lateral movement; that would use a tighter-scope VM range, not this first low-resource build.

## 2. One attack, three control states

Give ARTEX one explicit in-scope URL (`http://waf:8080/api/edge`) and a bounded task: map that entry surface, follow only the next-hop `/api/<role>/...` paths returned by the demo APIs, and stop after the synthetic canary is reached or a defense blocks the chain. ARTEX makes the real sequential requests; the WAF container uses a custom Nginx location template to route exact `/api/edge` plus `/api/edge/`, `/api/identity/`, `/api/workflow/`, and `/api/records/` to their respective backend containers on `proxy_net` and records each path. The agent never has direct network access to target containers; its only host access is the local LM Studio API. The local model supplies real ARTEX planning/tool calls.

### Handling ARTEX's built-in scope and WAF-bypass hooks (`guard/guard.go`)

Two codebase behaviors in ARTEX require explicit configuration in the demo setup:

1. **No hard-coded URL RoE filter**: ARTEX removed its hard-coded Rules of Engagement (RoE) URL filter in `guard/guard.go`; scope is enforced by prompt constraints (`agent/constraints.go`) plus network isolation. The four-network topology (`proxy_net` and `control_net` isolated from `artex`) provides the hard containment boundary, while task constraints keep the LLM focused on `http://waf:8080`.
2. **Preventing automatic WAF-bypass loops (`postToolUse` G5 Observer)**: ARTEX's `guard/guard.go` inspects `Bash` outputs matching `(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b` and tags them as `blocked` specifically to prompt the Planner to pivot strategies and attempt WAF bypasses/encodings. In Runs B, C, and D, we want ARTEX to recognize and report the defense block cleanly rather than spinning in a multi-minute evasion loop. Seed the task with an explicit `type=deny` constraint (`set_constraints`): *"Single-pass control validation: do not attempt payload re-encoding, WAF bypass, or brute-force retries when a hop returns HTTP 403; record the status and Rule 99001 from the WAF log, or the `token_revoked_by_defender` response, then conclude the run."*

| Hop | Observable event | Success criterion |
|---|---|---|
| 1. Entry | ARTEX discovers `/api/edge/export` via WAF and makes the mock export request. | Edge request appears in ARTEX trace and JSON audit; issues `edge_tok_<run_id>`. |
| 2. Identity | ARTEX uses `edge_tok_<run_id>` at `/api/identity/exchange` exposed by WAF. | Identity records token use and issues workflow-scoped `wf_tok_<run_id>`. |
| 3. Workflow | ARTEX follows `/api/workflow/pivot` and presents `wf_tok_<run_id>`. | Workflow records the cross-service pivot and issues `rec_tok_<run_id>`. |
| 4. Critical asset | ARTEX presents `rec_tok_<run_id>` at `/api/records/canary`. | Records logs allow/deny and returns only a harmless canary marker. |

### Control experiments

| Run | WAF virtual patch | AI/ML response | Expected visible outcome |
|---|---|---|---|
| A Baseline | Detection-only; log the known mock weakness. | Observe only. | Chain reaches canary. Capture real ARTEX time and exact event order. |
| B Virtual patch | Enable a narrow local rule for the demo route/parameter. | Observe only. | WAF blocks the known request before identity; show rule ID and no app-code change. |
| C AI defender | Detection-only for the WAF. | Score the sequence of unusual cross-service requests; revoke the synthetic `<run_id>` in `identity`, `workflow`, and `records` concurrently at the configured threshold. | First hops are visible; next protected request is denied (`403 token_revoked_by_defender`). Show alert, rationale, revoke event. |
| D Combined | Patch enabled. | Detector remains active. | Known exploit path is blocked at ingress; defender provides independent visibility if the attempt pattern changes. |

Virtual patch is a real proxy rule on a running lab service. The ML response is a real local action against the lab identity/workflow services. The detector is a small custom scikit-learn model, not a claim that a commercial AI product has been integrated.

### Measures to put on screen

- Wall-clock time from ARTEX task start to first access at each service; median of three pre-run repetitions, with one live run shown.
- Number of distinct service hops and whether the synthetic critical asset was reached.
- WAF block point/rule; ML alert point, score/features, token-revocation action, and whether the next hop was prevented.
- **Deterministic correlation via token-embedded `run_id`**: Rather than relying on the LLM to generate and forward an `X-Request-ID` header across four separate tool calls, the `edge` stub mints a `run_id` inside the initial synthetic token (`edge_tok_<run_id>`) and each downstream service preserves that `<run_id>` suffix in subsequent tokens (`wf_tok_<run_id>`, `rec_tok_<run_id>`) and JSON logs. ARTEX’s own wall-clock times the task; downstream service and defender timestamps correlate every hop deterministically by `run_id`.

## 3. Five-minute C-suite run

Realistic timing note: ARTEX uses a multi-agent loop (`MainAgent` → `Planner` → `Worker`, plus graph-recording tool calls like `insert_assets` and `record_finding` between intents). Left unconstrained on a local 20B model, decomposing four hops into separate Planner rounds takes 12–18 LLM turns (3–5 minutes), and running all four control states live will not fit inside five minutes.

To keep the live baseline segment reliably inside the **75-second window (`0:30–1:45`)**:
1. **Mount a focused demo skill (`./skills/demo-api-chain/SKILL.md`)**: Upstream `docker-compose.yml` bind-mounts `./skills:/app/skills`. Provide a concise skill instructing the Worker to execute the 4-hop API chain sequentially within a **single worker intent** using `WebFetch` (which automatically routes through ARTEX's built-in `:8788` traffic-recording proxy so every request/response appears live in the UI) and explicitly skip `nmap`/`whois`/`dig` reconnaissance.
2. **Pre-stage the task before `0:00`**: Have the exploration task, goal, and `type=deny` non-evasion constraint pre-created and ready to launch with one click at `0:30`.
3. **Hybrid live + captured presentation**: The live element is the baseline run shown in real time (`0:30–1:45`) to prove it is genuinely ARTEX and genuinely local. The virtual-patch, ML-defender, and combined results are shown from the clean rehearsed capture (`1:45–4:25`). Every number on screen comes from a real rehearsed run, and the live baseline is the anchor the audience watches happen. Treat the minute markers below as targets, not guarantees.

| Time | Show | Narration / evidence |
|---|---|---|
| 0:00–0:30 | Scope and business map | “This is a local, synthetic service chain. ARTEX is the live agent. Only these demo containers are in scope.” Show four nodes and the canary asset. |
| 0:30–1:45 | Baseline run (live) | Start ARTEX’s bounded task live. Show its real plan/tool calls beside the service events. Call out elapsed seconds as each service is reached. This is the one segment the audience watches run in real time. |
| 1:45–2:35 | Virtual patch (captured) | Show the rehearsed WAF-rule run: the same ARTEX task stops at ingress. Show the block event and rule ID, and confirm the canary was not accessed. |
| 2:35–3:35 | AI defender (captured) | Show the rehearsed detector run: anomaly explanation, token revocation, and the denied next hop. |
| 3:35–4:25 | Combined controls (captured) | Display the side-by-side A/B/C/D outcomes from rehearsal on one panel. |
| 4:25–5:00 | Decision | Ask which product control or wider attack surface should be validated in a follow-on isolated range. State the demo’s app/API scope. |

### Rehearsal acceptance criteria

| Check | Pass condition |
|---|---|
| Attack | ARTEX reaches the canary in baseline within the rehearsed time window and leaves correlated trace/log records. |
| Virtual patch | Enabling the rule prevents the edge request from reaching identity; no target code change is made. |
| AI response | Detector alerts before the canary request and revokes the synthetic token; the workflow/records request is denied. |
| Repeatability | Three reset runs produce the same service order; report time spread rather than one cherry-picked value. |
| Isolation | Targets have no host-published ports or external egress; ARTEX task scope contains only the lab hostname. |
| Fallback | Prepared screen recording and precomputed comparison panel are ready if local model latency varies. |

## 4. Build and run on this Windows machine

Use Docker Desktop’s WSL 2 backend and keep the working tree inside Ubuntu’s Linux filesystem for reliable build performance. The current Ubuntu distro exists but is stopped; Docker Desktop’s Linux engine is installed but currently not running.

### Prepare the machine

~~~bash
# PowerShell
wsl --list --verbose
# Start Docker Desktop from the Start menu, then:
wsl -d Ubuntu

# In Ubuntu / WSL
mkdir -p ~/work/artex-range && cd ~/work/artex-range
docker version
docker compose version
~~~

In Docker Desktop, enable WSL integration for Ubuntu. Allocate about 8 CPUs and 12–16 GB memory to the Docker/WSL engine; leave the current networking settings in place initially. The existing .wslconfig uses mirrored networking, firewall, and DNS tunneling, with no explicit memory cap.

### Pin ARTEX and prepare the local model

~~~bash
cd ~/work/artex-range
git clone https://github.com/RuoJi6/ARTEX.git artex
cd artex
git checkout 459a4842374c6cc0f53a716d41eca907449ccbdd
# Use the matching released container tag v0.3.27; record its image digest.

# In the demo .env, include the mandatory Postgres variables (upstream compose fails
# without POSTGRES_PASSWORD) plus ARTEX's OpenAI Chat Completions settings for LM Studio:
ARTEX_IMAGE=ruoji6/artex
ARTEX_TAG=v0.3.27
POSTGRES_USER=artex
POSTGRES_PASSWORD=artex-demo-local
POSTGRES_DB=artex

ARTEX_LLM_PROVIDER=openai
ARTEX_LLM_MODEL=artex-local
ARTEX_LLM_BASE_URL=http://host.docker.internal:1234/v1
OPENAI_API_KEY=lm-studio
~~~

#### First fix: prove the container-to-model hop

Settle this one first, because everything downstream assumes it works. ARTEX runs in a container and must reach LM Studio bound on the Windows host at port 1234. The existing `.wslconfig` uses mirrored networking, under which `host.docker.internal` behaves differently from the default NAT mode and may not resolve to the host from inside the container. Validate with a throwaway container before building the rest:

~~~bash
# Start LM Studio's server on the host first, then from WSL:
docker run --rm curlimages/curl -s http://host.docker.internal:1234/v1/models
~~~

If that returns the model list, the plan works as written. If it does not, it is a quick fix, not a dead end, in this order: (1) add `extra_hosts: ["host.docker.internal:host-gateway"]` to the `artex` service in the override; (2) bind LM Studio to the WSL interface address and point `ARTEX_LLM_BASE_URL` at that IP; (3) run a small forwarding proxy bound only to the lab subnet. Settle it here so it is not discovered during rehearsal.

Load the cached model with a **32K context window** and start the local API server:

~~~powershell
lms load openai/gpt-oss-20b --context-length 32768 --gpu max --identifier artex-local
lms server start
lms ps
~~~

Why 32K instead of 8K: ARTEX's `agent/provider.go` enforces a minimum compaction window floor of `minWindowK = 32` (`32,000` tokens), its UI connection test (`TestConnection`) sends `MaxTokens: 8192` in the request payload, and its Planner/Worker system prompts plus tool schemas consume several thousand tokens before the first turn. Loading with `--context-length 8192` will fail `TestConnection` immediately and overflow on the first Planner/Worker turn. At 32K context, GPT-OSS 20B uses ~14–16 GiB of VRAM (with KV cache), which still fits comfortably inside this host’s 24.0 GiB RTX 4090. In ARTEX's UI LLM profile settings, set **Context Window** to `32` (32K), per-reply **MaxTokens** to `2048`, and **Thinking / Reasoning Effort** to `disabled` or `low` so local inference does not burn 2,000+ thinking tokens per turn during the live baseline run. The installed Qwen3.6 27B is a higher-capacity alternative; Qwen2.5 7B Instruct is the lower-memory fallback. No model download is needed for this plan.

### Build the demo-specific Docker images

Create this repo layout in WSL:

~~~text
skills/demo-api-chain/SKILL.md  # focused skill so Worker runs the 4-hop chain in one intent via WebFetch
lab/stubs/                      # one Python Dockerfile; edge, identity, workflow, records roles
lab/defender/                   # Python + scikit-learn detector, synchronous /ingest webhook, status UI
lab/waf/                        # CRS local virtual-patch rule + custom Nginx location routing to 4 stubs
lab/compose.yml                 # 4 isolated networks, ports: !override, localhost-only bindings
~~~

The override (`lab/compose.yml`) adds the `waf`, four stub, and `defender` services, defines the four networks (`ingress_net`, `db_net`, `proxy_net`, `control_net`), reassigns `artex` and `postgres` onto them (removing the default bridge), and replaces the `8787` port mapping using `ports: !override`. Order matters: `pull` only fetches images for services declared in one of the two files, so the WAF/stub/defender images must be built or pulled in their own steps, not folded into a `pull artex postgres waf` against the upstream file (which knows nothing of `waf`).

~~~bash
# Build local images first (stubs and detector are not on any registry).
docker build -t artex-range/stubs:0.1 ./lab/stubs
docker build -t artex-range/defender:0.1 ./lab/defender

# Pull only the pinned registry images this lab consumes.
docker pull ruoji6/artex:v0.3.27
docker pull postgres:16-alpine
docker pull owasp/modsecurity-crs:<pinned-tag>   # select and pin a digest

# Bring the full override up. Validate the merged config before starting.
docker compose -f docker-compose.yml -f lab/compose.yml config
docker compose -f docker-compose.yml -f lab/compose.yml up -d
~~~

Use the upstream ARTEX image to save build time; build the stubs and detector locally. Pin the OWASP CRS/ModSecurity image to a digest after selection. Run `compose ... config` once and read the merged output to confirm:
1. `artex.ports` contains **only** `127.0.0.1:8787:8787` and `127.0.0.1:8788:8788` (verifying `ports: !override` stripped `0.0.0.0:8787`).
2. `artex` is attached only to `ingress_net` and `db_net`, with zero attachment to `proxy_net`, `control_net`, or `default`.
3. `db_net`, `proxy_net`, and `control_net` carry `internal: true`.
Do not use `latest` in the final rehearsal manifest.

## 5. Implement the stubs and defense

Use one Python 3.12-slim image with a tiny HTTP framework and one process per role. A role is selected by environment variables, so four containers reuse the same image layers. The fixture contains only synthetic users, tokens and canary text. Make the intended chain deterministic: `edge` generates a `<run_id>` embedded in `edge_tok_<run_id>`, and each downstream service validates the incoming token, preserves `<run_id>` in the next issued token (`wf_tok_<run_id>`, `rec_tok_<run_id>`), returns the next `/api/<role>/...` WAF path, and synchronously posts the audit event (`POST http://defender:9000/ingest`, 100ms timeout) over `control_net` before returning its HTTP response. Keep `/internal/revoke` and `/internal/reset` off host ports and require the local demo `X-Control-Token`; defender/reset calls use the lab control network.

| Implementation part | Behavior |
|---|---|
| edge role | Serves `/api/edge` metadata and `/api/edge/export`. Mints `edge_tok_<run_id>` and returns `/api/identity/exchange`; cannot fetch arbitrary URLs or execute commands. |
| identity role | Accepts `edge_tok_<run_id>` at `/api/identity/exchange`, issues `wf_tok_<run_id>`, and supports revocation via `POST /internal/revoke` on `control_net`. |
| workflow role | Accepts `wf_tok_<run_id>` at `/api/workflow/pivot`, issues `rec_tok_<run_id>` (reusable within this synthetic demo), and honors revocation from `defender` on `control_net`; no general-purpose proxy or shell. |
| records role | Returns the synthetic canary at `/api/records/canary` only when a valid, unrevoked `rec_tok_<run_id>` is presented; records every allow/deny. |
| Audit schema | UTC timestamp, `run_id` (extracted from token lineage), service, actor/session, route class, result, previous hop, and response latency. Avoid storing secrets or full request bodies. |

### Virtual patch image/config

The WAF uses a custom Nginx template to route `/api/edge` (exact path) and `/api/edge/`, plus the identity, workflow, and records paths, to their services over `proxy_net`. For the demo flaw, Rule 99001 matches only `POST /api/edge/export` with JSON `include_tokens=true`. Detection mode logs and passes; blocking mode returns HTTP 403. The WAF response body is not customized: confirm the rule ID in the WAF log. Keep the default CRS rules and local demo rules in versioned files.

### AI defender image/config

This is a repeatable local demonstration, not field-validated detection. Keep the seeded IsolationForest score visible, and explain that an explicit threshold for rapid cross-service or out-of-order requests makes the containment run predictable.

Use a small scikit-learn IsolationForest service receiving synchronous `POST /ingest` events from the four stubs over `control_net`. It computes rolling features by `run_id`; a small explicit threshold for rapid cross-service or out-of-order requests makes the demo repeatable. On containment it concurrently calls `/internal/revoke` on identity, workflow, and records. Calls use a 100ms timeout and are best-effort; `<20ms` is a measured target, not a guarantee. The acceptance criterion is that the next hop is denied. The service must not receive Docker socket access or execute commands.

For a simple status view, keep `GET /status` on `control_net` only and read it with `docker compose -f docker-compose.yml -f lab/compose.yml exec defender curl -s http://localhost:9000/status` or container logs. Do not add a WAF proxy route: WAF is not attached to `control_net`. This view complements ARTEX’s trace and the WAF event log.

### Reset and replay

Provide a `reset-demo.sh` wrapper that resets only target, WAF, and detector state (`docker compose -f docker-compose.yml -f lab/compose.yml exec` calling `POST http://defender:9000/internal/reset` and each stub's `/internal/reset` with the control header, plus toggling the WAF virtual-patch mode and reloading Nginx), while leaving `./data` (`jwt.key`, SQLite transcripts) and the `pgdata` PostgreSQL volume intact so ARTEX session history and pre-staged task definitions remain available for review. Confirm container health before each run. Do not use a broad `docker system prune` or delete volumes.

Local-only views: ARTEX UI at `http://127.0.0.1:8787` (recording proxy on `127.0.0.1:8788`); WAF-protected demo surface at `http://127.0.0.1:8080`.

## 6. Resource plan, delivery sequence, and limits

| Component | Planning use | Notes |
|---|---|---|
| ARTEX + PostgreSQL | 2–4 GB RAM; 2–4 vCPU | Use the pinned upstream application image and PostgreSQL Alpine image. |
| Four Python service stubs | 0.5–1.0 GB RAM total | One shared local image, small synthetic state. |
| ModSecurity + CRS | 0.5–1.5 GB RAM | Proxy only; path-based Nginx routing to the four stubs; no full SIEM/indexer. |
| ML defender + local dashboard | 0.5–1.0 GB RAM | scikit-learn and synchronous `/ingest` webhook on `control_net`. |
| GPT-OSS 20B in LM Studio | ~14–16 GiB GPU memory at 32K context (12.23 GiB at 8K); 12.11 GB model file cached | Host has 24,564 MiB VRAM; 32K context required by ARTEX `minWindowK=32` and `TestConnection`. |
| Total planning envelope | About 5–8 GB RAM for containers, plus model runtime; 20–30 GB additional disk for images/build cache | The 239.08 GB LM Studio model collection is already on disk. Host capacity is ample; measure actual use on first start. |

### Build sequence

| Phase | Work | Exit evidence |
|---|---|---|
| 1. Bring up host and prove the model hop | Start Docker Desktop and Ubuntu WSL; load model at `--context-length 32768`; confirm a throwaway container can reach `host.docker.internal:1234/v1/models`. | `docker info` succeeds, container gets the model list, and ARTEX UI `TestConnection` passes. |
| 2. Build the range | Implement four stubs (`run_id` token lineage + `/ingest` webhook), four networks (`ingress_net`, `db_net`, `proxy_net`, `control_net`), WAF multi-service proxy, detector, and `reset-demo.sh`. | `docker compose config` confirms `ports: !override` on `127.0.0.1:8787` and `artex` has no route to `proxy_net` or `control_net`. |
| 3. Connect ARTEX | Pin source/image (`v0.3.27`); configure `.env` (including `POSTGRES_PASSWORD`); add `skills/demo-api-chain/SKILL.md` and `type=deny` non-evasion constraint. | ARTEX trace and `:8788` traffic proxy show real `WebFetch` requests to `http://waf:8080/api/...` in a single worker intent. |
| 4. Prove controls | Rehearse baseline, WAF virtual patch, ML revocation, and combined cases with `reset-demo.sh`. | Baseline reaches canary in <75s; Runs B/C/D stop cleanly on `403` without WAF-bypass retry loops. |
| 5. Rehearse executive story | Run three timed trials, capture event trace, prepare fallback recording, confirm 5-minute timing. | One-page results card and a repeatable five-minute run. |

### Important limitations

- This proves ARTEX behavior only on this specific synthetic application/API chain. It is not a measurement of how quickly ARTEX compromises arbitrary infrastructure.
- The detector is a small local ML demonstration. Its threshold and response are tuned for this fixture; it is not production detection validation.
- The WAF rule protects the represented route. It does not patch application code or establish broad vulnerability coverage.
- If the next executive question is Windows/AD spread, build a separate two-VM follow-on with snapshots and a dedicated virtual switch. Do not add that complexity to the first demo.

## References

- [ARTEX maintained source and deployment notes](https://github.com/RuoJi6/ARTEX)
- [ARTEX Docker Compose file](https://github.com/RuoJi6/ARTEX/blob/main/docker-compose.yml)
- [CyberBattleSim README](https://github.com/microsoft/CyberBattleSim) (optional context only; abstract simulation)
- [OWASP CRS container guidance](https://coreruleset.org/docs/1-getting-started/1-3-using-containers/)
- [OWASP CRS container installation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/)
- [scikit-learn IsolationForest reference](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [LM Studio CLI: list, load, GPU offload and memory estimates](https://lmstudio.ai/docs/cli)
- [LM Studio local API server](https://lmstudio.ai/docs/developer/core/server)
- [LM Studio tool use and supported models](https://lmstudio.ai/docs/developer/openai-compat/tools)

## Go / fix recommendation

**Go.** This is a containerized application/API traversal demo that builds on this machine. There is no no-go condition: the host has ample compute and disk, and every image and the model are already local, so nothing here can stop the demo, only shape how it is built. What remains is a short list of things to fix on the way up, each with a defined check, not gates that block progress:

| Fix | What to do | Confirmed when |
|---|---|---|
| Container-to-model hop | Prove ARTEX's container can reach LM Studio under mirrored WSL networking; load the model at 32K context (`--context-length 32768`) for ARTEX's `minWindowK=32` floor. | A throwaway container gets `/v1/models` and the ARTEX UI `TestConnection` passes. |
| Network segmentation | Define `ingress_net`, `db_net`, `proxy_net`, `control_net` and `ports: !override` in `lab/compose.yml`; reassign the upstream `artex`/`postgres` services. | `docker compose config` shows `127.0.0.1` bindings and `artex` with no route to `proxy_net`/`control_net`. |
| Live timing and retry loops | Bound execution with a focused `demo-api-chain` skill and a `type=deny` non-evasion constraint to avoid `guard.go` WAF-evasion loops; show one baseline run live, the rest from rehearsed capture. | Baseline reaches canary in the rehearsed window; Runs B/C/D stop cleanly without retry loops. |

Work the three fixes in order; the first is the one to settle before building the rest, since everything downstream assumes the model hop works. Keep VMs as a later, explicitly scoped extension for OS/domain lateral movement.

The previous CyberBattleSim-only story is superseded. Keep the simulator only if a side-by-side abstract-versus-live illustration is useful; it is not the engine for achieving these three objectives.
