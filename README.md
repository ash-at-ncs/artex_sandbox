# ARTEX Cyber Simulation & Agentic Defense Sandbox

[![Release](https://img.shields.io/badge/release-v2.4.0-turquoise.svg)](https://github.com/kostchei/artex_sandbox/releases)
[![CISA KEV](https://img.shields.io/badge/CISA-KEV%20Integrated-red.svg)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-blue.svg)](https://attack.mitre.org/)
[![WAF Virtual Patch](https://img.shields.io/badge/WAF-OWASP%20CRS%20v4-orange.svg)](https://coreruleset.org/)
[![Behavioral AI](https://img.shields.io/badge/defense-Zero--Trust%20ML-green.svg)](https://scikit-learn.org/)

A containerized cyber range and interactive visual simulation sandbox designed to evaluate **autonomous offensive AI agents** (ARTEX) and benchmark modern **agentic defense mechanisms** (OWASP ModSecurity virtual patching, zero-trust behavioral ML anomaly detection, honeytoken canary alarms, and lateral token revocation).

---

## Quickstart & Launching

### One-Click Launchers
To run the local sandbox server and automatically launch the interactive Wire Diagram simulation in your default browser:

- **Windows**: Double-click `start.bat` or run:
  ```cmd
  start.bat
  ```
- **macOS / Linux**: Run:
  ```bash
  chmod +x start.sh
  ./start.sh
  ```
- **Cross-Platform Python**:
  ```bash
  python start.py
  ```

Once launched, navigate to:
- **Wire Diagram Interactive Demo**: [http://localhost:8080/wire.html](http://localhost:8080/wire.html)
- **Tabular Range Operations Dashboard**: [http://localhost:8080/index.html](http://localhost:8080/index.html)

---

## Interactive Wire Diagram Simulation (`wire.html`)

![ARTEX Wire Diagram Simulation Demo](assets/wire_simulation_demo.gif)

A full-screen, GPU-accelerated cyber wire diagram built with pure HTML5, SVG straight circuit traces, and CSS alpha-masking across 30 enterprise infrastructure icons.

### Key Capabilities
1. **Multi-Instance Cluster Forests**:
   - Organically clusters 1–3 identical icons together (e.g. AWS Production & Staging accounts, Customer REST Gateways, Postgres RDS read replicas) to model dense enterprise architectures without visual clutter.
2. **Infrastructure-Accurate CISA KEV Mapping**:
   - Every infrastructure target maps directly to realistic CISA Known Exploited Vulnerabilities (Log4j nodes get Log4Shell; Spring Boot gets Spring4Shell; Postgres RDS gets SQL injections; S3 lakes get storage zone exfiltration).
3. **Layer Diversity Guarantee**:
   - When multiple nodes are compromised in the same layer, the engine guarantees each compromised node displays a **distinct CISA KEV** in glowing red underneath.
4. **Apples-to-Apples Scenario Persistence**:
   - Toggling between the 4 defense scenarios tests the **exact same infrastructure, same nodes, same wires, and same vulnerabilities** without regenerating the estate.
   - Use the **`↻ NEW INFRA`** button at the top to generate a brand new randomized topology.

---

## The 4 Defense Run Scenarios

```
+---------------------------------------------------------------------------------------------------------+
|                                        01 / BASELINE (Unmitigated)                                      |
| Attacker breaches perimeter in milliseconds, pivots laterally through internal microservices, and       |
| exfiltrates backend clustered databases with 0% resistance.                                             |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------------+
|                                     02 / VIRTUAL PATCH (Edge WAF) [SI-2]                                |
| Edge WAF rulesets block ~50-60% of perimeter HTTP/CGI injection attacks (e.g. CVE-2024-4577).           |
| CRITICAL LIMITATION: Completely blind to VPN/SD-WAN protocols and internal lateral token abuse.          |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------------+
|                                  03 / BEHAVIORAL ML (Zero-Trust Isolation) [SI-4]                       |
| Misses raw edge firmware exploits without baselines, but intercepts internal anomalous token minting,  |
| lateral session reuse, and outbound JNDI egress inside the mesh, isolating the attacker before data     |
| lakes are reached.                                                                                      |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------------+
|                                      04 / DEFENSE-IN-DEPTH (Combined)                                   |
| Multi-layered posture combining edge WAF virtual patches, internal zero-trust behavioral ML, and        |
| backend honeytoken canary tripwires for total protection.                                               |
+---------------------------------------------------------------------------------------------------------+
```

---

## CISA KEV Threat Matrix by Architecture Layer & Icon Type

### Layer 0: Cloud Ingress & Perimeter Boundary (T1190)
| Icon File | Target Infrastructure Component | Associated CISA KEVs | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| `public-cloud.png` | AWS / Azure / GCP Accounts | `CVE-2024-4577` (PHP CGI Arg Injection), `CVE-2022-1388` (F5 BIG-IP iControl REST) | `T1190` |
| `cloud-infrastructure.png` | Cloud Infra VPCs & K8s Mesh | `CVE-2024-3400` (PAN-OS GlobalProtect RCE), `CVE-2023-3519` (Citrix NetScaler ADC RCE) | `T1190` |
| `remote-access.png` | Client VPN Gateways | `CVE-2023-46805` (Ivanti Connect Secure), `CVE-2022-42475` (FortiOS SSL-VPN Heap Overflow) | `T1190` |
| `network.png` | ExpressRoute / Network Backbone | `CVE-2023-20198` (Cisco IOS XE PrivEsc), `CVE-2024-21887` (Ivanti Policy Injection) | `T1068` |
| `branch.png` | Branch SD-WAN Gateways | `CVE-2023-46805` (Ivanti Connect Secure), `CVE-2022-42475` (FortiOS SSL-VPN) | `T1190` |
| `partners.png` | B2B Partner Peered Links | `CVE-2023-20198` (Cisco IOS XE), `CVE-2024-21887` (Ivanti Policy Injection) | `T1059` |
| `attack-surface.png` | External Attack Surfaces | `CVE-2024-4577` (PHP CGI), `CVE-2023-3519` (Citrix NetScaler ADC) | `T1190` |

### Layer 1: API Gateways & Identity Access (T1068, T1552, T1190)
| Icon File | Target Infrastructure Component | Associated CISA KEVs | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| `api.png` | Customer & Partner REST/GraphQL GWs | `CVE-2023-38035` (Ivanti Sentry API Auth Bypass), `CVE-2021-26855` (ProxyLogon SSRF) | `T1068`, `T1190` |
| `identity.png` | Okta / SAML / Active Directory IdP | `CVE-2023-4966` (Citrix Bleed Session Leak), `CVE-2022-26923` (AD Certifried Spoofing) | `T1552`, `T1068` |
| `configuration.png` | HashiCorp Vault Secrets Store | `CVE-2024-27198` (TeamCity Admin Token Minting), `CVE-2022-26923` (AD Certifried) | `T1552` |
| `endpoint.png` | Ivanti Sentry / ScreenConnect Ingress | `CVE-2024-1709` (ScreenConnect Auth Bypass), `CVE-2024-27198` (TeamCity Token Minting) | `T1068` |
| `threat-detection.png` | WAF Threat Detection Engines | `CVE-2023-22515` (Confluence Broken Access Control), `CVE-2023-29357` (SharePoint OAuth Bypass) | `T1068`, `T1552` |
| `soc.png` | Perimeter SOC Telemetry Sensors | `CVE-2023-22515` (Confluence Broken Access Control), `CVE-2023-29357` (SharePoint OAuth Bypass) | `T1068`, `T1552` |

### Layer 2: Microservices Mesh & Applications (T1059, T1210, T1505)
| Icon File | Target Infrastructure Component | Associated CISA KEVs | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| `server-infrastructure.png` | Log4j Logging Cluster | `CVE-2021-44228` (**Log4Shell** JNDI Remote Code Execution) | `T1059` |
| `application.png` | Spring Boot Services A & B | `CVE-2022-22965` (**Spring4Shell** Data Binding RCE) | `T1190` |
| `server-infrastructure.png` | Internal Confluence Server | `CVE-2023-22527` (**Confluence OGNL** Template Injection) | `T1059` |
| `application.png` | App Engine Core / Billing | `CVE-2022-29464` (WSO2 File Upload), `CVE-2022-30190` (MSDT Follina Command RCE) | `T1505`, `T1059` |
| `components.png` | Container Registry (Harbor/Artifactory) | `CVE-2023-46604` (ActiveMQ OpenWire RCE), `CVE-2022-46169` (Cacti Command Injection) | `T1059` |
| `cicd.png` | CI/CD Pipeline Runners | `CVE-2023-46604` (ActiveMQ OpenWire RCE), `CVE-2022-46169` (Cacti Command Injection) | `T1059` |
| `ai.png` | Predictive AI Inference Engine | `CVE-2022-29464` (WSO2 File Upload), `CVE-2023-2868` (Barracuda ESG Command Injection) | `T1505`, `T1059` |
| `iot.png` | Telemetry IoT Ingestion Hub | `CVE-2023-2868` (Barracuda ESG Command Injection), `CVE-2022-46169` (Cacti Command Injection) | `T1059` |
| `vulnerability-management.png` | Vulnerability Scanner Node | `CVE-2022-30190` (MSDT Follina Command RCE), `CVE-2023-46604` (ActiveMQ OpenWire RCE) | `T1059` |

### Layer 3: Backend Clustered Databases, Vaults & Storage (T1041, T1003, T1005)
| Icon File | Target Infrastructure & Team Owner | Associated CISA KEVs | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| `server-infrastructure.png` | Customer Postgres & MySQL RDS *(Core DBA & Read Ops)* | `CVE-2023-48788` (**FortiClient EMS SQLi DB Dump**), `CVE-2022-47966` (**ManageEngine PostgreSQL Dump**) | `T1041` |
| `server-infrastructure.png` | MOVEit SFTP & GoAnywhere MFT *(B2B EDI & FinOps Teams)* | `CVE-2023-34362` (**MOVEit Transfer SQLi Exfiltration**), `CVE-2023-0669` (**GoAnywhere MFT DB Dump**) | `T1041` |
| `data.png` | Customer Lake S3 *(Data Platform & BI Analytics Teams)* | `CVE-2023-24489` (**ShareFile Storage Zone Exfiltration**), `CVE-2023-36884` (**Office Document Exfiltration**) | `T1041` |
| `data.png` | Snowflake Warehouse & ClickHouse Lake *(Enterprise BI Team)* | `CVE-2023-27350` (**PaperCut Setup Wizard DB Dump**), `CVE-2022-22954` (**VMware Workspace ONE Secrets Dump**) | `T1041` |
| `server-infrastructure.png` | MongoDB & Redis Cluster *(Mobile App & Session Ops Teams)* | `CVE-2022-26134` (**Confluence OGNL DB Pool Harvest**), `CVE-2024-1086` (**Linux Netfilter PrivEsc DB Dump**) | `T1003` |
| `data-center.png` | Core SAN Storage Vault & AD NTDS *(Storage & Identity Teams)* | `CVE-2020-1472` (**Zerologon Cryptographic Hash Dump**), `CVE-2024-37085` (**VMware ESXi AD VMFS Disk Dump**) | `T1003`, `T1005` |

---

## Docker Range Architecture

For complete backend containerized testing with live ModSecurity WAF and IsolationForest ML Defender containers:

```bash
# Clone and enter repo
git clone https://github.com/kostchei/artex_sandbox.git
cd artex_sandbox

# Copy environment template
cp .env.example .env

# Build and start all services
docker compose up -d --build
```

### Stack Components
| Service | Container Name | Network Isolation | Function |
| :--- | :--- | :--- | :--- |
| **Ingress WAF** | `demo-waf` | `ingress_net`, `proxy_net` | OWASP ModSecurity Core Rule Set v4 reverse proxy enforcing virtual patches |
| **Edge API** | `demo-edge` | `proxy_net`, `control_net` | Initial perimeter target exposing parameter injection vulnerability |
| **Identity API** | `demo-identity` | `proxy_net`, `control_net` | Internal token exchange microservice vulnerable to privilege escalation |
| **Workflow API** | `demo-workflow` | `proxy_net`, `control_net` | Internal orchestration pivot point |
| **Records API** | `demo-records` | `proxy_net`, `control_net` | Isolated data repository storing the canary secret |
| **ML Defender** | `demo-defender` | `control_net` | Scikit-learn `IsolationForest` behavioral classifier with sub-20ms token revocation |
| **ARTEX Agent** | `artex-artex-1` | `ingress_net`, `db_net` | Autonomous offensive penetration testing agent and web console (`:8787`) |
| **Database** | `artex-postgres-1`| `db_net` | PostgreSQL 16 state storage for agent trajectory logs |

---

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
