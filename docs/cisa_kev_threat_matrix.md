# ARTEX Cyber Simulation Range: CISA KEV Threat Matrix

> This matrix describes the original 12-CVE scenario, not the current wire diagram's object assignments. See [wire diagram logic](wire_diagram_logic.md) for the current layers, connections, and product-specific assignments. In `wire.html`, mapped CVEs assume a vulnerable version and configuration for the simulation, not a verified finding.

The wire diagram shows illustrative attack-relevant service paths defined in `ALLOWED_CONNECTIONS`; it is not a discovered network map. Some accounts, security controls, monitoring systems, and other contextual objects have no modeled attack path and are intentionally unconnected. A compromise propagates along displayed paths only.

Named examples include Ivanti Connect Secure (CVE-2023-46805), PAN-OS GlobalProtect (CVE-2024-3400), Citrix NetScaler ADC (CVE-2023-3519), and WSO2 API Manager (CVE-2022-29464). Their inclusion models affected deployments and does not assert that all versions or configurations are vulnerable.

This document details the **12 CISA Known Exploited Vulnerabilities (KEVs)** modeled across the 4 architectural layers of the ARTEX Cyber Simulation Sandbox. These mappings are aligned with the Center for Threat-Informed Defense (CTID) ATT&CK-to-KEV framework from [`mitre-threat-vision-ncs`](https://github.com/kaligraeme/mitre-threat-vision-ncs).

---

## Architecture Layer Mapping Overview

```
Layer 01: Perimeter Ingress & Gateway (demo-waf / demo-edge)
 ├── CVE-2024-4577  (PHP CGI Argument Injection RCE)
 ├── CVE-2023-46805 (Ivanti Connect Secure Gateway Auth Bypass)
 └── CVE-2024-3400  (Palo Alto PAN-OS GlobalProtect Command Injection)
      │
      ▼
Layer 02: Access Control & Identity (demo-identity)
 ├── CVE-2023-22515 (Atlassian Confluence Broken Access Control)
 ├── CVE-2024-27198 (JetBrains TeamCity Admin Token Minting)
 └── CVE-2023-38035 (Ivanti Sentry API Auth Bypass)
      │
      ▼
Layer 03: Internal Services & Workflow Pivoting (demo-workflow)
 ├── CVE-2021-44228 (Apache Log4j "Log4Shell" JNDI RCE)
 ├── CVE-2023-22527 (Atlassian Confluence OGNL Template Injection RCE)
 └── CVE-2022-22965 (Spring Framework "Spring4Shell" Data Binding RCE)
      │
      ▼
Layer 04: Data Destinations & Crown Jewels (demo-records / Data Lakes)
 ├── CVE-2023-34362 (Progress MOVEit Transfer SQL Injection & Data Theft)
 ├── CVE-2022-29464 (WSO2 Identity Server & API Manager JSP Web Shell RCE)
 └── CVE-2023-27350 (PaperCut MF/NG Setup Auth Bypass & Record Extraction)
```

---

## Layer 01: Perimeter Ingress & Gateway (`demo-waf` & `demo-edge`)

* **Target Services**: Edge Reverse Proxies, WAFs, API Gateways, and Perimeter Appliances.
* **Primary MITRE ATT&CK Technique**: **`T1190: Exploit Public-Facing Application`** (Initial Access)
* **ARTEX Offensive Driver**: Automated recon via `nuclei`, `katana`, `httpx`, and specialized skills like [`skills/php2shell`](../skills/php2shell).
* **NIST SP 800-53 Rev 5 Controls**: `SI-2` (Flaw Remediation), `SC-7` (Boundary Protection), `CM-2` (Baseline Configuration).

### 1. CVE-2024-4577 — PHP CGI Argument Injection RCE
* **Target Product**: PHP (running on Windows in CGI or FastCGI mode)
* **CVSS Score**: 9.8 (Critical) | **CISA KEV Added**: June 12, 2024
* **Exploit Mechanics**: Bypasses the Windows character-encoding sanitization fix (CVE-2012-1823) using best-fit character replacement, allowing attackers to inject arbitrary command-line arguments (such as `-d allow_url_include=1 -d auto_prepend_file=php://input`) into `php-cgi.exe` and execute arbitrary system commands.
* **ARTEX Replication**: Mirrored directly by ARTEX's [`skills/php2shell`](../skills/php2shell) exploitation driver.

### 2. CVE-2023-46805 — Ivanti Connect Secure Authentication Bypass
* **Target Product**: Ivanti Connect Secure (ICS) & Policy Secure Gateways
* **CVSS Score**: 8.2 (High) | **CISA KEV Added**: January 10, 2024
* **Exploit Mechanics**: Path-traversal vulnerability in the web component of the gateway allows unauthenticated remote attackers to bypass access controls on restricted `/api/v1/cav/...` endpoints. Typically chained with `CVE-2024-21887` (command injection) for immediate perimeter takeover.
* **ARTEX Replication**: Autonomous API path fuzzing targeting administrative Cav endpoints.

### 3. CVE-2024-3400 — Palo Alto Networks PAN-OS GlobalProtect Command Injection
* **Target Product**: Palo Alto Networks PAN-OS GlobalProtect Gateway
* **CVSS Score**: 10.0 (Critical) | **CISA KEV Added**: April 12, 2024
* **Exploit Mechanics**: Unauthenticated command injection in the GlobalProtect telemetry pipeline allows remote attackers to execute arbitrary system code with root privileges on the firewall appliance.
* **ARTEX Replication**: Header and cookie manipulation during perimeter scanning.

---

## Layer 02: Access Control & Identity (`demo-identity`)

* **Target Services**: Authentication Microservices, OAuth2/OIDC Providers, Internal Identity Hubs.
* **Primary MITRE ATT&CK Techniques**: **`T1068: Exploitation for Privilege Escalation`**, **`T1078: Valid Accounts`**, **`T1552: Unsecured Credentials`**.
* **ARTEX Offensive Driver**: [`skills/api-security`](../skills/api-security), token manipulation, BOLA/IDOR enumeration.
* **NIST SP 800-53 Rev 5 Controls**: `AC-3` (Access Enforcement), `AC-2` (Account Management), `IA-2` (Identification and Authentication).

### 1. CVE-2023-22515 — Atlassian Confluence Broken Access Control
* **Target Product**: Atlassian Confluence Server & Data Center
* **CVSS Score**: 10.0 (Critical) | **CISA KEV Added**: October 5, 2023
* **Exploit Mechanics**: Improper authorization on internal setup endpoints allows unauthenticated attackers to reset the setup phase (`/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false`) and create an unauthorized administrator account.
* **ARTEX Replication**: Synthetic Hop 2 token exchange and role promotion (`role: admin`).

### 2. CVE-2024-27198 — JetBrains TeamCity Admin Token Minting
* **Target Product**: JetBrains TeamCity On-Premises
* **CVSS Score**: 9.8 (Critical) | **CISA KEV Added**: March 7, 2024
* **Exploit Mechanics**: Authentication bypass via alternative path traversal (`/hsts-marker/`) in the web UI controller, allowing unauthenticated attackers to invoke internal management endpoints and mint full administrative access tokens.
* **ARTEX Replication**: Automated minting of lateral pivot bearer tokens (`edge_tok` $\rightarrow$ `wf_tok`).

### 3. CVE-2023-38035 — Ivanti Sentry Administrative API Auth Bypass
* **Target Product**: Ivanti Sentry (formerly MobileIron Sentry)
* **CVSS Score**: 9.8 (Critical) | **CISA KEV Added**: August 22, 2023
* **Exploit Mechanics**: Apache HTTPD configuration flaw exposes internal port 8443 administration endpoints, allowing unauthenticated remote attackers to bypass identity verification, alter system configuration, and execute OS commands as root.
* **ARTEX Replication**: Microservice trust boundary bypass over internal bridge networks.

---

## Layer 03: Internal Services & Workflow Pivoting (`demo-workflow`)

* **Target Services**: Orchestration Engines, Background Workers, CI/CD pipelines, Microservice Middleware.
* **Primary MITRE ATT&CK Techniques**: **`T1059: Command and Scripting Interpreter`**, **`T1210: Exploitation of Remote Services`**.
* **ARTEX Offensive Driver**: Port discovery (`T1046`), internal Nuclei scanning, out-of-band (OAST) validation.
* **NIST SP 800-53 Rev 5 Controls**: `SI-4` (Information System Monitoring), `CA-7` (Continuous Monitoring), `SC-3` (Security Function Isolation).

### 1. CVE-2021-44228 — Apache Log4j ("Log4Shell") JNDI RCE
* **Target Product**: Apache Log4j 2.x
* **CVSS Score**: 10.0 (Critical) | **CISA KEV Added**: December 10, 2021
* **Exploit Mechanics**: Unauthenticated remote code execution via LDAP/RMI JNDI lookups triggered when user-controlled strings are logged.
* **ARTEX Replication**: Automated payload generation of `${jndi:...}` strings verified via out-of-band OAST DNS/HTTP listeners.

### 2. CVE-2023-22527 — Atlassian Confluence Server OGNL Injection
* **Target Product**: Atlassian Confluence Server & Data Center
* **CVSS Score**: 9.8 (Critical) | **CISA KEV Added**: January 24, 2024
* **Exploit Mechanics**: Unauthenticated template injection vulnerability allowing remote code execution via Object-Graph Navigation Language (OGNL) expressions injected into internal text evaluation calls.
* **ARTEX Replication**: Multi-round template injection payload mutation.

### 3. CVE-2022-22965 — Spring Framework ("Spring4Shell") Data Binding RCE
* **Target Product**: Spring Framework MVC / WebFlux (JDK 9+)
* **CVSS Score**: 9.8 (Critical) | **CISA KEV Added**: April 4, 2022
* **Exploit Mechanics**: Parameter data binding flaw allowing unauthenticated remote attackers to overwrite Tomcat logging properties via `class.module.classLoader` and drop an executable web shell.
* **ARTEX Replication**: Internal pivoting to establish durable access on worker containers.

---

## Layer 04: Data Destinations & Crown Jewels (`demo-records` & Data Lakes)

* **Target Services**: Customer Record Stores, Relational Databases, Big Data Lakes (AWS S3, Azure Data Lake).
* **Primary MITRE ATT&CK Techniques**: **`T1190: SQL Injection`**, **`T1041: Exfiltration Over C2`**, **`T1565: Data Manipulation`**.
* **ARTEX Offensive Driver**: `sqlmap` (pre-installed in container), automated data exfiltration pipelines.
* **NIST SP 800-53 Rev 5 Controls**: `SC-28` (Protection of Information at Rest), `AC-4` (Information Flow Enforcement), `AU-10` (Non-Repudiation).

### 1. CVE-2023-34362 — Progress MOVEit Transfer SQL Injection & Exfiltration
* **Target Product**: Progress MOVEit Transfer
* **CVSS Score**: 9.8 (Critical) | **CISA KEV Added**: June 2, 2023
* **Exploit Mechanics**: Unauthenticated SQL injection vulnerability in the web application allowing attackers to bypass authentication, dump database schemas, and deploy automated web shells (`LEMURLOOT`) to siphon customer records.
* **ARTEX Replication**: Automated retrieval of the canary record `CANARY_CONFIDENTIAL_ALPHA_7739`.

### 2. CVE-2022-29464 — WSO2 Identity Server & API Manager RCE & Database Theft
* **Target Product**: WSO2 Identity Server & API Manager
* **CVSS Score**: 9.8 (Critical) | **CISA KEV Added**: April 25, 2022
* **Exploit Mechanics**: Unauthenticated arbitrary file upload flaw allowing attackers to upload malicious JSP scripts directly into the web root, providing root-level execution and direct access to underlying database credentials.
* **ARTEX Replication**: Arbitrary file write and database credential harvesting.

### 3. CVE-2023-27350 — PaperCut MF/NG Authentication Bypass & Record Theft
* **Target Product**: PaperCut MF/NG Application Server
* **CVSS Score**: 9.8 (Critical) | **CISA KEV Added**: April 21, 2023
* **Exploit Mechanics**: Authentication bypass in the setup wizard (`SetupCompleted` class) allowing unauthenticated attackers to access administrative interfaces, dump user database tables, and execute arbitrary code.
* **ARTEX Replication**: Bypassing final-tier authorization to exfiltrate confidential records.
