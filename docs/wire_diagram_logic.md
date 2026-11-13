# Wire diagram: object, connection and KEV logic

This specification describes `wire.html`, the synthetic wire-diagram simulation. Its assets, links, vulnerabilities and defenses are scenario assumptions; they are not a discovery of a real environment or proof that a product is vulnerable. A KEV is a CVE in CISA's Known Exploited Vulnerabilities catalog.

## 1. Is the object in the right layer?

Each object family is declared in `LAYER_CONFIG`. Place the object according to its function in this scenario, not its icon or the consequence of an attack.

| Layer | Intended role | Examples and boundaries |
| --- | --- | --- |
| 01 — Cloud ingress | External gateways and network ingress, plus cloud and network context. | Ivanti Connect Secure VPN, GlobalProtect and NetScaler ADC are modeled as externally accessible gateways. Cloud accounts and projects are context, not vulnerable gateway products. |
| 02 — Gateways and auth | API gateways, identity services and boundary controls. | WSO2 API Manager, Ivanti Sentry, identity providers and the Active Directory domain controller. Monitoring and security controls are contextual unless a path is explicitly modeled. |
| 03 — Services mesh | Applications, middleware, service and operational tooling. | Spring MVC, Confluence, services using Log4j 2, and MOVEit Transfer / GoAnywhere MFT. File-transfer products are applications even when they handle valuable data. |
| 04 — Data stores and secrets | Data destinations, databases, storage and secret stores. | Customer S3 data, RDS, analytics stores, document databases and storage vaults. |

A cluster is a visual grouping, not proof of network connectivity or common ownership. The layout is simplified: a cloud account is an administrative container, and a data store can be reached by many paths not shown here. Objects without a modeled path can remain isolated. Treat mixed technology families cautiously when adding variants: each variant must belong in its declared layer and must support every relationship assigned to its family.

## 2. Does each connection make sense?

`ALLOWED_CONNECTIONS` defines directional, illustrative attack-relevant paths between named object families. An edge represents assumed access or a service interaction useful for the scenario, not a discovered route, verified authorization, or a guarantee that compromise automatically crosses a trust boundary. A source and target must be in adjacent layers and the pairing must have a plausible purpose in this deployment. For example, an API gateway may route requests to an application; an application or transfer service may access a data store. These specific deployments and permissions are assumed.

The generator chooses instances from permitted families and may add additional permitted links to connect variants. Proximity is used only to choose among allowed instances, never to approve a relationship. Family-level rules apply to *every* variant; split a family or use more specific rules if a relationship is not plausible for every variant. There is no fallback that connects an otherwise isolated node to an arbitrary neighbor. Attack propagation follows displayed outgoing wires; membership in a cluster does not itself permit a jump.

`EXTERNAL_ENTRY_GROUPS` limits off-screen attack arrows and initial attack origins to the modeled internet-facing Ivanti Connect Secure, GlobalProtect and NetScaler gateways. One or two are selected when new infrastructure is generated. Those selections persist across defense scenarios; resize or new infrastructure regenerates them. Placement in the ingress layer alone does not imply public reachability.

The model omits many real interactions, including application-to-identity authentication and monitoring telemetry. An isolated object means the simulation has no modeled attack path for it, not that the real-world technology has no connections.

## 3. Is the KEV right for the object?

`kevByVariant` maps a particular displayed variant to a CVE in the matching layer's `LAYER_KEVS` catalog. Do not assign a CVE merely because an asset is in the same layer, uses the same icon, holds data, or is near another object. Check the affected product, affected version, configuration and attack surface against the vendor advisory and CISA/NVD. Catalog membership alone does not establish applicability to every installation.

| Modeled object | Assigned KEV | Scope assumed for this scenario |
| --- | --- | --- |
| Ivanti Connect Secure VPN | [CVE-2023-46805](https://nvd.nist.gov/vuln/detail/CVE-2023-46805) | Affected Ivanti Connect Secure deployment. |
| PAN-OS GlobalProtect Gateway | [CVE-2024-3400](https://nvd.nist.gov/vuln/detail/CVE-2024-3400) | Affected PAN-OS version and GlobalProtect configuration. |
| Citrix NetScaler ADC Gateway | [CVE-2023-3519](https://nvd.nist.gov/vuln/detail/CVE-2023-3519) | Affected NetScaler ADC deployment and relevant gateway configuration. |
| WSO2 API Manager | [CVE-2022-29464](https://nvd.nist.gov/vuln/detail/CVE-2022-29464) | Affected API Manager version and accessible vulnerable endpoint. |
| Ivanti Sentry gateway | [CVE-2023-38035](https://nvd.nist.gov/vuln/detail/CVE-2023-38035) | Affected Sentry deployment and accessible administrative interface. |
| Service using Log4j 2 | [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | Affected Log4j 2 version and exploitable logging configuration. |
| Spring MVC WAR on Tomcat / JDK 9+ | [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) | Affected Spring Framework version and exploitable deployment; an ordinary Spring Boot executable JAR is not sufficient for the documented Tomcat WAR exploit. |
| Confluence Data Center | [CVE-2023-22527](https://nvd.nist.gov/vuln/detail/CVE-2023-22527) | Affected Confluence Data Center version. |
| MOVEit Transfer | [CVE-2023-34362](https://nvd.nist.gov/vuln/detail/CVE-2023-34362) | Affected MOVEit Transfer web application and HTTP(S) access. |
| GoAnywhere MFT | [CVE-2023-0669](https://nvd.nist.gov/vuln/detail/CVE-2023-0669) | Affected GoAnywhere MFT deployment and access to the vulnerable interface. |

The diagram does not inventory versions or verify configuration: the table records assumptions. Unmapped assets display `SIMULATED ACCESS` when reached; no CVE is inferred, and CVE-specific mitigations do not apply to them. Multiple instances may share the same valid CVE. The assigned CVE remains fixed for the infrastructure across scenario runs and is used for both mitigation and display. The catalog contains additional CVEs that are not necessarily assigned to any object.

## Recheck procedure and limitations

1. Review every family and each variant against the layer table; confirm labels distinguish products from components and data stores.
2. Inspect every `ALLOWED_CONNECTIONS` pairing against every source and target variant. Confirm its role and direction can be justified as a modeled interaction. Verify external entry groups separately.
3. Review every `kevByVariant` entry against the current vendor advisory and CISA KEV catalog, including prerequisites. Confirm it resolves within its layer and that unmapped assets receive no arbitrary fallback.
4. Exercise randomized layouts: check all generated wires against the allowlist, mapped CVEs against their variant, and selected entry arrows against the external-entry set; verify at least one route from each selected entry to a data target. Recheck behavior after switching scenarios, changing connector style, regenerating infrastructure and resizing.

Mitigation outcomes are simplified scenario rules, not validated product efficacy. A permitted edge is an assumed attack path and does not independently prove that a CVE can be exploited across it. Manual node clicks can mark an object hit outside automatic propagation. The simulation does not model all trust, protocol, access-control, monitoring or deployment details.
# Additional modeled products and path assumptions

WAF management, identity, and detection/SOC consoles each receive a vulnerability independently
with 25% probability when new infrastructure is generated. An unassigned
control has no modeled exploit, so an attack stops there without a defense
detection being counted. Assignment and paths persist with the infrastructure.
Splunk CVE-2023-32707 is a CVE, not represented here as a verified CISA KEV;
its scenario assumes a user with the `edit_user` capability, as described in
[Splunk's advisory](https://advisory.splunk.com/advisories/SVD-2023-0602).
The IDP, WAF management, and SOC connections assume management access and
service relationships; they do not imply that monitoring traffic itself grants
access or that exploitation automatically disables defensive controls.

The product pools are F5, Fortinet, Citrix and Imperva for WAF; VMware,
Microsoft, Red Hat and Okta for identity; and Splunk, IBM, Elastic and Wazuh
for SOC. They are representative products, not a verified market-share ranking.
Okta has no CVE assigned in this scenario. The other products use explicitly
mapped CVEs; some are not known to be CISA KEVs. See the relevant NVD records:
[FortiWeb](https://nvd.nist.gov/vuln/detail/CVE-2025-64446),
[NetScaler](https://nvd.nist.gov/vuln/detail/CVE-2023-3519),
[Imperva](https://nvd.nist.gov/vuln/detail/CVE-2018-5412),
[Keycloak](https://nvd.nist.gov/vuln/detail/CVE-2021-3827),
[AD FS](https://nvd.nist.gov/vuln/detail/CVE-2018-8340),
[QRadar](https://nvd.nist.gov/vuln/detail/CVE-2020-4888),
[Kibana](https://nvd.nist.gov/vuln/detail/CVE-2026-78597), and
[Wazuh](https://nvd.nist.gov/vuln/detail/CVE-2026-25769).
The Imperva CVE assumes local access; Keycloak and AD FS assume appropriate
credentials; Splunk assumes `edit_user`; QRadar and Kibana assume the relevant
authenticated privileges; Wazuh assumes a compromised cluster worker and the
shared cluster key; and NetScaler assumes an affected Gateway or AAA
configuration. The diagram assumes these prerequisites rather than modeling
their acquisition. A compromised WAF is an appliance or management foothold;
subsequent connections represent assumed access to its integrated services.

The expanded catalog also includes FortiOS CVE-2018-13379, Pulse Connect Secure
CVE-2019-11510, Apache HTTP Server CVE-2021-42013, Exchange CVE-2021-26855,
Ivanti EPM CVE-2024-29824, Confluence CVE-2023-22515, and WebLogic
CVE-2020-14882. The data tier includes Debian-packaged Redis CVE-2022-0543,
SQL Server Reporting Services CVE-2020-0618, and FortiClient EMS
CVE-2023-48788. These are assumed vulnerable product deployments. Apache
traversal requires a vulnerable configuration (CGI for code execution);
Redis is specifically the affected Debian package and requires access to Redis;
the reporting-service scenario assumes any necessary privileges; EMS is the
affected application with a SQL backend, not a vulnerability in SQL Server.
The model assumes the intervening network reachability and credentials required
for each hop; it does not simulate them or guarantee exfiltration.
References: [Redis](https://nvd.nist.gov/vuln/detail/CVE-2022-0543),
[reporting services](https://nvd.nist.gov/vuln/detail/CVE-2020-0618),
[Ivanti EPM](https://nvd.nist.gov/vuln/detail/CVE-2024-29824),
[Apache HTTP Server](https://nvd.nist.gov/vuln/detail/CVE-2021-42013),
[Pulse Connect Secure](https://nvd.nist.gov/vuln/detail/CVE-2019-11510), and
[CISA's exploited-vulnerability advisory](https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf).

The wire simulation includes vulnerable instances of F5 BIG-IP (CVE-2022-1388),
JetBrains TeamCity (CVE-2023-42793), Apache ActiveMQ (CVE-2023-46604), and
Cacti (CVE-2022-46169). Affected versions and configurations are assumed, not
detected. Sources: [CISA F5 advisory](https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf),
[CISA TeamCity advisory](https://www.cisa.gov/sites/default/files/2023-12/aa23-347a-russian-foreign-intelligence-service-svr-exploiting-jetbrains-teamcity-cve-globally_0.pdf),
[CISA ActiveMQ catalog announcement](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/3790dfb), and
[NVD Cacti record](https://nvd.nist.gov/vuln/detail/CVE-2022-46169).

These are hypothetical service relationships: the F5 management interface is
exposed and fronts API services; the API services can reach the ActiveMQ broker;
and the identity gateway gives access to internal TeamCity and Cacti services.
The final connections assume the broker, build service, or monitoring service
has credentials or integration access to its respective data target. A wire
represents that assumed reachability, not proof that exploitation automatically
grants the next hop. The simulation does not model credentials, network rules,
or exploit prerequisites in detail.


### AI gateway scenario

The simulated LiteLLM Proxy 1.83.6 is associated with CVE-2026-42271. The scenario assumes the attacker has a valid proxy API key and can reach the affected MCP test endpoints. The vendor identifies versions 1.74.2 through 1.83.6 as affected and 1.83.7 as fixed. The connection to a PostgreSQL database is an illustrative deployment relationship, not a claim about a real environment.

Source: https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g

The Confluence Server 8.5.1 example is within the affected version range for CVE-2023-22515: https://support.atlassian.com/atlassian-knowledge-base/kb/faq-for-cve-2023-22515/


### Exposure assignment and scenario calibration

Each infrastructure assigns independent simulated exposures to asset instances: 80% by default, or the asset's explicit vulnerability chance where specified. The assignment, topology, and defense seed persist when changing scenarios. Public access and assumed credentials are scenario findings, not invented CVEs. The generator resamples an infrastructure if the actual baseline probe order cannot reach a data target; the baseline probe order does not use hidden exposure assignments. The combined scenario prioritizes a viable canary route when the canary is selected, without bypassing earlier defenses.

Baseline displays at most three successful targets in each layer and at least one data target. Defended scenarios show at most one backend data target hit. A blocked or unexploitable node cannot be used as a stepping stone; agents continue checking other modeled connections. The synthetic WAF coverage and SOAR detection parameters are calibrated across generated infrastructures to approximately 50% of runs with a backend hit for each individual defense, and 25% for defense-in-depth. These are demo assumptions, not measured security product performance.
