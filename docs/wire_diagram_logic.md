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
