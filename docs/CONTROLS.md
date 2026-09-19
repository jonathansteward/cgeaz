# Control Mappings

Every policy, collector, report and gate rule in this repo, mapped to the NIST CSF 2.0
category it serves. This file is what turns the repo from code into a control catalog. The
same crosswalk is stored as data in the Cosmos `mappings` container, and
`labs/04-evidence/seed_crosswalk.py --check` fails if this file and the stored crosswalk
disagree.

## Stage 01 — Foundation

| Component | What it does | CSF 2.0 |
|---|---|---|
| Management group hierarchy + initiative assignment | Controls inherit to every current and future subscription — compliance by design | GV.PO, GV.OC |
| `cge-require-env-tag-rg` (Audit) | Inventory hygiene; owner accountability feeds the POA&M | ID.AM |
| `cge-deny-public-blob` (Deny) | Prevents public blob exposure at the API, before the resource exists | PR.DS |
| `cge-dine-storage-diagnostics` (DeployIfNotExists) | Logging that enforces its own coverage | PR.PS, DE.CM |
| `cge-min-tls12-storage` (Audit) | Flags storage accounts that accept legacy TLS, protecting data in transit | PR.DS |
| `cge-cosmos-no-public-access` (Audit) | Flags Cosmos DB accounts reachable from the public internet | PR.IR |
| `cge-storage-cmk` (Audit) | Flags storage encrypted with Microsoft-managed keys rather than customer-managed keys | PR.DS |
| Remediation identity (user-assigned, whitelist roles) | Every automated change has a named, auditable author | PR.AA, GV.RR |
| Log Analytics workspace + Activity Log routing | Central audit trail beyond the 90-day default | DE.CM, PR.PS |
| Scheduled alert rules (`alerts.tf`) + action group | The three KQL detections run hourly against the workspace and email the owner | DE.CM, DE.AE |

## Stage 03 — Evidence Store

| Component | What it does | CSF 2.0 |
|---|---|---|
| Cosmos DB (assessments / roleassignments / runs / frameworks / mappings) | Owned evidence schema; collect once, crosswalk to every framework | GV.OV, ID.RA |
| WORM immutability policy on `reports` | Artifacts tamper-proof by platform guarantee | PR.DS |
| Shared keys disabled + data-plane RBAC | Identity or nothing; no credentials to steal or rotate | PR.AA |
| Assessments collector (`collect_nightly`; Security Reader + Cosmos write only) | Continuous control-test capture with lineage; cannot alter what it observes | DE.CM, ID.RA |
| Role assignment collector (`collect_roles_nightly`) + `roleassignments` container | Nightly snapshot of who holds which role at which scope, with the same `runId` and `collectedAt` lineage | PR.AA, ID.AM, DE.CM |
| Run ledger (`runs` container) | Every collection run is recorded with its trigger and document count, so run history is evidence in the store | GV.OV, DE.CM |
| Collector/reporter identity split | The recorder of facts cannot author the narrative — SoD by role scopes | PR.AA, GV.RR |

## Stage 04 — Reporting

| Component | What it does | CSF 2.0 |
|---|---|---|
| POA&M generator (daily, SLA-dated) | Weakness management with owners and dates, from the store only | ID.IM, GV.RM |
| SAR generator (weekly) | Assessment reporting where every number traces to a stored document | ID.RA, GV.OV |
| OSCAL SSP generator (weekly) | A machine-readable System Security Plan built from the stored catalog, crosswalk and latest run, validated against the OSCAL 1.1.2 schema | GV.PO, GV.OV |

## Stage 06 — Enforcement

| Component | What it does | CSF 2.0 |
|---|---|---|
| `cge-fix-public-blob` (Modify, mode ladder) | Auto-remediation through the dedicated identity; human-approved in dry-run | PR.DS, RS.MI |
| `remediation_mode` variable | Escalation is a reviewed diff — automation acts, humans authorize | GV.PO, GV.RR |

## Repo gates (policy/) and detections

| Rule | Mistake it makes unmergeable, or event it detects | CSF 2.0 |
|---|---|---|
| `storage.rego` | Storage below the pipeline's own standard: public blobs, shared keys, TLS below 1.2 | PR.DS |
| `policy_identity.rego` | Remediation that silently never runs | PR.PS |
| `broad_roles.rego` | Owner/Contributor grants in governance code | PR.AA |
| `drift.yml` | Reality drifting from the code going unnoticed (nightly plan per stage) | DE.CM, DE.AE |
| `queries/tripwire_human_writes_to_governed_rgs.kql` | A person changing a governed resource group directly, outside the repo and CI | DE.CM, DE.AE |
| `queries/fafo_after_hours_admin_writes.kql` | Administrative change outside FAFO business hours going unnoticed | DE.CM, DE.AE |
| `queries/fafo_unapproved_regions.kql` | Resources created outside FAFO's approved regions | ID.AM, DE.CM |

## Crosswalk: CSF 2.0 to NIST 800-53

Components map to CSF 2.0 only. This table crosswalks each CSF category the pipeline uses to
the NIST 800-53 controls that support it, so one collected assessment serves both
frameworks. It is category-level and kept to the controls the pipeline can credibly speak
to; verify it against NIST's CSF 2.0 Reference Tool. The same crosswalk is stored in
Cosmos and drives the OSCAL System Security Plan.

| CSF 2.0 category | Title | 800-53 controls |
|---|---|---|
| GV.OC | Organizational Context | PM-1, PM-11 |
| GV.RM | Risk Management Strategy | PM-9, RA-1, RA-7 |
| GV.RR | Roles, Responsibilities, and Authorities | PM-2, PM-13, AC-5 |
| GV.PO | Policy | PL-1, PL-2, CM-1 |
| GV.OV | Oversight | CA-2, CA-7, PM-31 |
| ID.AM | Asset Management | CM-8, PM-5 |
| ID.RA | Risk Assessment | RA-3, RA-5 |
| ID.IM | Improvement | CA-5, PM-4 |
| PR.AA | Identity Management, Authentication, and Access Control | AC-2, AC-3, AC-5, AC-6, IA-2, IA-5 |
| PR.DS | Data Security | SC-8, SC-12, SC-13, SC-28 |
| PR.PS | Platform Security | CM-2, CM-6, CM-7 |
| PR.IR | Technology Infrastructure Resilience | SC-7 |
| DE.CM | Continuous Monitoring | AU-6, CA-7, SI-4 |
| DE.AE | Adverse Event Analysis | AU-6, SI-4, IR-4 |
| RS.CO | Incident Response Reporting and Communication | IR-4, IR-6 |
| RS.MI | Incident Mitigation | IR-4, SI-2 |

### Blast radius

| Policy / component | Effect | Blast radius |
|---|---|---|
| `cge-require-env-tag-rg` | Audit | None while Audit. Deny would block resource groups without an `env` tag across the sandbox group |
| `cge-deny-public-blob` | Deny | Blocks new or updated storage accounts allowing public blobs; existing accounts are only flagged |
| `cge-dine-storage-diagnostics` | DeployIfNotExists | Adds a diagnostic setting to storage accounts; cannot read data or change settings; adds ingestion cost |
| `cge-min-tls12-storage` | Audit | None while Audit. Deny would block storage accounts below TLS 1.2 and break legacy clients |
| `cge-cosmos-no-public-access` | Audit | None while Audit. Deny would block Cosmos accounts with public access until they use private endpoints |
| `cge-storage-cmk` | Audit | None while Audit. Deny would block any storage account without a Key Vault key |
| `cge-fix-public-blob` | Modify (mode ladder) | Sets `allowBlobPublicAccess` to false on existing storage accounts in the sandbox group; cannot delete or read data |
| Remediation identity | Monitoring Contributor and Storage Account Contributor at mg-grc-sandbox | Create or update diagnostic settings; set storage account properties; no data access |
| Scheduled alert rules | Alert (email) | Read the Activity Log and send email to the owner; change no resource; a small hourly-evaluation charge per rule |
| `grc_baseline` assignment | Initiative | Applies all six Stage 01 policies to every current and future subscription in the group |
