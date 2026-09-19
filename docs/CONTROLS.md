# Control Mappings

Every policy, collector, report and gate rule in this repo, mapped to the NIST CSF 2.0
category it serves, with the NIST 800-53 control it crosswalks to. This file is what turns
the repo from code into a control catalog. The same crosswalk is stored as data in the
Cosmos `mappings` container for both frameworks, and `labs/04-evidence/seed_800_53.py --check`
fails if this file and the stored crosswalk disagree.

## Stage 01 — Foundation

| Component | What it does | CSF 2.0 | 800-53 |
|---|---|---|---|
| Management group hierarchy + initiative assignment | Controls inherit to every current and future subscription — compliance by design | GV.PO, GV.OC | CM-2, CM-6 |
| `cge-require-env-tag-rg` (Audit) | Inventory hygiene; owner accountability feeds the POA&M | ID.AM | CM-8 |
| `cge-deny-public-blob` (Deny) | Prevents public blob exposure at the API, before the resource exists | PR.DS | AC-3, SC-7 |
| `cge-dine-storage-diagnostics` (DeployIfNotExists) | Logging that enforces its own coverage | PR.PS, DE.CM | AU-2, AU-12 |
| `cge-min-tls12-storage` (Audit) | Flags storage accounts that accept legacy TLS, protecting data in transit | PR.DS | SC-8, SC-13 |
| `cge-cosmos-no-public-access` (Audit) | Flags Cosmos DB accounts reachable from the public internet | PR.IR | SC-7 |
| `cge-storage-cmk` (Audit) | Flags storage encrypted with Microsoft-managed keys rather than customer-managed keys | PR.DS | SC-28, SC-12 |
| Remediation identity (user-assigned, whitelist roles) | Every automated change has a named, auditable author | PR.AA, GV.RR | AC-2, AC-6 |
| Log Analytics workspace + Activity Log routing | Central audit trail beyond the 90-day default | DE.CM, PR.PS | AU-2, AU-6, AU-11 |
| Scheduled alert rules (`alerts.tf`) + action group | The three KQL detections run hourly against the workspace and email the owner | DE.CM, DE.AE | CA-7, SI-4 |

## Stage 03 — Evidence Store

| Component | What it does | CSF 2.0 | 800-53 |
|---|---|---|---|
| Cosmos DB (assessments / roleassignments / runs / frameworks / mappings) | Owned evidence schema; collect once, crosswalk to every framework | GV.OV, ID.RA | CA-7, CA-2 |
| WORM immutability policy on `reports` | Artifacts tamper-proof by platform guarantee | PR.DS | AU-9, AU-11 |
| Shared keys disabled + data-plane RBAC | Identity or nothing; no credentials to steal or rotate | PR.AA | AC-3, AC-6, IA-5 |
| Assessments collector (`collect_nightly`; Security Reader + Cosmos write only) | Continuous control-test capture with lineage; cannot alter what it observes | DE.CM, ID.RA | CA-7, RA-5 |
| Role assignment collector (`collect_roles_nightly`) + `roleassignments` container | Nightly snapshot of who holds which role at which scope, with the same `runId` and `collectedAt` lineage | PR.AA, ID.AM, DE.CM | AC-2, AC-6, CA-7 |
| Run ledger (`runs` container) | Every collection run is recorded with its trigger and document count, so run history is evidence in the store | GV.OV, DE.CM | AU-2, AU-12, CA-7 |
| Collector/reporter identity split | The recorder of facts cannot author the narrative — SoD by role scopes | PR.AA, GV.RR | AC-5, AC-6 |

## Stage 04 — Reporting

| Component | What it does | CSF 2.0 | 800-53 |
|---|---|---|---|
| POA&M generator (daily, SLA-dated) | Weakness management with owners and dates, from the store only | ID.IM, GV.RM | CA-5 |
| SAR generator (weekly) | Assessment reporting where every number traces to a stored document | ID.RA, GV.OV | CA-2 |
| OSCAL SSP generator (weekly) | A machine-readable System Security Plan built from the stored catalog, crosswalk and latest run, validated against the OSCAL 1.1.2 schema | GV.PO, GV.OV | PL-2, CA-2 |

## Stage 06 — Enforcement

| Component | What it does | CSF 2.0 | 800-53 |
|---|---|---|---|
| `cge-fix-public-blob` (Modify, mode ladder) | Auto-remediation through the dedicated identity; human-approved in dry-run | PR.DS, RS.MI | CM-6, RA-7 |
| `remediation_mode` variable | Escalation is a reviewed diff — automation acts, humans authorize | GV.PO, GV.RR | CM-3 |

## Repo gates (policy/) and detections

| Rule | Mistake it makes unmergeable, or event it detects | CSF 2.0 | 800-53 |
|---|---|---|---|
| `storage.rego` | Storage below the pipeline's own standard: public blobs, shared keys, TLS below 1.2 | PR.DS | AC-3, SC-8, SC-28 |
| `policy_identity.rego` | Remediation that silently never runs | PR.PS | AC-6, CM-3 |
| `broad_roles.rego` | Owner/Contributor grants in governance code | PR.AA | AC-6 |
| `drift.yml` | Reality drifting from the code going unnoticed (nightly plan per stage) | DE.CM, DE.AE | CA-7, CM-3 |
| `queries/tripwire_human_writes_to_governed_rgs.kql` | A person changing a governed resource group directly, outside the repo and CI | DE.CM, DE.AE | CA-7, SI-4, CM-3 |
| `queries/fafo_after_hours_admin_writes.kql` | Administrative change outside FAFO business hours going unnoticed | DE.CM, DE.AE | CA-7, SI-4 |
| `queries/fafo_unapproved_regions.kql` | Resources created outside FAFO's approved regions | ID.AM, DE.CM | CM-2, SI-4 |

### Blast radius

| Policy / component | Effect | Blast radius | Rollback |
|---|---|---|---|
| `cge-require-env-tag-rg` | Audit | None while Audit. Deny would block resource groups without an `env` tag across the sandbox group | Set `tag_policy_effect` to Audit |
| `cge-deny-public-blob` | Deny | Blocks new or updated storage accounts allowing public blobs; existing accounts are only flagged | Set `public_blob_policy_effect` to Audit |
| `cge-dine-storage-diagnostics` | DeployIfNotExists | Adds a diagnostic setting to storage accounts; cannot read data or change settings; adds ingestion cost | Remove from initiative |
| `cge-min-tls12-storage` | Audit | None while Audit. Deny would block storage accounts below TLS 1.2 and break legacy clients | Set effect to Audit |
| `cge-cosmos-no-public-access` | Audit | None while Audit. Deny would block Cosmos accounts with public access until they use private endpoints | Set effect to Audit |
| `cge-storage-cmk` | Audit | None while Audit. Deny would block any storage account without a Key Vault key | Set effect to Audit or Disabled |
| `cge-fix-public-blob` | Modify (mode ladder) | Sets `allowBlobPublicAccess` to false on existing storage accounts in the sandbox group; cannot delete or read data | Set `remediation_mode` to audit |
| Remediation identity | Monitoring Contributor and Storage Account Contributor at mg-grc-sandbox | Create or update diagnostic settings; set storage account properties; no data access | Remove the role assignments |
| Scheduled alert rules | Alert (email) | Read the Activity Log and send email to the owner; change no resource; a small hourly-evaluation charge per rule | Destroy `alerts.tf` resources or set `enabled = false` |
| `grc_baseline` assignment | Initiative | Applies all six Stage 01 policies to every current and future subscription in the group | Destroy the assignment |
