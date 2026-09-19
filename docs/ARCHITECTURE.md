# Architecture

This pipeline discovers what a subscription is running, collects control evidence into a
store the team owns, generates reports from that store only, and enforces baseline
controls through Azure Policy with a human at the approval gate. Everything is deployed
as Terraform, there is one root module per stage in the sandbox subscription under the `mg-grc`
management group hierarchy.

## Stage flow

Each stage is its own Terraform root module with its own state file. Stages pass values
forward through outputs, read by the next stage with `terraform_remote_state`. No stage
edits another stage's state.

```
01 Foundation ──► 02 Activation ──► 03 Evidence store ──► 04 Reporting
      │                                    ▲                    │
      │                                    │                    ▼
      └──────────────► 06 Enforcement ─────┘             WORM reports container
                              │
                              ▼
                  remediation shows up in the
                  next collection run (loop)
```

| Stage | Purpose | Key outputs handed on |
|---|---|---|
| `01-foundation` | Management group hierarchy, the policy initiative and its assignment, the remediation identity, the Log Analytics workspace, the evidence resource group | `management_group_id`, `log_analytics_workspace_id`, `evidence_resource_group_name`, `remediation_identity_id` |
| `02-activation` | Discovery. Reads the current tier of each Defender plan. Enabling a plan is conditional on the measured gap | `current_plan_tiers`, `activation_needed` |
| `03-evidence-store` | Cosmos DB (`assessments`, `roleassignments`, `frameworks`, `mappings`), the evidence storage account with the WORM `reports` container, the collector Function App | `cosmos_endpoint`, `cosmos_account_id`, `evidence_storage_account`, `collector_function_app` |
| `04-reporting` | The reporting Function App: POA&M (daily) and SAR (weekly) generators | `reporting_function_app`, `reporter_principal_id` |
| `06-enforcement` | The remediation policy `cge-fix-public-blob` and its escalation ladder | `remediation_mode` |

Stage 05 does not exist as a stage: the narrative layer described in the labs is not part
of this deployment.

### Run-time data path

1. `collect_nightly` (05:00 UTC) and `collect_roles_nightly` (05:30 UTC) run. The first reads Defender assessments through the ARM API and
   upserts one document per assessment and resource into Cosmos `assessments`. Every
   document carries the run's `runId` and `collectedAt`. The document ID is a hash of the
   assessment and resource, so re-running the collector updates a document and never
   duplicates it.
2. `poam_daily` (06:00 UTC) and `sar_weekly` (Monday 07:00 UTC) read the latest run from
   Cosmos only and write dated files into the `reports` container. The reporters have no
   path to live platform data.
3. The WORM policy on `reports` means a report cannot be deleted or replaced during the
   retention period, so each artifact is a fixed record of that day.
4. Any number in a report can be reproduced with a stored query. For example, the SAR's
   open-findings count is:
   `SELECT VALUE COUNT(1) FROM c WHERE c.runId = "<runId from the SAR header>" AND c.status = "Unhealthy"`

## Identity boundaries

No identity both writes evidence and generates reports. None of the runtime identities (the
remediation identity and both Function Apps) holds Owner or Contributor; their permissions
are a whitelist of their job. The CI identity is the one exception: it holds Contributor at
the sandbox management group so that `terraform plan` can refresh state and list storage
keys. It is federated to this repository only, holds no secret, and Contributor cannot write
role assignments. Narrowing it to a custom role is the known improvement.

| Identity | Type | Roles | Can | Cannot |
|---|---|---|---|---|
| Remediation identity | User-assigned | Monitoring Contributor at the sandbox management group; Storage Account Contributor at the same scope, granted only when `remediation_mode` is not `audit` | Create diagnostic settings; set blob public access to false | Read data, delete resources, change other properties |
| Collector Function | System-assigned | Security Reader at the subscription; Cosmos DB Built-in Data Contributor on the evidence account | Read Defender assessments and role assignments; write evidence documents | Change what it observes; write reports |
| Reporter Function | System-assigned | Cosmos DB Built-in Data Reader; Storage Blob Data Contributor on the evidence storage account | Read evidence; write reports into the WORM container | Write to Cosmos; read live platform data |
| CI identity (`github-cgeaz-*` app registration) | Federated, no secret | Contributor at `mg-grc` for plan and refresh; Storage Blob Data Contributor on the state resource group | Run `terraform plan` and drift checks | Be used by any repository other than the federated one |

Notes on these boundaries:

- Separating collector and reporter is separation of duties by role scope. The recorder of
  facts cannot write the narrative, and the author of the narrative cannot alter the
  facts.
- Every assignment with a remediation effect carries an `identity` block that names the
  remediation identity. Without it the policy deploys cleanly and remediation silently
  never runs. The gate rule `policy_identity.rego` makes that mistake unmergeable.
- The evidence storage account has shared keys disabled. The Function Apps each have a
  separate internal storage account for their runtime, which is the one documented
  exception and holds no evidence.
- The CI identity's federated credentials name this repository and both the
  `pull_request` and `main` subjects, in plain and immutable-ID form. It uses OIDC, so
  there are no stored credentials.

## Change control

| Control | Where | What it protects |
|---|---|---|
| Compliance gate | `.github/workflows/gate.yml` | Every PR to `main` runs `terraform plan` per stage and evaluates the plan with conftest rules in `policy/` |
| Gate rules | `policy/*.rego` | No public blob access, no shared keys, TLS 1.2 or higher, no Owner or Contributor grants, no remediation assignment without an identity |
| Drift detection, code vs. reality | `.github/workflows/drift.yml` | Nightly `terraform plan -detailed-exitcode` per stage; drift opens an issue |
| Drift detection, who touched reality | KQL tripwire in Log Analytics | Out-of-band administrative writes and their caller |
| FAFO detections | `queries/*.kql` | Administrative changes outside business hours; resources created outside the approved regions |
| Escalation ladder | `remediation_mode` in stage 06 | `audit`, then `dry-run`, then `enforce`; each step is a reviewed change |

## Why these choices

- **Discovery before activation.** Stage 02 reads the current Defender tiers with data
  sources before anything is enabled, and only the measured gap is acted on. Keying
  resources on live values that the same run changes makes Terraform destroy what it
  just enabled on the next run.
- **Remediation runs in dry-run with a human approving.** The `modify` effect is deployed
  but not enforced. A person creates the remediation task, so automation acts only after
  someone authorizes it. Stepping up to `enforce` is a reviewed change to one variable.
- **Audit first for new controls.** A new policy, such as the TLS minimum, starts in Audit
  so its effect is observed before it can block anything. Deny is used only where the
  control is clear-cut, as with public blob access.
- **Deterministic document IDs.** The same assessment on the same resource always maps to
  the same document, so collection is idempotent and history is carried by `runId` and
  `collectedAt`.
- **WORM is left unlocked in this deployment.** The retention policy is 90 days and
  unlocked so teardown works. A production deployment locks it, after which no one can
  shorten or remove it.
- **Identity and OIDC instead of keys.** Evidence storage has shared keys disabled, Cosmos
  is accessed by data-plane roles, and CI authenticates by federation. There are no stored
  credentials to rotate or leak.
- **Immutable OIDC subject.** GitHub issues tokens whose subject includes the numeric
  owner and repository IDs, so the federated credentials are registered for that form as
  well as the plain one. A renamed or recreated repository cannot reuse them.
- **CI writes its own backend config.** `labs/03-foundation/backend.hcl` is generated per
  environment and is not committed, so the workflows create it from the
  `STATE_STORAGE_ACCOUNT` repository variable before `terraform init`.
- **A current conftest release is installed in CI.** The rules use `import rego.v1`, which
  the older bundled action cannot parse, so the workflow downloads a pinned release.
- **The gate matrix does not cancel on first failure.** `fail-fast: false` lets every
  stage report, and prevents a cancelled plan from leaving a stale state lock behind.

## Evidence schema and partition keys

| Container | Partition key | Holds |
|---|---|---|
| `assessments` | `/subscriptionId` | One document per Defender assessment and resource, per run |
| `roleassignments` | `/subscriptionId` | One document per role assignment, per run |
| `runs` | `/collector` | The ledger: one entry per collection run, with its trigger (`timer` or `manual`) and document count |
| `frameworks` | `/frameworkId` | The NIST 800-53 catalog subset (families and controls) |
| `mappings` | `/frameworkId` | The crosswalk from policies, components, gates and assessments to controls |

- **Why `/subscriptionId` for the two evidence containers.** Every report and every
  reproducing query is scoped to one subscription, so each query touches one partition. A
  second or third subscription lands in its own partition with no reshaping of the store,
  which is what the estate-size-independence requirement asks for. Write volume is one
  document per finding or assignment per night, far below the throughput of a single
  partition, so the key does not create a hot partition.
- **Why `/collector` for the run ledger.** Evidence documents upsert on deterministic IDs, so
  they carry only the latest `runId` and cannot show history. The `runs` container is what
  accumulates. Every query against it is "the runs of one collector", and it takes a few
  writes a day, so the key spreads nothing it needs to. The `trigger` field is what separates
  scheduled runs from manual ones.
- **Why `/frameworkId` for the catalog containers.** Reads are always "all documents for
  one framework". Adding a second framework adds a partition and leaves the first alone.
- **The second collector.** `collect_roles_nightly` snapshots role assignments into
  `roleassignments` with the same `runId` and `collectedAt` lineage and the same
  deterministic-ID upsert as the assessments collector. It runs as the existing collector
  identity, and Security Reader is enough to read assignments, so no role is added.

