# CGE-AZ Pipeline Starter

The lab and capstone repo for **CGE-AZ: Certified GRC Engineer — Azure Specialty**
(GRC Engineering Club Training Academy).

Over six labs you build a complete, automated GRC engineering pipeline in your own
Azure subscription:

```
1 Discovery → 2 Activation → 3 Evidence Store → 4 Reporting → 5 Narrative → 6 Enforcement ↺
   detect        enable         Cosmos + WORM      SAR/POA&M      AI digest     Azure Policy
   what runs     what's         Blob + collector   OSCAL SSP      (describes,   + remediation
                 missing        Functions          from the       never         identity
                                                   store ONLY     decides)
```

Automated, continuous, defensible, self-correcting. Most tooling reports findings —
this pipeline reports them **and fixes them**, and every fix shows up, documented, in
the next collection.

## Start here

1. **[docs/SETUP.md](docs/SETUP.md)** — one-time setup (free account, providers,
   regional quirks, cost guardrails). Do not skip it.
2. **labs/01-sandbox → labs/06-loop** — one lab per course domain, in order.
3. **[docs/VALIDATION-LOG.md](docs/VALIDATION-LOG.md)** — every lab was run end-to-end
   on a brand-new free account before shipping; this is what broke and how the labs
   route around it. If a step surprises you, look here first.

## Layout

```
stages/      one directory per pipeline stage — each a Terraform root module with its own state
functions/   the collector and report generators (Python, timer-triggered, managed identity)
labs/        the six lab guides + helper scripts
policy/      OPA/conftest rules that gate this repo's own changes
queries/     KQL detections for the FAFO operating rules
docs/        setup guide, architecture, control mappings, validation log
submission/  the evidence package: plans, identities, reports, run history, WORM proof
.github/     the compliance gate (PR) and drift detection (nightly)
```

Architecture, identity boundaries and the reasoning behind non-obvious choices are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Every policy, collector and gate rule is
mapped to NIST 800-53 in [docs/CONTROLS.md](docs/CONTROLS.md).

## Deploy order (from an empty subscription)

1. **Prerequisites.** An Azure subscription, `az`, `terraform` (≥ 1.9), `python3`, `gh`.
   Register the resource providers listed in [docs/SETUP.md](docs/SETUP.md).
2. **Sandbox and hierarchy.** Follow `labs/01-sandbox` to create the `mg-grc` management
   group hierarchy and budget guardrails. Optionally seed a small estate with
   `labs/01-sandbox/seed-estate.sh` so discovery has material to work on.
3. **Remote state.** Run `labs/03-foundation/bootstrap.sh`. It creates the state storage
   account and writes `labs/03-foundation/backend.hcl`.
4. **Stages, in order.** In each of `stages/01-foundation`, `02-activation`,
   `03-evidence-store`, `04-reporting`, `06-enforcement`:
   ```bash
   terraform init -backend-config=../../labs/03-foundation/backend.hcl
   terraform plan
   terraform apply
   ```
   Later stages read earlier stages' outputs, so the order matters.
5. **Function code.** Zip-deploy `functions/collect_assessments` to the collector app and
   `functions/reports` to the reporting app (`az functionapp deployment source config-zip`).
6. **Seed the framework data.** `python3 labs/04-evidence/seed_800_53.py` writes the
   NIST 800-53 catalog and crosswalk into Cosmos.
7. **Arm CI.** Run `labs/06-loop/arm-your-fork.sh <github-user>` and set the printed
   repository variables. Protect `main` with the four `gate (…)` checks.
8. **Verify.** Call `collect_now` and `collect_roles_now`, then `poam_now`, `sar_now` and `ssp_now`,
   and reproduce a SAR number with the query in "Reproducing a report number" below.

## Static analysis

Run before opening a PR: `terraform fmt -recursive stages/`, `terraform validate` per
stage, `tflint --chdir stages/<stage>` (configuration in `.tflint.hcl`; run `tflint --init`
once) and `checkov -d stages`. checkov reports no failed checks. Each skipped check carries
an inline `#checkov:skip=<id>:<reason>` comment in the resource explaining why. The
reasoning is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The compliance gate then
runs the plan through the conftest rules in `policy/`.

## FAFO operating rules

FAFO is the fictional company this estate belongs to. Its rules, which the detections in
`queries/` enforce:

| Rule | Value |
|---|---|
| Business hours for administrative changes | 08:00 to 18:00 Eastern, Monday to Friday |
| Approved regions | `eastus`, `eastus2`, `centralus` (plus `global` resources) |
| Required tags | `env`, `owner`, `costcenter`, `dataclassification` |
| Data at rest and in transit | TLS 1.2 or higher; no public blob access; customer-managed keys wanted |

Detections:
- `queries/fafo_after_hours_admin_writes.kql` — administrative writes and deletes outside business hours, by caller.
- `queries/fafo_unapproved_regions.kql` — successful writes that create resources outside the approved regions.
- `queries/tripwire_human_writes_to_governed_rgs.kql` — a person changing a governed resource group directly, outside the repo and CI.

`stages/01-foundation/alerts.tf` schedules all three hourly against the Log Analytics workspace and emails the owner.

## Framework track: NIST 800-53

The pipeline maps to **NIST 800-53**. It suits a US-federal-shaped estate like FAFO's
and it is the catalog the Azure Policy compliance tooling and the OSCAL format speak.
The store holds a deliberate subset, not the whole catalog: the 26 controls this
pipeline actually serves, grouped into nine families, and a crosswalk that maps every
policy, component, gate rule and observed Defender assessment to those controls
(`labs/04-evidence/seed_800_53.py`, Cosmos containers `frameworks` and `mappings`).
[docs/CONTROLS.md](docs/CONTROLS.md) is the human-readable copy, and
`seed_800_53.py --check` fails if the two drift apart.

## What this repository adds to the starter

- Three custom policies beyond the taught set: `cge-min-tls12-storage`,
  `cge-cosmos-no-public-access`, `cge-storage-cmk`. Each has a parameterized effect
  (Audit by default), a blast-radius note in code, and a CONTROLS.md mapping.
- A second collector and container: `roleassignments` snapshots of who holds which role.
- Two FAFO-specific KQL detections and a human-change tripwire, all scheduled as alert rules; an 800-53 catalog and crosswalk; an OSCAL System Security Plan generated from the store; and an architecture doc.
- A gate that installs a current conftest and generates its own backend config, and
  that does not cancel sibling stages on failure.

## Reproducing a report number

The SAR's "Open findings" figure equals the number of Unhealthy documents for the run
named in its header:

```sql
SELECT VALUE COUNT(1) FROM c WHERE c.runId = "<runId from the SAR header>" AND c.status = "Unhealthy"
```

Any finding traces by its assessment ID to one document in the `assessments` container,
carrying `assessmentId`, `resourceId`, `collectedAt` and `runId`.

## The rules the repo lives by

- **Discovers first, then acts.** Stage one changes nothing; activation closes only
  the measured gap.
- **Collect once.** One assessment document serves every framework through the
  mappings crosswalk.
- **Reports read from Cosmos only.** Every number is a fact with a receipt.
- **Zero keys.** Managed identity end to end; the evidence store disables shared keys
  entirely.
- **Automation acts; humans authorize.** Escalation (audit → dry-run → enforce) is a
  reviewed one-line diff.
- **Changes go through the repo, never the portal.** The drift detectors are watching —
  that's the point of them.

## Capstone

The graded capstone is this pipeline, running in its own subscription, with its own
modifications (see "What this repository adds to the starter"). Rubric and submission
checklist: `docs/RUBRIC.md`. The evidence package is under `submission/`. Stage 5 is
optional and is not deployed here.

---

*Built by the community, for the community · www.grcengclub.com*
