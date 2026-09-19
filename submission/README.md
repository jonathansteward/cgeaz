# Evidence package

| File | What it shows | How it was produced |
|---|---|---|
| `plans/<stage>.json` | `terraform plan` for each stage: every resource and the action Terraform would take. All `no-op`, so code and deployed state match | `terraform show -json`, reduced to address, type and action so no attribute values are included |
| `identities.json` | Every Azure role assignment in the subscription: principal, its display name, role and scope. Service principals keep their names (the two Function Apps, the remediation identity, the CI identity); people are redacted | `az role assignment list --all --include-inherited`, names resolved with `az ad sp show` |
| `cosmos-data-roles.json` | The Cosmos data-plane roles, which `az role assignment list` does not show: the collector writes, the reporter only reads | `az cosmosdb sql role assignment list` |
| `policies.json` | The custom policy definitions that exist in Azure, the policies inside the baseline initiative, and the assignments with their enforcement mode | `az policy definition list`, `az policy set-definition show`, `az policy assignment list` |
| `reports/` | A generated POA&M (JSON and Excel), SAR and OSCAL System Security Plan, as written to the WORM container. The SSP validates against the official OSCAL 1.1.2 schema (`validate_ssp.py`) | Downloaded from the `reports` container |
| `run-history.json` | The collection run ledger: one entry per run, with its trigger (`timer` or `manual`) | Query of the Cosmos `runs` container |
| `worm-denied.json` | Two attempts to delete blobs in the immutable `reports` container, both refused (`BlobImmutableDueToPolicy`) | `az storage blob delete` output |
| `gate-blocked.json` | A pull request whose change violated a gate rule, the failing check and its message | GitHub Actions run for the closed pull request |

How this package is meant to be cross-checked against the code: `stages/*/policies.tf` and
`stages/06-enforcement/main.tf` declare seven custom policy definitions, and `policies.json`
shows seven defined in Azure, six inside the baseline initiative and one remediation policy,
with two assignments. The role assignments the Terraform declares match `identities.json`
and `cosmos-data-roles.json`, and every plan in `plans/` has only `no-op` actions.

The subscription and tenant identifiers that appear are identifiers, not credentials.
Timer entries in `run-history.json` accumulate as the schedules fire: `collect_nightly`
(05:00 UTC) and `collect_roles_nightly` (05:30 UTC).
