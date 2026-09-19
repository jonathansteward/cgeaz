# Evidence package

Generated from the deployed environment. Nothing here is written by hand.

| File | What it shows | How it was produced |
|---|---|---|
| `plans/<stage>.json` | `terraform plan` for each stage: every resource and the action Terraform would take. All `no-op`, so code and deployed state match | `terraform show -json`, reduced to address, type and action so no attribute values are included |
| `identities.json` | Every role assignment in the subscription: principal, role, scope. Shows the runtime identities hold whitelist roles only | `az role assignment list --all --include-inherited`, with names and emails removed |
| `reports/` | A generated POA&M (JSON and Excel), SAR and OSCAL System Security Plan, as written to the WORM container. The SSP validates against the official OSCAL 1.1.2 schema (`validate_ssp.py`) | Downloaded from the `reports` container |
| `run-history.json` | The collection run ledger: one entry per run, with its trigger (`timer` or `manual`) | Query of the Cosmos `runs` container |
| `worm-denied.json` | Two attempts to delete blobs in the immutable `reports` container, both refused (`BlobImmutableDueToPolicy`) | `az storage blob delete` output |
| `gate-blocked.json` | A pull request whose change violated a gate rule, the failing check and its message | GitHub Actions run for the closed pull request |

The subscription and tenant identifiers that appear are identifiers, not credentials.
Timer entries in `run-history.json` accumulate as the schedules fire: `collect_nightly`
(05:00 UTC) and `collect_roles_nightly` (05:30 UTC).
