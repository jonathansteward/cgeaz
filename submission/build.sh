#!/usr/bin/env bash
# Regenerate the evidence package from the deployed environment. Run from the repo root,
# logged in with `az login`, with terraform, jq and python3 (azure-cosmos, azure-identity).
#
#   TF_VAR_owner_email=you@example.com TF_VAR_state_storage_account=<state account> \
#     PYTHON=python3 ./submission/build.sh
#
# gate-blocked.json records a closed pull request and is not regenerated here.
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
EVID_RG="${EVID_RG:-rg-grc-evidence-dev}"
mkdir -p submission/plans submission/reports

echo "== plans"
for s in 01-foundation 02-activation 03-evidence-store 04-reporting 06-enforcement; do
  (cd "stages/$s"
   terraform init -input=false -backend-config=../../labs/03-foundation/backend.hcl >/dev/null
   terraform plan -input=false -out="/tmp/$s.plan" >/dev/null
   terraform show -json "/tmp/$s.plan" \
     | jq --arg s "$s" '{stage: $s, format_version, resource_changes: [.resource_changes[] | {address, type, actions: .change.actions}]}' \
     > "../../submission/plans/$s.json"
   rm -f "/tmp/$s.plan")
  echo "  $s"
done

echo "== identities"
az role assignment list --all --include-inherited -o json \
  | jq '[.[] | {principalId, principalType, roleDefinitionName, scope, createdOn}]' > submission/identities.json

ACC=$(cd stages/03-evidence-store && terraform output -raw evidence_storage_account)

echo "== reports"
for b in $(az storage blob list --account-name "$ACC" -c reports --auth-mode login \
    --query "[?starts_with(name,'poam/') || starts_with(name,'sar/') || starts_with(name,'ssp/')].name" -o tsv); do
  az storage blob download --account-name "$ACC" -c reports -n "$b" \
    --file "submission/reports/$(basename "$b")" --auth-mode login --no-progress -o none
done

echo "== SSP schema check (skipped if jsonschema/regex are not installed)"
LATEST_SSP=$(ls -1 submission/reports/ssp-*.json 2>/dev/null | tail -1 || true)
if [ -n "$LATEST_SSP" ] && "$PYTHON" -c "import jsonschema, regex" 2>/dev/null; then
  "$PYTHON" submission/validate_ssp.py "$LATEST_SSP"
fi

echo "== run history"
COSMOS_ENDPOINT=$(cd stages/03-evidence-store && terraform output -raw cosmos_endpoint) "$PYTHON" - <<'PY'
import json, os
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
c = (CosmosClient(os.environ["COSMOS_ENDPOINT"], DefaultAzureCredential())
     .get_database_client("grc").get_container_client("runs"))
rows = sorted(c.query_items("SELECT c.collector, c.trigger, c.runId, c.collectedAt, c.documentsWritten FROM c",
                            enable_cross_partition_query=True), key=lambda r: r["collectedAt"])
json.dump({"source": "Cosmos container 'runs' (the collection run ledger). trigger is 'timer' for scheduled runs and 'manual' for runs started by a person.",
           "runs": rows}, open("submission/run-history.json", "w"), indent=2)
print(f"  {len(rows)} runs, {sum(r['trigger'] == 'timer' for r in rows)} from timers")
PY

echo "== WORM proof (both deletes are expected to be refused)"
LATEST_SAR=$(az storage blob list --account-name "$ACC" -c reports --prefix sar/ --auth-mode login --query "[-1].name" -o tsv)
attempt() {
  az storage blob delete --account-name "$ACC" -c reports -n "$1" --auth-mode login 2>&1 \
    | grep -E "ERROR|ErrorCode|Time:" | tr '\n' ' ' || true
}
R1=$(attempt worm-test.txt); R2=$(attempt "$LATEST_SAR")
POLICY=$(az storage container immutability-policy show --account-name "$ACC" -c reports -g "$EVID_RG" \
  --query "{retentionDays:immutabilityPeriodSinceCreationInDays,state:state}" -o json)
jq -n --arg acc "$ACC" --arg a "$R1" --arg b "$R2" --arg sar "$LATEST_SAR" --argjson p "$POLICY" \
  '{container: "reports", storageAccount: $acc, immutabilityPolicy: $p,
    attempts: [{blob: "worm-test.txt", command: "az storage blob delete", result: ($a | if test("BlobImmutableDueToPolicy") then "blocked" else "NOT BLOCKED" end), output: $a},
               {blob: $sar, command: "az storage blob delete", result: ($b | if test("BlobImmutableDueToPolicy") then "blocked" else "NOT BLOCKED" end), output: $b}]}' \
  > submission/worm-denied.json
jq -r '.attempts[] | "  \(.blob): \(.result)"' submission/worm-denied.json

echo "== scan"
if grep -rniE "@[a-z0-9.-]+\.(com|org|net)" submission --include='*.json' --include='*.md' | grep -v example; then
  echo "  email-like text found above: scrub it before committing"; exit 1
fi
command -v gitleaks >/dev/null && gitleaks detect --no-git --source submission --no-banner 2>&1 | tail -1
echo "done"
