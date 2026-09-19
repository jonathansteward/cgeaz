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
     | jq --arg s "$s" '{stage: $s, format_version, resource_changes: [.resource_changes[]
         | {address, type, actions: .change.actions}
           + (if (.type | test("policy|role_assignment|scheduled_query|cosmosdb_sql_container|storage_container|management_group|user_assigned_identity|action_group"))
              then {name: (.change.after.name // null), display_name: (.change.after.display_name // null)} else {} end)
           + (if .type == "azurerm_management_group_policy_set_definition"
              then {policy_definition_references: (.change.after.policy_definition_reference | length)} else {} end)]}' \
     > "../../submission/plans/$s.json"
   rm -f "/tmp/$s.plan")
  echo "  $s"
done

echo "== identities"
RAW=$(az role assignment list --all --include-inherited -o json)
NAMES="{}"
for pid in $(echo "$RAW" | jq -r '[.[] | select(.principalType == "ServicePrincipal") | .principalId] | unique | .[]'); do
  name=$(az ad sp show --id "$pid" --query displayName -o tsv 2>/dev/null || echo "unresolved")
  NAMES=$(echo "$NAMES" | jq --arg k "$pid" --arg v "$name" '. + {($k): $v}')
done
# Service principals keep their display names (they name the pipeline identities); people
# are redacted, and so are group and user object names beyond the group's own name.
echo "$RAW" | jq --argjson names "$NAMES" '[.[] | {
    principalId, principalType,
    principalDisplayName: (if .principalType == "ServicePrincipal" then ($names[.principalId] // "unresolved")
                           elif .principalType == "User" then "redacted-user"
                           else (.principalName // "group") end),
    roleDefinitionName, scope, createdOn}]' > submission/identities.json
echo "  $(jq length submission/identities.json) assignments"

echo "== Cosmos data-plane roles (not shown by az role assignment list)"
COSMOS=$(cd stages/03-evidence-store && terraform output -raw cosmos_account_name)
CNAMES="{}"
for pid in $(az cosmosdb sql role assignment list -a "$COSMOS" -g "$EVID_RG" -o json | jq -r '[.[].principalId] | unique | .[]'); do
  name=$(az ad sp show --id "$pid" --query displayName -o tsv 2>/dev/null || echo "redacted-user")
  CNAMES=$(echo "$CNAMES" | jq --arg k "$pid" --arg v "$name" '. + {($k): $v}')
done
az cosmosdb sql role assignment list -a "$COSMOS" -g "$EVID_RG" -o json \
  | jq --argjson names "$CNAMES" '[.[] | {principalId, principalDisplayName: ($names[.principalId] // "redacted-user"),
      role: (if (.roleDefinitionId | endswith("0000-000000000001")) then "Cosmos DB Built-in Data Reader"
             elif (.roleDefinitionId | endswith("0000-000000000002")) then "Cosmos DB Built-in Data Contributor"
             else .roleDefinitionId end), scope}]' > submission/cosmos-data-roles.json
echo "  $(jq length submission/cosmos-data-roles.json) data-plane assignments"

echo "== policies (what is actually defined and assigned)"
MG=/providers/Microsoft.Management/managementGroups/mg-grc-sandbox
DEFS=$(az policy definition list --management-group mg-grc-sandbox --query "[?policyType=='Custom'].{name:name, displayName:displayName, mode:mode}" -o json)
INIT=$(az policy set-definition show --name cge-grc-baseline --management-group mg-grc-sandbox -o json \
  | jq '{name, displayName, referenceCount: (.policyDefinitions | length), references: [.policyDefinitions[].policyDefinitionId | split("/") | .[-1]] | sort}')
ASSIGN=$(az policy assignment list --scope "$MG" -o json \
  | jq '[.[] | {name, displayName, enforcementMode, scope, identityType: (.identity.type // "none")}]')
jq -n --argjson d "$DEFS" --argjson i "$INIT" --argjson a "$ASSIGN" \
  '{customDefinitions: ($d | sort_by(.name)), initiative: $i, assignments: ($a | sort_by(.name))}' > submission/policies.json
echo "  $(jq '.customDefinitions | length' submission/policies.json) custom definitions, initiative references $(jq .initiative.referenceCount submission/policies.json), $(jq '.assignments | length' submission/policies.json) assignments"

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
