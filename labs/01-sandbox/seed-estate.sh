#!/usr/bin/env bash
# Seed a small, cheap "enterprise-looking" estate into the current subscription so
# discovery, assessments, and reports have real material to work on.
#
# Twelve resources across three resource groups (network, data, apps). Most are free;
# the rest cost pennies a month at idle. Several are deliberately misconfigured so the
# policies and Defender have something to find. None of the misconfigurations exposes
# data: the weak storage account is empty and the open NSG rule guards no hosts.
#
#   ./seed-estate.sh              deploy (idempotent: safe to re-run)
#   ./seed-estate.sh --dry-run    print what would be created, change nothing
#   ./seed-estate.sh --destroy    delete the three estate resource groups
#
# Optional environment: LOCATION (default: the sandbox resource group's region),
# OWNER_TAG (default: platform-team).
set -uo pipefail

MODE="deploy"
case "${1:-}" in
  --dry-run) MODE="dry-run" ;;
  --destroy) MODE="destroy" ;;
  "") ;;
  *) echo "usage: $0 [--dry-run|--destroy]" >&2; exit 2 ;;
esac

SUB_ID=$(az account show --query id -o tsv) || { echo "az login first" >&2; exit 1; }
SUB_NAME=$(az account show --query name -o tsv)
LOCATION="${LOCATION:-$(az group show -n rg-grc-sandbox-dev --query location -o tsv 2>/dev/null || echo eastus)}"
OWNER_TAG="${OWNER_TAG:-platform-team}"

# Stable suffix from the subscription ID, so re-runs reuse the same global names.
SUF=$(printf '%s' "$SUB_ID" | shasum -a 256 | cut -c1-6)

RG_NET="rg-estate-network-dev"
RG_DATA="rg-estate-data-dev"
RG_APPS="rg-estate-apps-dev"

TAGS_STD="env=dev owner=$OWNER_TAG costcenter=cc-1042 dataclassification=internal"
TAGS_CONF="env=dev owner=$OWNER_TAG costcenter=cc-2210 dataclassification=confidential"
TAGS_MIN="owner=$OWNER_TAG"   # deliberately missing env and costcenter

OK=0; FAIL=0
step() { printf '%-58s' "$1"; }
ok()   { echo "ok";   OK=$((OK+1)); }
bad()  { echo "FAILED"; FAIL=$((FAIL+1)); echo "    $1" | head -3 >&2; }

# run <label> <command...>: run quietly, report ok/FAILED, keep going either way.
run() {
  local label="$1"; shift
  step "$label"
  if [ "$MODE" = "dry-run" ]; then echo "(dry-run)"; return 0; fi
  local out
  if out=$("$@" 2>&1 >/dev/null); then ok; else bad "$out"; fi
}

echo "Subscription : $SUB_NAME ($SUB_ID)"
echo "Location     : $LOCATION"
echo "Mode         : $MODE"
echo

if [ "$MODE" = "destroy" ]; then
  for rg in "$RG_NET" "$RG_DATA" "$RG_APPS"; do
    step "delete resource group $rg"
    if az group exists -n "$rg" | grep -q true; then
      if az group delete -n "$rg" --yes --no-wait >/dev/null 2>&1; then echo "requested (async)"; else echo "FAILED"; fi
    else
      echo "not present"
    fi
  done
  echo
  echo "Deletion runs in the background. Soft-deleted Key Vaults keep their name for"
  echo "7 days unless purged: az keyvault purge --name kv-estate-$SUF"
  exit 0
fi

# ---- providers -------------------------------------------------------------------
echo "== Resource providers =="
for ns in Microsoft.Network Microsoft.Storage Microsoft.KeyVault Microsoft.ManagedIdentity \
          Microsoft.OperationalInsights Microsoft.Insights Microsoft.ServiceBus; do
  state=$(az provider show --namespace "$ns" --query registrationState -o tsv 2>/dev/null || echo unknown)
  step "$ns ($state)"
  if [ "$state" = "Registered" ]; then echo "ok"
  elif [ "$MODE" = "dry-run" ]; then echo "(would register)"
  elif az provider register --namespace "$ns" --wait >/dev/null 2>&1; then echo "registered"; else echo "FAILED"; FAIL=$((FAIL+1)); fi
done
echo

# ---- resource groups -------------------------------------------------------------
echo "== Resource groups =="
run "$RG_NET"  az group create -n "$RG_NET"  -l "$LOCATION" --tags $TAGS_STD
run "$RG_DATA" az group create -n "$RG_DATA" -l "$LOCATION" --tags $TAGS_CONF
run "$RG_APPS" az group create -n "$RG_APPS" -l "$LOCATION" --tags $TAGS_MIN   # no env tag: trips the tag policy
echo

echo "== The twelve resources =="

# 1. Virtual network with two subnets (free)
run " 1 vnet-estate-hub" az network vnet create -g "$RG_NET" -n vnet-estate-hub -l "$LOCATION" \
  --address-prefixes 10.20.0.0/16 --subnet-name snet-web --subnet-prefixes 10.20.1.0/24 --tags $TAGS_STD
run "   subnet snet-data" az network vnet subnet create -g "$RG_NET" --vnet-name vnet-estate-hub \
  -n snet-data --address-prefixes 10.20.2.0/24

# 2. Network security group, deliberately permissive: SSH open to the internet (free).
#    Not attached to any subnet or NIC, so it exposes nothing.
run " 2 nsg-estate-web" az network nsg create -g "$RG_NET" -n nsg-estate-web -l "$LOCATION" --tags $TAGS_STD
run "   rule allow-ssh-any (misconfigured)" az network nsg rule create -g "$RG_NET" --nsg-name nsg-estate-web \
  -n allow-ssh-any --priority 100 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes '*' --destination-port-ranges 22

# 3. Route table (free)
run " 3 rt-estate-egress" az network route-table create -g "$RG_NET" -n rt-estate-egress -l "$LOCATION" --tags $TAGS_STD

# 4. Application security group (free)
run " 4 asg-estate-web" az network asg create -g "$RG_NET" -n asg-estate-web -l "$LOCATION" --tags $TAGS_STD

# 5. Hardened storage account (LRS, pennies)
run " 5 stestatedata$SUF (hardened)" az storage account create -g "$RG_DATA" -n "stestatedata$SUF" -l "$LOCATION" \
  --sku Standard_LRS --kind StorageV2 --min-tls-version TLS1_2 --allow-blob-public-access false \
  --https-only true --tags $TAGS_CONF

# 6. Storage account left in a weak posture: shared keys on and plain HTTP allowed. Public blob
#    access is NOT enabled here, because the baseline's cge-deny-public-blob policy denies it
#    (the first version of this script tried, and the policy blocked it).
run " 6 stestatelogs$SUF (misconfigured)" az storage account create -g "$RG_DATA" -n "stestatelogs$SUF" -l "$LOCATION" \
  --sku Standard_LRS --kind StorageV2 --min-tls-version TLS1_2 --allow-blob-public-access false \
  --allow-shared-key-access true --https-only false --tags $TAGS_STD

# 7. Key Vault, RBAC mode. Purge protection is left off (the default); the service does not
#    accept an explicit false. Standard tier, per-operation pricing.
run " 7 kv-estate-$SUF (no purge protection)" az keyvault create -g "$RG_DATA" -n "kv-estate-$SUF" -l "$LOCATION" \
  --enable-rbac-authorization true --retention-days 7 --tags $TAGS_CONF

# 8. User-assigned managed identity (free)
run " 8 id-estate-app" az identity create -g "$RG_APPS" -n id-estate-app -l "$LOCATION" --tags $TAGS_MIN

# 9. Log Analytics workspace (pay per GB; idle cost is zero)
run " 9 law-estate" az monitor log-analytics workspace create -g "$RG_APPS" -n law-estate -l "$LOCATION" \
  --sku PerGB2018 --retention-time 30 --tags $TAGS_MIN

# 10. Application Insights, workspace-based (pay per GB). Uses the ARM API directly so no CLI extension is needed.
step "10 appi-estate"
if [ "$MODE" = "dry-run" ]; then echo "(dry-run)"; else
  LAW_ID=$(az monitor log-analytics workspace show -g "$RG_APPS" -n law-estate --query id -o tsv 2>/dev/null)
  if [ -n "$LAW_ID" ] && out=$(az resource create -g "$RG_APPS" -n appi-estate -l "$LOCATION" \
      --resource-type Microsoft.Insights/components --api-version 2020-02-02 \
      --properties "{\"Application_Type\":\"web\",\"WorkspaceResourceId\":\"$LAW_ID\"}" 2>&1 >/dev/null); then ok
  else bad "${out:-log analytics workspace missing}"; fi
fi

# 11. Action group for security-operations notifications (free)
run "11 ag-estate-secops" az monitor action-group create -g "$RG_APPS" -n ag-estate-secops --short-name secops \
  --tags $TAGS_MIN

# 12. Service Bus namespace, Basic tier (per-operation pricing, effectively free at idle)
run "12 sb-estate-$SUF" az servicebus namespace create -g "$RG_APPS" -n "sb-estate-$SUF" -l "$LOCATION" \
  --sku Basic --tags $TAGS_MIN

echo
echo "created: $OK   failed: $FAIL"
if [ "$MODE" = "deploy" ]; then
  echo
  echo "== Estate =="
  az resource list --query "[?starts_with(resourceGroup,'rg-estate-')].{group:resourceGroup,name:name,type:type}" \
    -o table 2>/dev/null
  echo
  echo "Remove everything with: $0 --destroy"
fi
[ "$FAIL" -eq 0 ]
