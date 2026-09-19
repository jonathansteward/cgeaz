# --- The collector Function App: timer-triggered Python, managed identity, zero keys. ---
# One app for collectors, a separate app (stage 04) for reporting: the Function App is
# the identity boundary, and no identity both writes evidence and generates reports.

# Internal plumbing storage for the Functions runtime (NOT the evidence store —
# that account has shared keys disabled; this one is the app's own scratch space).
resource "azurerm_storage_account" "func_internal" {
  #checkov:skip=CKV_AZURE_59:Reached by the Function Apps and the deployer over the public endpoint; access is identity-only. A private endpoint costs about $7 a month per account, out of scope for a sandbox.
  #checkov:skip=CKV_AZURE_206:LRS is enough for a sandbox; the WORM policy, not replication, is the integrity control.
  #checkov:skip=CKV_AZURE_33:The queue service is not used by this runtime account.
  #checkov:skip=CKV2_AZURE_38:Evidence retention is the WORM policy on the reports container; runtime accounts hold no evidence.
  #checkov:skip=CKV2_AZURE_33:Private endpoints cost about $7 a month each; out of scope for a sandbox.
  #checkov:skip=CKV2_AZURE_1:Customer-managed keys need a Key Vault and a key. The baseline audits this with cge-storage-cmk and the finding is accepted.
  #checkov:skip=CKV2_AZURE_40:The Functions runtime requires the account key; this account holds no evidence.
  #checkov:skip=CKV2_AZURE_41:No SAS tokens are issued for this account.
  name                            = "stgrcfunc${random_string.suffix.result}"
  resource_group_name             = local.evidence_rg
  location                        = var.functions_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = local.common_tags
}

resource "azurerm_service_plan" "collectors" {
  #checkov:skip=CKV_AZURE_212:Consumption (Y1) plans have no instance count to set.
  #checkov:skip=CKV_AZURE_225:Consumption (Y1) plans have no zone redundancy option; pay-per-execution is the point for a sandbox.
  name                = "asp-grc-collectors-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption: pay per execution. Pennies.
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "collectors" {
  #checkov:skip=CKV_AZURE_221:Reached by the timer host and by callers holding function keys; private access needs a VNet and a paid plan.
  name                       = "func-grc-collectors-${random_string.suffix.result}"
  resource_group_name        = local.evidence_rg
  location                   = var.functions_location
  service_plan_id            = azurerm_service_plan.collectors.id
  https_only                 = true
  storage_account_name       = azurerm_storage_account.func_internal.name
  storage_account_access_key = azurerm_storage_account.func_internal.primary_access_key

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    "COSMOS_ENDPOINT"                = azurerm_cosmosdb_account.evidence.endpoint
    "COSMOS_DATABASE"                = azurerm_cosmosdb_sql_database.grc.name
    "SUBSCRIPTION_ID"                = local.subscription
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    "ENABLE_ORYX_BUILD"              = "true"
  }

  tags = local.common_tags

  # Zip deploy with a remote build (the deploy step in labs/04-evidence and labs/05-reports)
  # removes this setting from the running app after it has done its job. Without this,
  # every nightly drift run would report the same non-change as drift.
  lifecycle {
    ignore_changes = [app_settings["ENABLE_ORYX_BUILD"]]
  }
}

# --- The collector identity's whitelist: read posture, write evidence. Nothing else. ---

# Security Reader at the subscription: read Defender assessments, change nothing.
resource "azurerm_role_assignment" "collector_security_reader" {
  scope                = "/subscriptions/${local.subscription}"
  role_definition_name = "Security Reader"
  principal_id         = azurerm_linux_function_app.collectors.identity[0].principal_id
}

# Cosmos data-plane write. "Cosmos DB Built-in Data Contributor" (00000000-0000-0000-0000-000000000002)
# is a Cosmos-native data-plane role, not an ARM role — control plane vs data plane, again.
resource "azurerm_cosmosdb_sql_role_assignment" "collector_cosmos_write" {
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  role_definition_id  = "${azurerm_cosmosdb_account.evidence.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = azurerm_linux_function_app.collectors.identity[0].principal_id
  scope               = azurerm_cosmosdb_account.evidence.id
}
