locals {
  evidence_rg      = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  cosmos_endpoint  = data.terraform_remote_state.evidence.outputs.cosmos_endpoint
  cosmos_id        = data.terraform_remote_state.evidence.outputs.cosmos_account_id
  cosmos_name      = data.terraform_remote_state.evidence.outputs.cosmos_account_name
  evidence_storage = data.terraform_remote_state.evidence.outputs.evidence_storage_account
  common_tags = {
    env     = var.environment
    purpose = "grc-reporting"
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

data "azurerm_storage_account" "evidence" {
  name                = local.evidence_storage
  resource_group_name = local.evidence_rg
}

resource "azurerm_storage_account" "func_internal" {
  #checkov:skip=CKV_AZURE_59:Reached by the Function Apps and the deployer over the public endpoint; access is identity-only. A private endpoint costs about $7 a month per account, out of scope for a sandbox.
  #checkov:skip=CKV_AZURE_206:LRS is enough for a sandbox; the WORM policy, not replication, is the integrity control.
  #checkov:skip=CKV_AZURE_33:The queue service is not used by this runtime account.
  #checkov:skip=CKV2_AZURE_38:Evidence retention is the WORM policy on the reports container; runtime accounts hold no evidence.
  #checkov:skip=CKV2_AZURE_33:Private endpoints cost about $7 a month each; out of scope for a sandbox.
  #checkov:skip=CKV2_AZURE_1:Customer-managed keys need a Key Vault and a key. The baseline audits this with cge-storage-cmk and the finding is accepted.
  #checkov:skip=CKV2_AZURE_40:The Functions runtime requires the account key; this account holds no evidence.
  #checkov:skip=CKV2_AZURE_41:No SAS tokens are issued for this account.
  name                            = "stgrcrpt${random_string.suffix.result}"
  resource_group_name             = local.evidence_rg
  location                        = var.functions_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = local.common_tags
}

resource "azurerm_service_plan" "reporting" {
  #checkov:skip=CKV_AZURE_212:Consumption (Y1) plans have no instance count to set.
  #checkov:skip=CKV_AZURE_225:Consumption (Y1) plans have no zone redundancy option; pay-per-execution is the point for a sandbox.
  name                = "asp-grc-reporting-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "reporting" {
  #checkov:skip=CKV_AZURE_221:Reached by the timer host and by callers holding function keys; private access needs a VNet and a paid plan.
  name                       = "func-grc-reporting-${random_string.suffix.result}"
  resource_group_name        = local.evidence_rg
  location                   = var.functions_location
  service_plan_id            = azurerm_service_plan.reporting.id
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
    "COSMOS_ENDPOINT"                = local.cosmos_endpoint
    "COSMOS_DATABASE"                = "grc"
    "REPORTS_ACCOUNT_URL"            = data.azurerm_storage_account.evidence.primary_blob_endpoint
    "REPORTS_CONTAINER"              = "reports"
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

# --- The reporting identity's whitelist — the mirror image of the collector's. ---
# Cosmos READ (built-in Data Reader), Blob WRITE into the WORM container. No path to
# live platform data: no Security Reader, no Cosmos write. SoD, enforced by scopes.

resource "azurerm_cosmosdb_sql_role_assignment" "reporter_cosmos_read" {
  resource_group_name = local.evidence_rg
  account_name        = local.cosmos_name
  role_definition_id  = "${local.cosmos_id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
  principal_id        = azurerm_linux_function_app.reporting.identity[0].principal_id
  scope               = local.cosmos_id
}

resource "azurerm_role_assignment" "reporter_blob_write" {
  scope                = data.azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_function_app.reporting.identity[0].principal_id
}

output "reporting_function_app" {
  value = azurerm_linux_function_app.reporting.name
}

output "reporter_principal_id" {
  value = azurerm_linux_function_app.reporting.identity[0].principal_id
}
