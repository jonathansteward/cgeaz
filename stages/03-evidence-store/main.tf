locals {
  evidence_rg  = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  subscription = data.terraform_remote_state.foundation.outputs.subscription_id
  common_tags = {
    env     = var.environment
    purpose = "grc-evidence-plane"
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# --- Cosmos DB: the evidence database we OWN. Serverless; pennies at lab scale. ---

resource "azurerm_cosmosdb_account" "evidence" {
  #checkov:skip=CKV_AZURE_100:Customer-managed keys need a Key Vault and a key; the account is identity-only and the finding is accepted.
  #checkov:skip=CKV_AZURE_101:No private endpoint in a sandbox. Local authentication is disabled, so access is Entra ID only. cge-cosmos-no-public-access flags it and the finding is accepted.
  #checkov:skip=CKV_AZURE_99:Restricting by IP or VNet needs a fixed egress address, which the Consumption plan does not have.
  #checkov:skip=CKV_AZURE_140:False positive: local_authentication_enabled = false is set; the check reads the deprecated attribute.
  name                = "cosmos-grc-evidence-${random_string.suffix.result}"
  location            = var.location
  resource_group_name = local.evidence_rg
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  # Identity-only access: no key-based auth against the evidence database.
  # local_authentication_disabled was deprecated in favour of local_authentication_enabled
  # (removed in azurerm v5.0); the boolean inverts, so disabled=true becomes enabled=false.
  local_authentication_enabled = false

  # No key-based metadata writes either: management-plane changes go through Entra ID roles.
  access_key_metadata_writes_enabled = false

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }

  tags = local.common_tags
}

resource "azurerm_cosmosdb_sql_database" "grc" {
  name                = "grc"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
}

# assessments: one document per finding per run. Partitioned by subscription+date query pattern.
resource "azurerm_cosmosdb_sql_container" "assessments" {
  name                = "assessments"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/subscriptionId"]
}

# frameworks: CSF 2.0 / 800-53 catalogs as records we own.
resource "azurerm_cosmosdb_sql_container" "frameworks" {
  name                = "frameworks"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/frameworkId"]
}

# mappings: the crosswalk — which assessment satisfies which control in which framework.
resource "azurerm_cosmosdb_sql_container" "mappings" {
  name                = "mappings"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/frameworkId"]
}

# roleassignments: who held which role, at which scope, at each collection run. Partitioned
# by subscription like assessments: every query the reports and KQL-adjacent checks run is
# scoped to one subscription, and a new subscription lands in its own partition with no
# reshaping. The write volume is one document per assignment per night, far below the
# single-partition throughput limit, so this key will not create a hot partition.
resource "azurerm_cosmosdb_sql_container" "roleassignments" {
  name                = "roleassignments"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/subscriptionId"]
}

# runs: the ledger of collection runs. Evidence documents upsert on deterministic IDs and so
# carry only the latest runId; this container is what accumulates. Partitioned by collector:
# the queries are "all runs of collector X", and the write rate is a handful of entries a day.
resource "azurerm_cosmosdb_sql_container" "runs" {
  name                = "runs"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/collector"]
}

# --- Evidence artifact storage: WORM reports container, zero shared keys. ---

resource "azurerm_storage_account" "evidence" {
  #checkov:skip=CKV_AZURE_59:Reached by the Function Apps and the deployer over the public endpoint; access is identity-only. A private endpoint costs about $7 a month per account, out of scope for a sandbox.
  #checkov:skip=CKV_AZURE_206:LRS is enough for a sandbox; the WORM policy, not replication, is the integrity control.
  #checkov:skip=CKV_AZURE_33:The queue service is not used by the evidence account.
  #checkov:skip=CKV2_AZURE_38:Evidence retention is the WORM policy on the reports container; runtime accounts hold no evidence.
  #checkov:skip=CKV2_AZURE_33:Private endpoints cost about $7 a month each; out of scope for a sandbox.
  #checkov:skip=CKV2_AZURE_1:Customer-managed keys need a Key Vault and a key. The baseline audits this with cge-storage-cmk and the finding is accepted.
  name                     = "stgrcevid${random_string.suffix.result}"
  resource_group_name      = local.evidence_rg
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # The store's front door has one kind of lock: identity.
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false

  blob_properties {
    versioning_enabled = true
  }

  tags = local.common_tags
}

resource "azurerm_storage_container" "reports" {
  #checkov:skip=CKV2_AZURE_21:Read logging on the WORM container adds ingestion cost; administrative activity is already in the Activity Log.
  name               = "reports"
  storage_account_id = azurerm_storage_account.evidence.id
}

# WORM: write once, read many. Not access control — a platform guarantee.
resource "azurerm_storage_container_immutability_policy" "reports_worm" {
  # resource_manager_id was deprecated on azurerm_storage_container; id now returns the
  # resource-manager ID this argument expects.
  storage_container_resource_manager_id = azurerm_storage_container.reports.id
  immutability_period_in_days           = var.reports_retention_days
  # Unlocked for the course so teardown works. Production locks it — after which
  # nobody, including Microsoft, can shorten or remove it.
}

# The deployer needs blob DATA-plane access to verify WORM behavior and upload seeds —
# Owner is control-plane only (the 01_02 lesson, in production form).
data "azurerm_client_config" "current" {}

resource "azurerm_role_assignment" "deployer_blob_data" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

# The deployer also seeds the frameworks/mappings containers (labs/04's seed script),
# so it gets the Cosmos data-plane contributor role. Same reasoning as the blob role above.
resource "azurerm_cosmosdb_sql_role_assignment" "deployer_cosmos_write" {
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  role_definition_id  = "${azurerm_cosmosdb_account.evidence.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = data.azurerm_client_config.current.object_id
  scope               = azurerm_cosmosdb_account.evidence.id
}
