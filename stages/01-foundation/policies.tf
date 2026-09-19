# Three policies, one initiative, assigned once at mg-grc-sandbox.
# Every subscription that ever joins the sandbox group inherits all of it. (CSF: GV.PO, PR.DS, PR.PS)

# --- 1. Require the `env` tag on resource groups (inventory hygiene; POA&M owner resolution) ---

# blast radius: Audit by default, so nothing is blocked. Escalated to Deny (via
# tag_policy_effect), it blocks creating any resource group in mg-grc-sandbox
# without an env tag, including ones created by other pipelines.
# rollback: set tag_policy_effect back to "Audit" and merge.

resource "azurerm_policy_definition" "require_env_tag" {
  name                = "cge-require-env-tag-rg"
  display_name        = "Resource groups must carry an env tag"
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Resources/subscriptions/resourceGroups" },
        { field = "tags['env']", exists = "false" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 2. Deny public blob access on storage accounts (clear-cut, framework-mandated: earned Deny) ---

# blast radius: with Deny, blocks creating or updating any storage account in
# mg-grc-sandbox that allows public blob access. Existing accounts are not changed,
# only flagged. Cannot touch any other property.
# rollback: set public_blob_policy_effect to "Audit" and merge.

resource "azurerm_policy_definition" "deny_public_blob" {
  name                = "cge-deny-public-blob"
  display_name        = "Storage accounts must not allow public blob access"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", equals = "true" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 3. deployIfNotExists: storage accounts missing diagnostic settings get them, routed to the GRC workspace ---
# Logging that enforces its own coverage. Remediation runs AS the identity in identity.tf.

# blast radius: creates a diagnostic setting on storage accounts under mg-grc-sandbox
# that are missing one, sending Transaction metrics to the GRC workspace. Runs as the
# remediation identity (Monitoring Contributor). Cannot read blob data or change
# storage settings. Adds Log Analytics ingestion cost.
# rollback: remove the policy from the initiative; existing diagnostic settings remain.

resource "azurerm_policy_definition" "storage_diagnostics" {
  name                = "cge-dine-storage-diagnostics"
  display_name        = "Storage accounts must route diagnostics to the GRC workspace"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    workspaceId = {
      type     = "String"
      metadata = { displayName = "Log Analytics workspace resource ID" }
    }
  })

  policy_rule = jsonencode({
    if = {
      field  = "type"
      equals = "Microsoft.Storage/storageAccounts"
    }
    then = {
      effect = "DeployIfNotExists"
      details = {
        type = "Microsoft.Insights/diagnosticSettings"
        roleDefinitionIds = [
          # Monitoring Contributor
          "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
        ]
        existenceCondition = {
          allOf = [
            { field = "Microsoft.Insights/diagnosticSettings/workspaceId", equals = "[parameters('workspaceId')]" }
          ]
        }
        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              resourceName = { value = "[field('name')]" }
              workspaceId  = { value = "[parameters('workspaceId')]" }
              location     = { value = "[field('location')]" }
            }
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                resourceName = { type = "string" }
                workspaceId  = { type = "string" }
                location     = { type = "string" }
              }
              resources = [
                {
                  type       = "Microsoft.Storage/storageAccounts/providers/diagnosticSettings"
                  apiVersion = "2021-05-01-preview"
                  name       = "[concat(parameters('resourceName'), '/Microsoft.Insights/ds-to-grc-workspace')]"
                  properties = {
                    workspaceId = "[parameters('workspaceId')]"
                    metrics = [
                      { category = "Transaction", enabled = true }
                    ]
                  }
                }
              ]
            }
          }
        }
      }
    }
  })
}

# --- 4. Require TLS 1.2 or higher on storage accounts (data in transit; audit first) ---

# blast radius: Audit only, so nothing is blocked or changed. Escalated to Deny, it
# blocks creating or updating any storage account below TLS 1.2 in mg-grc-sandbox,
# and clients that still negotiate TLS 1.0/1.1 would fail to connect.
# rollback: set the effect back to "Audit" and merge.

resource "azurerm_policy_definition" "min_tls" {
  name                = "cge-min-tls12-storage"
  display_name        = "Storage accounts must require TLS 1.2 or higher"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/minimumTlsVersion", notIn = ["TLS1_2", "TLS1_3"] }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 5. Cosmos DB accounts must not allow public network access (network exposure; audit first) ---

# blast radius: Audit only, so nothing is blocked or changed. Escalated to Deny, it
# blocks creating or updating any Cosmos DB account in mg-grc-sandbox that leaves public
# network access enabled, and existing accounts would fail their next update until they
# move to private endpoints or a VNet.
# rollback: set cosmosPublicAccessEffect back to "Audit" and merge.

resource "azurerm_policy_definition" "cosmos_public_access" {
  name                = "cge-cosmos-no-public-access"
  display_name        = "Cosmos DB accounts must disable public network access"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.DocumentDB/databaseAccounts" },
        { field = "Microsoft.DocumentDB/databaseAccounts/publicNetworkAccess", notEquals = "Disabled" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 6. Storage accounts should encrypt with customer-managed keys (data at rest; audit first) ---

# blast radius: Audit only, so nothing is blocked or changed. Every storage account using
# Microsoft-managed keys, including the pipeline's own, will show as non-compliant, which
# is the intended finding. Escalated to Deny, it would block creating any storage account
# without a Key Vault key, so do not escalate until a key vault exists.
# rollback: set cmkEffect back to "Audit" or "Disabled" and merge.

resource "azurerm_policy_definition" "storage_cmk" {
  name                = "cge-storage-cmk"
  display_name        = "Storage accounts should use customer-managed keys"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/encryption.keySource", notEquals = "Microsoft.Keyvault" }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- The initiative: one assignment, whole-sandbox inheritance ---

# blast radius: the whole initiative applies to mg-grc-sandbox, so every current and
# future subscription in that group inherits all six policies.
# rollback: destroy the assignment; definitions stay but stop applying.

resource "azurerm_management_group_policy_set_definition" "grc_baseline" {
  name                = "cge-grc-baseline"
  display_name        = "CGE-AZ GRC Baseline"
  policy_type         = "Custom"
  management_group_id = azurerm_management_group.sandbox.id

  parameters = jsonencode({
    tagEffect        = { type = "String", defaultValue = "Audit" }
    publicBlobEffect = { type = "String", defaultValue = "Deny" }
    workspaceId      = { type = "String" }
    tlsEffect        = { type = "String", defaultValue = "Audit" }
    cosmosPublicAccessEffect  = { type = "String", defaultValue = "Audit" }
    cmkEffect                 = { type = "String", defaultValue = "Audit" }
  })

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.require_env_tag.id
    parameter_values = jsonencode({
      effect = { value = "[parameters('tagEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.deny_public_blob.id
    parameter_values = jsonencode({
      effect = { value = "[parameters('publicBlobEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.storage_diagnostics.id
    parameter_values = jsonencode({
      workspaceId = { value = "[parameters('workspaceId')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.min_tls.id
    parameter_values = jsonencode({
      effect = { value = "[parameters('tlsEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.cosmos_public_access.id
    parameter_values = jsonencode({
      effect = { value = "[parameters('cosmosPublicAccessEffect')]" }
    })
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.storage_cmk.id
    parameter_values = jsonencode({
      effect = { value = "[parameters('cmkEffect')]" }
    })
  }
}

resource "azurerm_management_group_policy_assignment" "grc_baseline" {
  name                 = "cge-grc-baseline"
  display_name         = "CGE-AZ GRC Baseline"
  policy_definition_id = azurerm_management_group_policy_set_definition.grc_baseline.id
  management_group_id  = azurerm_management_group.sandbox.id
  location             = var.location

  parameters = jsonencode({
    tagEffect        = { value = var.tag_policy_effect }
    publicBlobEffect = { value = var.public_blob_policy_effect }
    workspaceId      = { value = azurerm_log_analytics_workspace.grc.id }
  })

  # Remediation effects (deployIfNotExists) execute AS this identity.
  # Without this block, Terraform applies cleanly and remediation silently never runs.
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.remediation.id]
  }
}
