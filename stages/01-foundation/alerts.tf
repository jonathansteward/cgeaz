# Detection, the "who is touching reality" half of drift detection. drift.yml answers "does
# reality still match the code"; these scheduled queries answer "who has been changing
# reality, and when". The queries live in queries/ so they can be run by hand and reviewed in
# a PR; this file schedules them against the workspace the Activity Log is routed to.
# Mapped to 800-53 CA-7 and SI-4 in docs/CONTROLS.md.

# blast radius: sends email to the owner and nothing else. It reads the Activity Log, changes
# no resource, and costs a small per-rule charge for the hourly evaluation.
# rollback: destroy this file's resources, or set enabled = false on a rule.

resource "azurerm_monitor_action_group" "secops" {
  name                = "ag-grc-secops"
  resource_group_name = azurerm_resource_group.sandbox.name
  short_name          = "grcsecops"

  email_receiver {
    name                    = "owner"
    email_address           = var.owner_email
    use_common_alert_schema = true
  }

  tags = {
    env     = var.environment
    purpose = "cge-az-labs"
  }
}

locals {
  detections = {
    "fafo-after-hours-admin-writes" = {
      description = "FAFO rule: administrative changes happen 08:00-18:00 Eastern, Monday to Friday."
      query       = file("${path.module}/../../queries/fafo_after_hours_admin_writes.kql")
      severity    = 3
    }
    "fafo-unapproved-regions" = {
      description = "FAFO rule: resources are created only in the approved regions."
      query       = file("${path.module}/../../queries/fafo_unapproved_regions.kql")
      severity    = 2
    }
    "tripwire-human-writes-to-governed-rgs" = {
      description = "A person changed a governed resource group directly instead of through the repo and CI."
      query       = file("${path.module}/../../queries/tripwire_human_writes_to_governed_rgs.kql")
      severity    = 2
    }
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detections" {
  for_each = local.detections

  name                 = "alert-${each.key}"
  resource_group_name  = azurerm_resource_group.sandbox.name
  location             = var.location
  description          = each.value.description
  severity             = each.value.severity
  evaluation_frequency = "PT1H"
  window_duration      = "PT1H"
  scopes               = [azurerm_log_analytics_workspace.grc.id]
  enabled              = true

  criteria {
    query                   = each.value.query
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.secops.id]
  }

  tags = {
    env     = var.environment
    purpose = "cge-az-labs"
  }
}
