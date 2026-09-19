# Unit tests for broad_roles.rego.
package main

import rego.v1

role_plan(role, action) := {"resource_changes": [{
	"address": "azurerm_role_assignment.example",
	"type": "azurerm_role_assignment",
	"change": {"actions": [action], "after": {"role_definition_name": role}},
}]}

test_owner_is_denied if {
	some msg in deny with input as role_plan("Owner", "create")
	contains(msg, "Owner")
}

test_contributor_is_denied if {
	some msg in deny with input as role_plan("Contributor", "create")
	contains(msg, "Contributor")
}

test_granular_role_passes if {
	count(deny) == 0 with input as role_plan("Security Reader", "create")
}

test_deleting_a_broad_role_is_allowed if {
	count(deny) == 0 with input as role_plan("Owner", "delete")
}
