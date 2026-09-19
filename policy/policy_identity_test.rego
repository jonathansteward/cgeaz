# Unit tests for policy_identity.rego.
package main

import rego.v1

assignment(after) := {"resource_changes": [{
	"address": "azurerm_management_group_policy_assignment.example",
	"type": "azurerm_management_group_policy_assignment",
	"change": {"actions": ["create"], "after": after},
}]}

test_assignment_without_identity_is_denied if {
	some msg in deny with input as assignment({"name": "no-identity"})
	contains(msg, "identity block")
}

test_assignment_with_identity_passes if {
	count(deny) == 0 with input as assignment({"identity": [{"type": "UserAssigned"}]})
}
