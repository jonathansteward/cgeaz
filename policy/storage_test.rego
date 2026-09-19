# Unit tests for storage.rego. Run with: conftest verify -p policy/
package main

import rego.v1

good_storage := {"resource_changes": [{
	"address": "azurerm_storage_account.good",
	"type": "azurerm_storage_account",
	"name": "good",
	"change": {"actions": ["create"], "after": {
		"allow_nested_items_to_be_public": false,
		"shared_access_key_enabled": false,
		"min_tls_version": "TLS1_2",
	}},
}]}

test_compliant_storage_passes if {
	count(deny) == 0 with input as good_storage
}

test_public_blob_is_denied if {
	bad := json.patch(good_storage, [{"op": "replace", "path": "/resource_changes/0/change/after/allow_nested_items_to_be_public", "value": true}])
	some msg in deny with input as bad
	contains(msg, "public blob access")
}

test_shared_key_is_denied if {
	bad := json.patch(good_storage, [{"op": "replace", "path": "/resource_changes/0/change/after/shared_access_key_enabled", "value": true}])
	some msg in deny with input as bad
	contains(msg, "shared key access")
}

test_tls_1_0_is_denied if {
	bad := json.patch(good_storage, [{"op": "replace", "path": "/resource_changes/0/change/after/min_tls_version", "value": "TLS1_0"}])
	some msg in deny with input as bad
	contains(msg, "TLS 1.2")
}

test_tls_1_3_passes if {
	ok := json.patch(good_storage, [{"op": "replace", "path": "/resource_changes/0/change/after/min_tls_version", "value": "TLS1_3"}])
	count(deny) == 0 with input as ok
}

test_unset_tls_uses_the_secure_default if {
	ok := json.patch(good_storage, [{"op": "remove", "path": "/resource_changes/0/change/after/min_tls_version"}])
	count(deny) == 0 with input as ok
}
