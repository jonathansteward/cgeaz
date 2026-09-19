# tflint configuration. Install tflint, then run `tflint --init` once and `tflint --chdir stages/<stage>`.
config {
  call_module_type = "local"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "azurerm" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

# The evidence store is protected by the WORM policy on the reports container and by
# identity-only access. It is deliberately not protected with prevent_destroy, because the
# course ends with a full teardown (`terraform destroy`) that must work.
rule "azurerm_resources_missing_prevent_destroy" {
  enabled = false
}
