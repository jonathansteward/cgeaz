# Gate rules

The OPA/conftest rules the compliance gate runs against every pull request's Terraform plan
(`.github/workflows/gate.yml`).

| Rule file | What it blocks |
|---|---|
| `storage.rego` | Storage accounts with public blob access, shared keys, or TLS below 1.2 |
| `broad_roles.rego` | Owner or Contributor role assignments |
| `policy_identity.rego` | Policy assignments without an identity block |

Run the unit tests and the included examples locally:

```bash
conftest verify -p policy/                                            # unit tests (*_test.rego)
conftest test policy/examples/compliant-plan.json -p policy/          # passes
conftest test policy/examples/violating-plan.json -p policy/          # fails, naming each rule
```
