#!/usr/bin/env python3
"""Seed the frameworks and mappings containers with a NIST 800-53 subset.

This is the framework track for this pipeline: an 800-53 catalog (the controls the
pipeline actually serves, not the whole catalog) and a crosswalk from every policy,
component, and gate rule to those controls. The same sources are also crosswalked to
NIST CSF 2.0 categories (the CSF 2.0 structure itself is seeded by seed_frameworks.py), so
one collected assessment serves both frameworks. docs/CONTROLS.md is the human-readable
copy of both crosswalks; `--check` fails if it and this file disagree.

    # validate the data and compare it with docs/CONTROLS.md, no Azure access needed
    python3 seed_800_53.py --dry-run --check

    # write to Cosmos (after stages/03-evidence-store is deployed, az login as yourself)
    pip install azure-cosmos azure-identity
    COSMOS_ENDPOINT=$(cd ../../stages/03-evidence-store && terraform output -raw cosmos_endpoint) \
        python3 seed_800_53.py

Every document has a deterministic id, so re-running upserts and never duplicates.
Both containers are partitioned on /frameworkId, so every document carries it.
"""

import argparse
import os
import re
import sys
from pathlib import Path

FRAMEWORK_ID = "nist-800-53"

FAMILIES = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "PL": "Planning",
    "RA": "Risk Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# The subset this pipeline serves. Titles are the 800-53 control titles.
CONTROLS = {
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "AC-5": "Separation of Duties",
    "AC-6": "Least Privilege",
    "AU-2": "Event Logging",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    "AU-9": "Protection of Audit Information",
    "AU-11": "Audit Record Retention",
    "AU-12": "Audit Record Generation",
    "CA-2": "Control Assessments",
    "CA-5": "Plan of Action and Milestones",
    "CA-7": "Continuous Monitoring",
    "CM-2": "Baseline Configuration",
    "CM-3": "Configuration Change Control",
    "CM-6": "Configuration Settings",
    "CM-8": "System Component Inventory",
    "IA-5": "Authenticator Management",
    "IR-6": "Incident Reporting",
    "PL-2": "System Security and Privacy Plans",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "RA-7": "Risk Response",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SI-4": "System Monitoring",
}

# (sourceType, source, description, controls) — mirrors docs/CONTROLS.md.
CROSSWALK = [
    # Azure Policy definitions
    ("policy", "cge-require-env-tag-rg", "Resource groups must carry an env tag", ["CM-8"]),
    ("policy", "cge-deny-public-blob", "Storage accounts must not allow public blob access", ["AC-3", "SC-7"]),
    ("policy", "cge-dine-storage-diagnostics", "Storage accounts route diagnostics to the GRC workspace", ["AU-2", "AU-12"]),
    ("policy", "cge-min-tls12-storage", "Storage accounts must require TLS 1.2 or higher", ["SC-8", "SC-13"]),
    ("policy", "cge-cosmos-no-public-access", "Cosmos DB accounts must disable public network access", ["SC-7"]),
    ("policy", "cge-storage-cmk", "Storage accounts should use customer-managed keys", ["SC-28", "SC-12"]),
    ("policy", "cge-fix-public-blob", "Remediation: disable public blob access", ["CM-6", "RA-7"]),
    # Pipeline components
    ("component", "management-group-hierarchy", "Management group hierarchy and initiative assignment", ["CM-2", "CM-6"]),
    ("component", "remediation-identity", "User-assigned remediation identity with whitelist roles", ["AC-2", "AC-6"]),
    ("component", "log-analytics-activity-log", "Log Analytics workspace and Activity Log routing", ["AU-2", "AU-6", "AU-11"]),
    ("component", "cosmos-evidence-store", "Cosmos DB evidence store", ["CA-7", "CA-2"]),
    ("component", "worm-reports-container", "WORM immutability policy on the reports container", ["AU-9", "AU-11"]),
    ("component", "shared-keys-disabled-rbac", "Shared keys disabled, data-plane RBAC", ["AC-3", "AC-6", "IA-5"]),
    ("component", "collector-function", "Collector Function (Security Reader, Cosmos write only)", ["CA-7", "RA-5"]),
    ("component", "collector-reporter-split", "Collector and reporter identity split", ["AC-5", "AC-6"]),
    ("component", "run-ledger", "Run ledger container recording every collection run", ["AU-2", "AU-12", "CA-7"]),
    ("component", "role-assignment-collector", "Role assignment collector and roleassignments container", ["AC-2", "AC-6", "CA-7"]),
    ("component", "poam-generator", "POA&M generator", ["CA-5"]),
    ("component", "sar-generator", "SAR generator", ["CA-2"]),
    ("component", "ssp-generator", "OSCAL System Security Plan generator", ["PL-2", "CA-2"]),
    ("component", "scheduled-detection-alerts", "Scheduled alert rules running the KQL detections hourly", ["CA-7", "SI-4"]),
    ("component", "remediation-mode-variable", "remediation_mode escalation variable", ["CM-3"]),
    # Repo gates
    ("gate", "storage.rego", "Storage below the pipeline's own standard", ["AC-3", "SC-8", "SC-28"]),
    ("gate", "policy_identity.rego", "Remediation assignment without an identity", ["AC-6", "CM-3"]),
    ("gate", "broad_roles.rego", "Owner or Contributor grants in governance code", ["AC-6"]),
    ("gate", "drift-detection", "drift.yml and the KQL tripwire", ["CA-7", "SI-4", "CM-3"]),
    ("gate", "tripwire-human-writes-to-governed-rgs", "KQL: a person changed a governed resource group directly", ["CA-7", "SI-4", "CM-3"]),
    ("gate", "fafo-after-hours-admin-writes", "KQL: administrative changes outside business hours", ["CA-7", "SI-4"]),
    ("gate", "fafo-unapproved-regions", "KQL: resources created outside approved regions", ["CM-2", "SI-4"]),
    # Defender assessments observed in the store. Extend this list with your own findings
    # (see the query in the README) and verify each mapping against the catalog.
    ("assessment", "3869fbd7-5d90-84e4-37bd-d9a7f4ce9a24",
     "Email notification for high severity alerts should be enabled", ["IR-6", "SI-4"]),
]


# NIST CSF 2.0 categories for the same sources, keyed by (sourceType, source).
CSF_CATEGORIES = {
    "GV.OC", "GV.RM", "GV.RR", "GV.PO", "GV.OV", "GV.SC", "ID.AM", "ID.RA", "ID.IM",
    "PR.AA", "PR.AT", "PR.DS", "PR.PS", "PR.IR", "DE.CM", "DE.AE",
    "RS.MA", "RS.AN", "RS.CO", "RS.MI", "RC.RP", "RC.CO",
}
CSF_FRAMEWORK_ID = "nist-csf-2.0"
CSF = {
    ("policy", "cge-require-env-tag-rg"): ["ID.AM"],
    ("policy", "cge-deny-public-blob"): ["PR.DS"],
    ("policy", "cge-dine-storage-diagnostics"): ["PR.PS", "DE.CM"],
    ("policy", "cge-min-tls12-storage"): ["PR.DS"],
    ("policy", "cge-cosmos-no-public-access"): ["PR.IR"],
    ("policy", "cge-storage-cmk"): ["PR.DS"],
    ("policy", "cge-fix-public-blob"): ["PR.DS", "RS.MI"],
    ("component", "management-group-hierarchy"): ["GV.PO", "GV.OC"],
    ("component", "remediation-identity"): ["PR.AA", "GV.RR"],
    ("component", "log-analytics-activity-log"): ["DE.CM", "PR.PS"],
    ("component", "cosmos-evidence-store"): ["GV.OV", "ID.RA"],
    ("component", "worm-reports-container"): ["PR.DS"],
    ("component", "shared-keys-disabled-rbac"): ["PR.AA"],
    ("component", "collector-function"): ["DE.CM", "ID.RA"],
    ("component", "collector-reporter-split"): ["PR.AA", "GV.RR"],
    ("component", "run-ledger"): ["GV.OV", "DE.CM"],
    ("component", "role-assignment-collector"): ["PR.AA", "ID.AM", "DE.CM"],
    ("component", "poam-generator"): ["ID.IM", "GV.RM"],
    ("component", "sar-generator"): ["ID.RA", "GV.OV"],
    ("component", "ssp-generator"): ["GV.PO", "GV.OV"],
    ("component", "scheduled-detection-alerts"): ["DE.CM", "DE.AE"],
    ("component", "remediation-mode-variable"): ["GV.PO", "GV.RR"],
    ("gate", "storage.rego"): ["PR.DS"],
    ("gate", "policy_identity.rego"): ["PR.PS"],
    ("gate", "broad_roles.rego"): ["PR.AA"],
    ("gate", "drift-detection"): ["DE.CM", "DE.AE"],
    ("gate", "tripwire-human-writes-to-governed-rgs"): ["DE.CM", "DE.AE"],
    ("gate", "fafo-after-hours-admin-writes"): ["DE.CM", "DE.AE"],
    ("gate", "fafo-unapproved-regions"): ["ID.AM", "DE.CM"],
    ("assessment", "3869fbd7-5d90-84e4-37bd-d9a7f4ce9a24"): ["RS.CO", "DE.AE"],
}


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def build_documents():
    frameworks, mappings = [], []

    frameworks.append({
        "id": FRAMEWORK_ID,
        "frameworkId": FRAMEWORK_ID,
        "type": "framework",
        "name": "NIST 800-53",
        "scope": "Subset: the controls this pipeline serves, not the full catalog",
        "families": sorted(FAMILIES),
    })
    for fam, name in sorted(FAMILIES.items()):
        frameworks.append({
            "id": f"800-53-family-{fam}",
            "frameworkId": FRAMEWORK_ID,
            "type": "family",
            "familyId": fam,
            "name": name,
            "controls": sorted(c for c in CONTROLS if c.startswith(fam + "-")),
        })
    for cid, title in sorted(CONTROLS.items()):
        frameworks.append({
            "id": f"800-53-{cid}",
            "frameworkId": FRAMEWORK_ID,
            "type": "control",
            "controlId": cid,
            "family": cid.split("-")[0],
            "title": title,
        })

    for source_type, source, description, controls in CROSSWALK:
        mappings.append({
            "id": f"map-{source_type}-{slug(source)}",
            "frameworkId": FRAMEWORK_ID,
            "type": "crosswalk",
            "sourceType": source_type,
            "source": source,
            "description": description,
            "controls": controls,
        })
        mappings.append({
            "id": f"map-csf-{source_type}-{slug(source)}",
            "frameworkId": CSF_FRAMEWORK_ID,
            "type": "crosswalk",
            "sourceType": source_type,
            "source": source,
            "description": description,
            "controls": CSF[(source_type, source)],
        })
    return frameworks, mappings


def validate(frameworks, mappings) -> list[str]:
    problems = []
    known = set(CONTROLS)
    for fam_id in {c.split("-")[0] for c in CONTROLS}:
        if fam_id not in FAMILIES:
            problems.append(f"control family {fam_id} has no FAMILIES entry")
    for m in mappings:
        if m["frameworkId"] != FRAMEWORK_ID:
            continue
        for c in m["controls"]:
            if c not in known:
                problems.append(f"{m['source']}: maps to {c}, which is not in the catalog subset")
    for source_type, source, _, _ in CROSSWALK:
        cats = CSF.get((source_type, source))
        if not cats:
            problems.append(f"{source}: no CSF 2.0 mapping")
            continue
        for c in cats:
            if c not in CSF_CATEGORIES:
                problems.append(f"{source}: {c} is not a CSF 2.0 category")
    ids = [d["id"] for d in frameworks + mappings]
    if len(ids) != len(set(ids)):
        problems.append("duplicate document ids")
    return problems


def check_controls_md(path: Path) -> list[str]:
    """Compare the crosswalks with docs/CONTROLS.md, the human-readable copy."""
    if not path.exists():
        return [f"{path} not found"]
    csf_re = re.compile(r"[A-Z]{2}\.[A-Z]{2}(, [A-Z]{2}\.[A-Z]{2})*")
    ctl_re = re.compile(r"[A-Z]{2}-\d+(, [A-Z]{2}-\d+)*")
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 4 or not csf_re.fullmatch(cells[2]) or not ctl_re.fullmatch(cells[3]):
            continue
        name = cells[0].replace("`", "").split(" (")[0]
        rows[name] = (set(cells[2].split(", ")), set(cells[3].split(", ")))

    problems = []
    for csf_ids, ctl_ids in rows.values():
        for c in sorted(csf_ids - CSF_CATEGORIES):
            problems.append(f"CONTROLS.md uses {c}, which is not a CSF 2.0 category")
        for c in sorted(ctl_ids - set(CONTROLS)):
            problems.append(f"CONTROLS.md uses {c}, which is not in the 800-53 subset")
    for source_type, source, _, controls in CROSSWALK:
        if source_type != "policy":
            continue
        row = rows.get(source)
        if row is None:
            problems.append(f"policy {source} is in the crosswalk but not in CONTROLS.md")
            continue
        if row[1] != set(controls):
            problems.append(f"policy {source}: 800-53 {sorted(controls)} != CONTROLS.md {sorted(row[1])}")
        if row[0] != set(CSF[(source_type, source)]):
            problems.append(f"policy {source}: CSF {sorted(CSF[(source_type, source)])} != CONTROLS.md {sorted(row[0])}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="build and validate documents, write nothing")
    parser.add_argument("--check", action="store_true", help="compare the crosswalk with docs/CONTROLS.md")
    args = parser.parse_args()

    frameworks, mappings = build_documents()
    problems = validate(frameworks, mappings)
    if args.check:
        problems += check_controls_md(Path(__file__).resolve().parents[2] / "docs" / "CONTROLS.md")
    for p in problems:
        print(f"problem: {p}", file=sys.stderr)
    if problems:
        return 1

    print(f"{len(frameworks)} framework documents, {len(mappings)} mapping documents")
    if args.dry_run:
        return 0

    endpoint = os.environ.get("COSMOS_ENDPOINT")
    if not endpoint:
        print("Set COSMOS_ENDPOINT (see docstring).", file=sys.stderr)
        return 1

    from azure.cosmos import CosmosClient
    from azure.identity import DefaultAzureCredential

    database = CosmosClient(endpoint, DefaultAzureCredential()).get_database_client(
        os.environ.get("COSMOS_DATABASE", "grc")
    )
    for container_name, docs in (("frameworks", frameworks), ("mappings", mappings)):
        container = database.get_container_client(container_name)
        for doc in docs:
            container.upsert_item(doc)
        print(f"upserted {len(docs)} documents into {container_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
