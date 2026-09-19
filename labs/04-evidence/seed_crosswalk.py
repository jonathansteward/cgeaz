#!/usr/bin/env python3
"""Seed the NIST CSF 2.0 categories and the CSF 2.0 to 800-53 crosswalk into Cosmos.

Components are mapped to CSF 2.0 categories only. seed_frameworks.py seeds the CSF 2.0
functions; this script adds the 22 categories with their titles, a crosswalk from every
policy, component, gate rule and observed Defender assessment to the categories it serves,
and a framework crosswalk from each CSF category to the NIST 800-53 controls that support
it, with those controls' titles. One collected assessment therefore serves both frameworks
(collect once), and the report generators, including the OSCAL System Security Plan, read
all of it from the store. docs/CONTROLS.md is the human-readable copy; `--check` fails if
it and this file disagree.

    # validate the data and compare it with docs/CONTROLS.md, no Azure access needed
    python3 seed_crosswalk.py --dry-run --check

    # write to Cosmos (after stages/03-evidence-store is deployed, az login as yourself)
    pip install azure-cosmos azure-identity
    COSMOS_ENDPOINT=$(cd ../../stages/03-evidence-store && terraform output -raw cosmos_endpoint) \
        python3 seed_crosswalk.py

Every document has a deterministic id, so re-running upserts and never duplicates.
Both containers are partitioned on /frameworkId, so every document carries it.
"""

import argparse
import os
import re
import sys
from pathlib import Path

FRAMEWORK_ID = "nist-csf-2.0"
TARGET_FRAMEWORK_ID = "nist-800-53"

CATEGORIES = {
    "GV.OC": "Organizational Context",
    "GV.RM": "Risk Management Strategy",
    "GV.RR": "Roles, Responsibilities, and Authorities",
    "GV.PO": "Policy",
    "GV.OV": "Oversight",
    "GV.SC": "Cybersecurity Supply Chain Risk Management",
    "ID.AM": "Asset Management",
    "ID.RA": "Risk Assessment",
    "ID.IM": "Improvement",
    "PR.AA": "Identity Management, Authentication, and Access Control",
    "PR.AT": "Awareness and Training",
    "PR.DS": "Data Security",
    "PR.PS": "Platform Security",
    "PR.IR": "Technology Infrastructure Resilience",
    "DE.CM": "Continuous Monitoring",
    "DE.AE": "Adverse Event Analysis",
    "RS.MA": "Incident Management",
    "RS.AN": "Incident Analysis",
    "RS.CO": "Incident Response Reporting and Communication",
    "RS.MI": "Incident Mitigation",
    "RC.RP": "Incident Recovery Plan Execution",
    "RC.CO": "Incident Recovery Communication",
}

# (sourceType, source, description, CSF 2.0 categories) — mirrors docs/CONTROLS.md.
CROSSWALK = [
    # Azure Policy definitions
    ("policy", "cge-require-env-tag-rg", "Resource groups must carry an env tag", ["ID.AM"]),
    ("policy", "cge-deny-public-blob", "Storage accounts must not allow public blob access", ["PR.DS"]),
    ("policy", "cge-dine-storage-diagnostics", "Storage accounts route diagnostics to the GRC workspace", ["PR.PS", "DE.CM"]),
    ("policy", "cge-min-tls12-storage", "Storage accounts must require TLS 1.2 or higher", ["PR.DS"]),
    ("policy", "cge-cosmos-no-public-access", "Cosmos DB accounts must disable public network access", ["PR.IR"]),
    ("policy", "cge-storage-cmk", "Storage accounts should use customer-managed keys", ["PR.DS"]),
    ("policy", "cge-fix-public-blob", "Remediation: disable public blob access", ["PR.DS", "RS.MI"]),
    # Pipeline components
    ("component", "management-group-hierarchy", "Management group hierarchy and initiative assignment", ["GV.PO", "GV.OC"]),
    ("component", "remediation-identity", "User-assigned remediation identity with whitelist roles", ["PR.AA", "GV.RR"]),
    ("component", "log-analytics-activity-log", "Log Analytics workspace and Activity Log routing", ["DE.CM", "PR.PS"]),
    ("component", "cosmos-evidence-store", "Cosmos DB evidence store", ["GV.OV", "ID.RA"]),
    ("component", "worm-reports-container", "WORM immutability policy on the reports container", ["PR.DS"]),
    ("component", "shared-keys-disabled-rbac", "Shared keys disabled, data-plane RBAC", ["PR.AA"]),
    ("component", "collector-function", "Collector Function (Security Reader, Cosmos write only)", ["DE.CM", "ID.RA"]),
    ("component", "collector-reporter-split", "Collector and reporter identity split", ["PR.AA", "GV.RR"]),
    ("component", "run-ledger", "Run ledger container recording every collection run", ["GV.OV", "DE.CM"]),
    ("component", "role-assignment-collector", "Role assignment collector and roleassignments container", ["PR.AA", "ID.AM", "DE.CM"]),
    ("component", "poam-generator", "POA&M generator", ["ID.IM", "GV.RM"]),
    ("component", "sar-generator", "SAR generator", ["ID.RA", "GV.OV"]),
    ("component", "ssp-generator", "OSCAL System Security Plan generator", ["GV.PO", "GV.OV"]),
    ("component", "scheduled-detection-alerts", "Scheduled alert rules running the KQL detections hourly", ["DE.CM", "DE.AE"]),
    ("component", "remediation-mode-variable", "remediation_mode escalation variable", ["GV.PO", "GV.RR"]),
    # Repo gates and detections
    ("gate", "storage.rego", "Storage below the pipeline's own standard", ["PR.DS"]),
    ("gate", "policy_identity.rego", "Remediation assignment without an identity", ["PR.PS"]),
    ("gate", "broad_roles.rego", "Owner or Contributor grants in governance code", ["PR.AA"]),
    ("gate", "drift-detection", "drift.yml: reality drifting from the code", ["DE.CM", "DE.AE"]),
    ("gate", "tripwire-human-writes-to-governed-rgs", "KQL: a person changed a governed resource group directly", ["DE.CM", "DE.AE"]),
    ("gate", "fafo-after-hours-admin-writes", "KQL: administrative changes outside business hours", ["DE.CM", "DE.AE"]),
    ("gate", "fafo-unapproved-regions", "KQL: resources created outside approved regions", ["ID.AM", "DE.CM"]),
    # Defender assessments observed in the store. Extend this list with your own findings
    # (see the query in the README) and verify each mapping.
    ("assessment", "3869fbd7-5d90-84e4-37bd-d9a7f4ce9a24",
     "Email notification for high severity alerts should be enabled", ["RS.CO", "DE.AE"]),
]


# The framework crosswalk: each CSF 2.0 category to the NIST 800-53 controls that support it.
# Category-level, derived from NIST's published CSF 2.0 informative references and kept to the
# controls this pipeline can credibly speak to. Verify against the CSF 2.0 Reference Tool.
CSF_TO_800_53 = {
    "GV.OC": ["PM-1", "PM-11"],
    "GV.RM": ["PM-9", "RA-1", "RA-7"],
    "GV.RR": ["PM-2", "PM-13", "AC-5"],
    "GV.PO": ["PL-1", "PL-2", "CM-1"],
    "GV.OV": ["CA-2", "CA-7", "PM-31"],
    "ID.AM": ["CM-8", "PM-5"],
    "ID.RA": ["RA-3", "RA-5"],
    "ID.IM": ["CA-5", "PM-4"],
    "PR.AA": ["AC-2", "AC-3", "AC-5", "AC-6", "IA-2", "IA-5"],
    "PR.DS": ["SC-8", "SC-12", "SC-13", "SC-28"],
    "PR.PS": ["CM-2", "CM-6", "CM-7"],
    "PR.IR": ["SC-7"],
    "DE.CM": ["AU-6", "CA-7", "SI-4"],
    "DE.AE": ["AU-6", "SI-4", "IR-4"],
    "RS.CO": ["IR-4", "IR-6"],
    "RS.MI": ["IR-4", "SI-2"],
}

CONTROL_TITLES = {
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "AC-5": "Separation of Duties",
    "AC-6": "Least Privilege",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    "CA-2": "Control Assessments",
    "CA-5": "Plan of Action and Milestones",
    "CA-7": "Continuous Monitoring",
    "CM-1": "Policy and Procedures",
    "CM-2": "Baseline Configuration",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CM-8": "System Component Inventory",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-5": "Authenticator Management",
    "IR-4": "Incident Handling",
    "IR-6": "Incident Reporting",
    "PL-1": "Policy and Procedures",
    "PL-2": "System Security and Privacy Plans",
    "PM-1": "Information Security Program Plan",
    "PM-2": "Information Security Program Leadership Role",
    "PM-4": "Plan of Action and Milestones Process",
    "PM-5": "System Inventory",
    "PM-9": "Risk Management Strategy",
    "PM-11": "Mission and Business Process Definition",
    "PM-13": "Security and Privacy Workforce",
    "PM-31": "Continuous Monitoring Strategy",
    "RA-1": "Policy and Procedures",
    "RA-3": "Risk Assessment",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "RA-7": "Risk Response",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SI-2": "Flaw Remediation",
    "SI-4": "System Monitoring",
}


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def build_documents():
    frameworks = [
        {
            "id": f"csf2-cat-{cid}",
            "frameworkId": FRAMEWORK_ID,
            "type": "category",
            "categoryId": cid,
            "function": cid.split(".")[0],
            "title": title,
        }
        for cid, title in sorted(CATEGORIES.items())
    ]
    mappings = [
        {
            "id": f"map-{source_type}-{slug(source)}",
            "frameworkId": FRAMEWORK_ID,
            "type": "crosswalk",
            "sourceType": source_type,
            "source": source,
            "description": description,
            "controls": categories,
        }
        for source_type, source, description, categories in CROSSWALK
    ]
    frameworks += [
        {
            "id": f"800-53-{cid}",
            "frameworkId": TARGET_FRAMEWORK_ID,
            "type": "control",
            "controlId": cid,
            "family": cid.split("-")[0],
            "title": title,
        }
        for cid, title in sorted(CONTROL_TITLES.items())
    ]
    mappings += [
        {
            "id": f"xwalk-{cat.lower().replace('.', '-')}-to-800-53",
            "frameworkId": FRAMEWORK_ID,
            "type": "framework-crosswalk",
            "targetFramework": TARGET_FRAMEWORK_ID,
            "source": cat,
            "title": CATEGORIES[cat],
            "controls": controls,
        }
        for cat, controls in sorted(CSF_TO_800_53.items())
    ]
    return frameworks, mappings


def validate(frameworks, mappings) -> list[str]:
    problems = []
    for m in mappings:
        if m["type"] != "crosswalk":
            continue
        for c in m["controls"]:
            if c not in CATEGORIES:
                problems.append(f"{m['source']}: {c} is not a CSF 2.0 category")
    for cat, controls in CSF_TO_800_53.items():
        if cat not in CATEGORIES:
            problems.append(f"crosswalk source {cat} is not a CSF 2.0 category")
        for c in controls:
            if c not in CONTROL_TITLES:
                problems.append(f"{cat}: crosswalk to {c}, which has no title in CONTROL_TITLES")
    used = {c for _, _, _, cats in CROSSWALK for c in cats}
    for cat in sorted(used - set(CSF_TO_800_53)):
        problems.append(f"{cat} is used by a component but has no crosswalk to 800-53")
    ids = [d["id"] for d in frameworks + mappings]
    if len(ids) != len(set(ids)):
        problems.append("duplicate document ids")
    return problems


def check_controls_md(path: Path) -> list[str]:
    """Compare the crosswalks with docs/CONTROLS.md, the human-readable copy."""
    if not path.exists():
        return [f"{path} not found"]
    csf_id = re.compile(r"[A-Z]{2}\.[A-Z]{2}")
    csf_list = re.compile(r"[A-Z]{2}\.[A-Z]{2}(, [A-Z]{2}\.[A-Z]{2})*")
    ctl_list = re.compile(r"[A-Z]{2}-\d+(, [A-Z]{2}-\d+)*")
    rows, xwalk = {}, {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 3:
            continue
        if csf_id.fullmatch(cells[0]) and ctl_list.fullmatch(cells[2]):
            xwalk[cells[0]] = set(cells[2].split(", "))
        elif csf_list.fullmatch(cells[2]):
            rows[cells[0].replace("`", "").split(" (")[0]] = set(cells[2].split(", "))

    problems = []
    for name, cats in rows.items():
        for c in sorted(cats - set(CATEGORIES)):
            problems.append(f"CONTROLS.md row '{name}' uses {c}, which is not a CSF 2.0 category")
    for source_type, source, _, categories in CROSSWALK:
        if source_type != "policy":
            continue
        row = rows.get(source)
        if row is None:
            problems.append(f"policy {source} is in the crosswalk but not in CONTROLS.md")
        elif row != set(categories):
            problems.append(f"policy {source}: crosswalk {sorted(categories)} != CONTROLS.md {sorted(row)}")
    for cat, controls in CSF_TO_800_53.items():
        if cat not in xwalk:
            problems.append(f"{cat} is in the CSF to 800-53 crosswalk but not in CONTROLS.md")
        elif xwalk[cat] != set(controls):
            problems.append(f"{cat}: crosswalk {sorted(controls)} != CONTROLS.md {sorted(xwalk[cat])}")
    for cat in sorted(set(xwalk) - set(CSF_TO_800_53)):
        problems.append(f"CONTROLS.md crosswalks {cat}, which the seed script does not")
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
