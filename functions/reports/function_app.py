"""CGE-AZ pipeline — Stage 4 report generators.

Reports read from Cosmos ONLY — never from live services. Every number in every
artifact resolves to a stored, timestamped document. A report that reads live data
is a report whose numbers can't be reproduced tomorrow; a report that reads the
store is a fact with a receipt.

Generators here: POA&M (xlsx + json, daily), SAR (markdown, weekly) and an OSCAL System
Security Plan (json, weekly), all with HTTP triggers for labs and demos.
"""

import datetime
import io
import json
import logging
import os
import uuid
from collections import Counter, defaultdict

import azure.functions as func
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from openpyxl import Workbook

app = func.FunctionApp()

# Severity-based SLAs: a POA&M is a plan, not a list.
SLA_DAYS = {"High": 30, "Medium": 90, "Low": 180}


def _clients():
    credential = DefaultAzureCredential()
    cosmos = (
        CosmosClient(os.environ["COSMOS_ENDPOINT"], credential)
        .get_database_client(os.environ["COSMOS_DATABASE"])
        .get_container_client("assessments")
    )
    blobs = BlobServiceClient(
        account_url=os.environ["REPORTS_ACCOUNT_URL"], credential=credential
    ).get_container_client(os.environ["REPORTS_CONTAINER"])
    return cosmos, blobs


def _latest_run(cosmos):
    """Pin the report to a specific collection sweep — a statement about a known moment."""
    rows = list(
        cosmos.query_items(
            "SELECT TOP 1 c.runId, c.collectedAt FROM c ORDER BY c.collectedAt DESC",
            enable_cross_partition_query=True,
        )
    )
    return (rows[0]["runId"], rows[0]["collectedAt"]) if rows else (None, None)


def _unhealthy(cosmos, run_id):
    return list(
        cosmos.query_items(
            "SELECT * FROM c WHERE c.runId = @run AND c.status = 'Unhealthy'",
            parameters=[{"name": "@run", "value": run_id}],
            enable_cross_partition_query=True,
        )
    )


def _dated_path(prefix: str, ext: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return f"{prefix}/{now:%Y/%m}/{prefix}-{now:%Y-%m-%d}.{ext}"


def generate_poam() -> dict:
    cosmos, blobs = _clients()
    run_id, collected_at = _latest_run(cosmos)
    findings = _unhealthy(cosmos, run_id) if run_id else []
    today = datetime.date.today()

    wb = Workbook()
    ws = wb.active
    ws.title = "POA&M"
    ws.append(
        ["POA&M ID", "Weakness", "Affected Resource", "Severity",
         "Detected (run)", "Scheduled Completion", "Owner", "Status"]
    )
    rows = []
    for i, f in enumerate(sorted(findings, key=lambda x: x.get("severity") or ""), 1):
        severity = f.get("severity") or "Medium"
        due = today + datetime.timedelta(days=SLA_DAYS.get(severity, 90))
        row = {
            "poamId": f"POAM-{today:%Y%m%d}-{i:03d}",
            "weakness": f.get("displayName"),
            "resourceId": f.get("resourceId"),
            "severity": severity,
            "detectedRun": run_id,
            "scheduledCompletion": due.isoformat(),
            "owner": "resource-group owner tag",  # resolved during Domain 5's lab extension
            "status": "Open",
        }
        rows.append(row)
        ws.append(list(row.values()))

    xlsx = io.BytesIO()
    wb.save(xlsx)
    xlsx_path = _dated_path("poam", "xlsx")
    json_path = _dated_path("poam", "json")
    blobs.upload_blob(xlsx_path, xlsx.getvalue(), overwrite=False)
    blobs.upload_blob(
        json_path,
        json.dumps({"runId": run_id, "collectedAt": collected_at, "items": rows}, indent=2),
        overwrite=False,
    )
    logging.info("POA&M: %d items -> %s", len(rows), xlsx_path)
    return {"items": len(rows), "runId": run_id, "xlsx": xlsx_path, "json": json_path}


def generate_sar() -> dict:
    cosmos, blobs = _clients()
    run_id, collected_at = _latest_run(cosmos)
    findings = _unhealthy(cosmos, run_id) if run_id else []
    by_severity = Counter(f.get("severity") or "Unknown" for f in findings)

    lines = [
        "# Security Assessment Report (SAR)",
        "",
        f"- **Collection run:** `{run_id}`",
        f"- **Collected at:** {collected_at}",
        f"- **Open findings:** {len(findings)}",
        f"- **By severity:** " + (", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items())) or "none"),
        "",
        "## Findings",
        "",
    ]
    for f in sorted(findings, key=lambda x: x.get("severity") or ""):
        lines += [
            f"### {f.get('displayName')}",
            f"- Severity: {f.get('severity')}",
            f"- Resource: `{f.get('resourceId')}`",
            f"- Assessment ID: `{f.get('assessmentId')}` (trace: query the assessments container)",
            "",
        ]

    path = _dated_path("sar", "md")
    blobs.upload_blob(path, "\n".join(lines), overwrite=False)
    logging.info("SAR: %d findings -> %s", len(findings), path)
    return {"findings": len(findings), "runId": run_id, "path": path}


# --- OSCAL System Security Plan ---------------------------------------------------
# Built entirely from the store. Components are mapped to CSF 2.0 categories, and the stored
# CSF 2.0 to 800-53 crosswalk carries those categories to the 800-53 controls the plan
# speaks in. UUIDs are derived from stable names, so two plans differ only where the store
# differs.

OSCAL_VERSION = "1.1.2"
CSF_ID = "nist-csf-2.0"
TARGET_ID = "nist-800-53"
SSP_NAMESPACE = uuid.UUID("6f1c2f5e-0b7a-4d43-9e1e-3a5b8c1d7e42")
COMPONENT_TYPE = {"policy": "policy", "component": "software", "gate": "process", "assessment": "service"}


def _uuid(name: str) -> str:
    return str(uuid.uuid5(SSP_NAMESPACE, name))


def _container(name: str):
    return (
        CosmosClient(os.environ["COSMOS_ENDPOINT"], DefaultAzureCredential())
        .get_database_client(os.environ["COSMOS_DATABASE"])
        .get_container_client(name)
    )


def _query(container: str, framework: str, where: str) -> list:
    return list(
        _container(container).query_items(
            f"SELECT * FROM c WHERE c.frameworkId = @f AND {where}",
            parameters=[{"name": "@f", "value": framework}],
            partition_key=framework,
        )
    )


def build_ssp(controls: list, crosswalk: list, category_map: dict, findings: list, run_id, collected_at, generated_at: str) -> dict:
    """controls: 800-53 control documents; crosswalk: component to CSF category documents;
    category_map: CSF category to the 800-53 controls that support it."""
    titles = {c["controlId"]: c["title"] for c in controls}
    components_in_scope = [m for m in crosswalk if m["sourceType"] != "assessment"]

    # control -> {component key -> (component doc, the CSF categories that carry it there)}
    by_control = defaultdict(dict)
    for m in components_in_scope:
        for cat in m["controls"]:
            for ctl in category_map.get(cat, []):
                entry = by_control[ctl].setdefault((m["sourceType"], m["source"]), (m, set()))
                entry[1].add(cat)

    open_findings = Counter()
    for f in findings:
        for m in crosswalk:
            if m["sourceType"] == "assessment" and m["source"] == f.get("assessmentId"):
                for cat in m["controls"]:
                    for ctl in category_map.get(cat, []):
                        open_findings[ctl] += 1

    components = [
        {
            "uuid": _uuid("component:this-system"),
            "type": "this-system",
            "title": "FAFO GRC engineering pipeline",
            "description": "The collectors, evidence store, report generators, policies and gates that make up the pipeline.",
            "status": {"state": "operational"},
        }
    ] + [
        {
            "uuid": _uuid(f"component:{m['sourceType']}:{m['source']}"),
            "type": COMPONENT_TYPE.get(m["sourceType"], "software"),
            "title": m["source"],
            "description": m["description"],
            "status": {"state": "operational"},
        }
        for m in components_in_scope
    ]

    requirements = []
    for ctl in sorted(by_control):
        oscal_id = ctl.lower()
        requirements.append(
            {
                "uuid": _uuid(f"requirement:{oscal_id}"),
                "control-id": oscal_id,
                "props": [{"name": "implementation-status", "value": "partial", "ns": "http://csrc.nist.gov/ns/oscal"}],
                "by-components": [
                    {
                        "component-uuid": _uuid(f"component:{m['sourceType']}:{m['source']}"),
                        "uuid": _uuid(f"by:{oscal_id}:{m['sourceType']}:{m['source']}"),
                        "description": f"{m['description']} ({m['sourceType']}: {m['source']}), which contributes to this "
                        f"control through CSF 2.0 {', '.join(sorted(cats))}.",
                        "implementation-status": {"state": "partial"},
                    }
                    for (_, _), (m, cats) in sorted(by_control[ctl].items())
                ],
                "remarks": f"{titles.get(ctl, ctl)}. Reached through the CSF 2.0 to 800-53 crosswalk, so each component "
                f"contributes without claiming the whole control. Open findings mapped to it in run {run_id}: "
                f"{open_findings.get(ctl, 0)}.",
            }
        )

    return {
        "system-security-plan": {
            "uuid": _uuid("ssp"),
            "metadata": {
                "title": "System Security Plan: FAFO GRC engineering pipeline",
                "last-modified": generated_at,
                "version": (collected_at or generated_at)[:10],
                "oscal-version": OSCAL_VERSION,
                "roles": [{"id": "system-owner", "title": "System Owner"}],
                "parties": [{"uuid": _uuid("party:fafo"), "type": "organization", "name": "FAFO"}],
                "responsible-parties": [{"role-id": "system-owner", "party-uuids": [_uuid("party:fafo")]}],
                "remarks": f"Generated from the evidence store. Assessments run: {run_id or 'none yet'}. Components are mapped "
                "to NIST CSF 2.0 categories; the 800-53 controls below come from the stored CSF 2.0 to 800-53 crosswalk and are "
                "a subset, not the full baseline.",
            },
            "import-profile": {
                "href": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"
            },
            "system-characteristics": {
                "system-ids": [{"id": "fafo-grc-pipeline"}],
                "system-name": "FAFO GRC engineering pipeline",
                "description": "An automated pipeline that discovers what an Azure subscription runs, collects control "
                "evidence into a store the team owns, reports only from that store, and enforces baseline controls "
                "through Azure Policy with a human at the approval gate.",
                "security-sensitivity-level": "moderate",
                "system-information": {
                    "information-types": [
                        {
                            "uuid": _uuid("information-type:security-assessment"),
                            "title": "Security assessment and configuration evidence",
                            "description": "Defender assessments, role assignments, policy definitions and run records.",
                            "confidentiality-impact": {"base": "fips-199-moderate"},
                            "integrity-impact": {"base": "fips-199-moderate"},
                            "availability-impact": {"base": "fips-199-low"},
                        }
                    ]
                },
                "security-impact-level": {
                    "security-objective-confidentiality": "fips-199-moderate",
                    "security-objective-integrity": "fips-199-moderate",
                    "security-objective-availability": "fips-199-low",
                },
                "status": {"state": "operational"},
                "authorization-boundary": {
                    "description": "One Azure subscription under the mg-grc management group hierarchy: the evidence "
                    "resource group, the sandbox resource group, and the policies assigned at mg-grc-sandbox."
                },
            },
            "system-implementation": {
                "users": [
                    {
                        "uuid": _uuid("user:owner"),
                        "title": "Pipeline owner",
                        "role-ids": ["system-owner"],
                        "authorized-privileges": [
                            {"title": "Approve remediation and escalate policy effects", "functions-performed": ["approve-remediation"]}
                        ],
                    }
                ],
                "components": components,
            },
            "control-implementation": {
                "description": "Components are mapped to NIST CSF 2.0 categories (mappings container); each requirement below is an "
                "800-53 control reached through the stored CSF 2.0 to 800-53 crosswalk. The mapping mirrors docs/CONTROLS.md.",
                "implemented-requirements": requirements,
            },
        }
    }


def generate_ssp() -> dict:
    cosmos, blobs = _clients()
    run_id, collected_at = _latest_run(cosmos)
    findings = _unhealthy(cosmos, run_id) if run_id else []
    controls = _query("frameworks", TARGET_ID, "c.type = 'control'")
    crosswalk = _query("mappings", CSF_ID, "c.type = 'crosswalk'")
    category_map = {d["source"]: d["controls"] for d in _query("mappings", CSF_ID, "c.type = 'framework-crosswalk'")}
    generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    ssp = build_ssp(controls, crosswalk, category_map, findings, run_id, collected_at, generated_at)

    path = _dated_path("ssp", "json")
    blobs.upload_blob(path, json.dumps(ssp, indent=2), overwrite=False)
    reqs = ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
    logging.info("SSP: %d requirements -> %s", len(reqs), path)
    return {"requirements": len(reqs), "controls": len(controls), "crosswalk": len(crosswalk), "runId": run_id, "path": path}


@app.timer_trigger(schedule="0 0 6 * * *", arg_name="timer", run_on_startup=False)
def poam_daily(timer: func.TimerRequest) -> None:
    generate_poam()


@app.timer_trigger(schedule="0 0 7 * * 1", arg_name="timer", run_on_startup=False)
def sar_weekly(timer: func.TimerRequest) -> None:
    generate_sar()


@app.timer_trigger(schedule="0 30 7 * * 1", arg_name="timer", run_on_startup=False)
def ssp_weekly(timer: func.TimerRequest) -> None:
    generate_ssp()


@app.route(route="poam", auth_level=func.AuthLevel.FUNCTION)
def poam_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_poam()) + "\n", status_code=200)


@app.route(route="sar", auth_level=func.AuthLevel.FUNCTION)
def sar_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_sar()) + "\n", status_code=200)


@app.route(route="ssp", auth_level=func.AuthLevel.FUNCTION)
def ssp_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_ssp()) + "\n", status_code=200)
