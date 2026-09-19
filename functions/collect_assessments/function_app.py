"""CGE-AZ pipeline — Stage 3 collector.

Timer fires nightly -> managed identity -> Defender assessments API -> Cosmos.
One document per assessment per run, upserted on a deterministic ID so re-runs
refresh instead of duplicate. Deliberately boring: if you can read this file,
you can defend this pipeline's data lineage.
"""

import datetime
import hashlib
import logging
import os
import uuid

import azure.functions as func
import requests
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

app = func.FunctionApp()

ARM = "https://management.azure.com"
API_VERSION = "2021-06-01"


def _collect() -> dict:
    subscription_id = os.environ["SUBSCRIPTION_ID"]
    cosmos_endpoint = os.environ["COSMOS_ENDPOINT"]
    database = os.environ["COSMOS_DATABASE"]

    # DefaultAzureCredential resolves to the Function App's managed identity in Azure
    # (and to your `az login` session when run locally). No keys, anywhere.
    credential = DefaultAzureCredential()
    token = credential.get_token(f"{ARM}/.default").token

    run_id = str(uuid.uuid4())
    collected_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    container = (
        CosmosClient(cosmos_endpoint, credential)
        .get_database_client(database)
        .get_container_client("assessments")
    )

    url = (
        f"{ARM}/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Security/assessments?api-version={API_VERSION}"
    )
    written = 0
    while url:
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=60)
        resp.raise_for_status()
        payload = resp.json()

        for assessment in payload.get("value", []):
            props = assessment.get("properties", {})
            resource_id = (
                props.get("resourceDetails", {}).get("Id")
                or props.get("resourceDetails", {}).get("id", "")
            )
            # Deterministic ID: same assessment+resource upserts, never duplicates.
            doc_id = hashlib.sha256(
                f"{assessment['name']}|{resource_id}".encode()
            ).hexdigest()[:32]

            container.upsert_item(
                {
                    "id": doc_id,
                    "subscriptionId": subscription_id,
                    "assessmentId": assessment["name"],
                    "displayName": props.get("displayName"),
                    "status": props.get("status", {}).get("code"),
                    "statusCause": props.get("status", {}).get("cause"),
                    "severity": props.get("metadata", {}).get("severity"),
                    "categories": props.get("metadata", {}).get("categories"),
                    "resourceId": resource_id,
                    "collectedAt": collected_at,
                    "runId": run_id,
                }
            )
            written += 1

        url = payload.get("nextLink")

    logging.info("collection run %s complete: %d documents", run_id, written)
    return {"runId": run_id, "written": written, "collectedAt": collected_at}


@app.timer_trigger(schedule="0 0 5 * * *", arg_name="timer", run_on_startup=False)
def collect_nightly(timer: func.TimerRequest) -> None:
    """Nightly sweep at 05:00 UTC — midnight-ish US Eastern."""
    _collect()


@app.route(route="collect", auth_level=func.AuthLevel.FUNCTION)
def collect_now(req: func.HttpRequest) -> func.HttpResponse:
    """Manual trigger for labs and demos: hit the endpoint, get the run summary."""
    result = _collect()
    return func.HttpResponse(
        f"run {result['runId']}: {result['written']} documents at {result['collectedAt']}\n",
        status_code=200,
    )


# --- Role assignment snapshots -------------------------------------------------------
# A second collector feeding a second container. Who holds which role, at which scope, at
# collection time. Same lineage rules as the assessments collector: every document carries
# the run's runId and collectedAt, and the ID is deterministic so a re-run refreshes.

ROLE_API_VERSION = "2022-04-01"
PRIVILEGED_ROLES = {"Owner", "Contributor", "User Access Administrator"}


def _arm_get_all(url: str, token: str) -> list:
    items = []
    while url:
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=60)
        resp.raise_for_status()
        payload = resp.json()
        items.extend(payload.get("value", []))
        url = payload.get("nextLink")
    return items


def _collect_role_assignments() -> dict:
    subscription_id = os.environ["SUBSCRIPTION_ID"]
    credential = DefaultAzureCredential()
    token = credential.get_token(f"{ARM}/.default").token

    run_id = str(uuid.uuid4())
    collected_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    container = (
        CosmosClient(os.environ["COSMOS_ENDPOINT"], credential)
        .get_database_client(os.environ["COSMOS_DATABASE"])
        .get_container_client("roleassignments")
    )

    base = f"{ARM}/subscriptions/{subscription_id}/providers/Microsoft.Authorization"
    role_names = {
        d["id"].lower(): d.get("properties", {}).get("roleName")
        for d in _arm_get_all(f"{base}/roleDefinitions?api-version={ROLE_API_VERSION}", token)
    }

    written = 0
    for assignment in _arm_get_all(f"{base}/roleAssignments?api-version={ROLE_API_VERSION}", token):
        props = assignment.get("properties", {})
        role_id = props.get("roleDefinitionId", "")
        role_name = role_names.get(role_id.lower())
        container.upsert_item(
            {
                "id": hashlib.sha256(assignment["id"].lower().encode()).hexdigest()[:32],
                "subscriptionId": subscription_id,
                "roleAssignmentId": assignment["id"],
                "principalId": props.get("principalId"),
                "principalType": props.get("principalType"),
                "roleDefinitionId": role_id,
                "roleName": role_name,
                "isPrivileged": role_name in PRIVILEGED_ROLES,
                "scope": props.get("scope"),
                "createdOn": props.get("createdOn"),
                "collectedAt": collected_at,
                "runId": run_id,
            }
        )
        written += 1

    logging.info("role assignment run %s complete: %d documents", run_id, written)
    return {"runId": run_id, "written": written, "collectedAt": collected_at}


@app.timer_trigger(schedule="0 30 5 * * *", arg_name="timer", run_on_startup=False)
def collect_roles_nightly(timer: func.TimerRequest) -> None:
    """Nightly role assignment snapshot at 05:30 UTC, after the assessments sweep."""
    _collect_role_assignments()


@app.route(route="collect_roles", auth_level=func.AuthLevel.FUNCTION)
def collect_roles_now(req: func.HttpRequest) -> func.HttpResponse:
    """Manual trigger: hit the endpoint, get the run summary."""
    result = _collect_role_assignments()
    return func.HttpResponse(
        f"run {result['runId']}: {result['written']} role assignments at {result['collectedAt']}\n",
        status_code=200,
    )
