#!/usr/bin/env python3
import os
import json
from pathlib import Path
from dotenv import load_dotenv
import yaml
from datetime import datetime, timezone
import hashlib
import sys
import traceback
import json as _json
import copy

from postman_api import (
    upsert_collection,
    upsert_environment,
    create_spec,
    generate_collection,
    resolve_collection_uid,
    delete_collection,
    openapi_to_collection,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "specs" / "payment-refund-api-openapi.yaml"
JWT_SCRIPT = ROOT / "scripts" / "jwt_prerequest.js"
OUT = ROOT / "generated"


def env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing env var: {name}")
    return value


def main():
    load_dotenv()

    force_run = ("--force" in sys.argv) or os.getenv("POSTMAN_FORCE", "").lower() in ("1", "true", "yes")

    OUT.mkdir(exist_ok=True)
    (OUT / "environments").mkdir(exist_ok=True)

    log_file = OUT / "postman_actions.log"

    def _write_log(action, status, details=None):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "status": status,
            "details": details,
        }
        try:
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write(_json.dumps(entry) + "\n")
        except Exception:
            sys.stderr.write("Log write failed:\n" + traceback.format_exc())

    api_key = env("POSTMAN_API_KEY")
    workspace_id = env("POSTMAN_WORKSPACE_ID")

    print("🔹 Reading OpenAPI spec")
    spec_content = SPEC_PATH.read_text()
    spec_obj = yaml.safe_load(spec_content) or {}

    spec_name = os.getenv("POSTMAN_SPEC_NAME") or spec_obj.get("info", {}).get("title") or "Refund API"
    spec_version = os.getenv("POSTMAN_SPEC_VERSION") or spec_obj.get("info", {}).get("version") or "1.0.0"

    spec_sha256 = hashlib.sha256(spec_content.encode()).hexdigest()
    state_file = OUT / "state.json"

    prev_state = {}
    if state_file.exists():
        prev_state = json.loads(state_file.read_text())

    prev_hash = prev_state.get("spec_sha256")

    if prev_hash == spec_sha256 and not force_run:
        print("🔒 No spec drift detected. Safe to skip.")
        return

    # -------------------------------
    # COLLECTION UID RESOLUTION (HARD GUARANTEES)
    # -------------------------------
    provided_uid = os.getenv("POSTMAN_COLLECTION_UID", "").strip() or None
    allow_bootstrap = os.getenv("POSTMAN_ALLOW_BOOTSTRAP_CREATE", "false").lower() in ("1", "true", "yes")

    target_uid = None
    uid_source = None

    if provided_uid:
        resolved_uid, reason = resolve_collection_uid(api_key, workspace_id, provided_uid)
        if not resolved_uid:
            if not allow_bootstrap:
                print("\n❌ FATAL: POSTMAN_COLLECTION_UID was provided but not found in this workspace.")
                print("This pipeline is configured to FAIL instead of creating duplicates.")
                print("Fix the secret or explicitly allow bootstrap creation.\n")
                sys.exit(1)

            print("⚠️ Provided UID invalid, bootstrap allowed — creating new collection")
            from postman_api import create_empty_collection

            target_uid = create_empty_collection(api_key, workspace_id, "Payments – Refund API")
            uid_source = "bootstrap_created"
        else:
            target_uid = resolved_uid
            uid_source = "env_secret_verified"
            print("✅ Using provided POSTMAN_COLLECTION_UID")

    elif prev_state.get("collection_uid"):
        if not allow_bootstrap:
            print("\n❌ FATAL: No POSTMAN_COLLECTION_UID provided and bootstrap disabled.")
            sys.exit(1)
        target_uid = prev_state["collection_uid"]
        uid_source = "state_reuse"

    else:
        if not allow_bootstrap:
            print("\n❌ FATAL: No collection UID and bootstrap disabled.")
            sys.exit(1)

        from postman_api import create_empty_collection

        print("🔹 First-run bootstrap: creating collection")
        target_uid = create_empty_collection(api_key, workspace_id, "Payments – Refund API")
        uid_source = "bootstrap_created"

    # -------------------------------
    # GENERATE COLLECTION LOCALLY
    # -------------------------------
    collection = openapi_to_collection(spec_content, spec_name)

    # Inject JWT prerequest
    jwt_code = JWT_SCRIPT.read_text().splitlines()
    collection.setdefault("event", []).append({
        "listen": "prerequest",
        "script": {"type": "text/javascript", "exec": jwt_code},
    })

    # Inject linked collections
    linked_env = os.getenv("POSTMAN_LINKED_COLLECTION_UIDS", "").strip()
    if linked_env:
        collection["linked_collections"] = [u.strip() for u in linked_env.split(",") if u.strip()]

    # -------------------------------
    # PATCH + PUT DECISION
    # -------------------------------
    use_patch = os.getenv("POSTMAN_USE_PATCH", "false").lower() in ("1", "true", "yes")
    do_sync = os.getenv("SYNC_LINKED_COLLECTIONS", "false").lower() in ("1", "true", "yes")

    patch_attempted = False
    patch_succeeded = False
    put_performed = False

    if use_patch:
        patch_attempted = True
        from postman_api import patch_collection_metadata_only

        patch_payload = copy.deepcopy(collection)
        if patch_payload.get("info", {}).get("schema"):
            del patch_payload["info"]["schema"]

        try:
            patch_collection_metadata_only(api_key, target_uid, patch_payload)
            patch_succeeded = True
            print("✅ PATCH metadata succeeded")
        except Exception as e:
            print("⚠️ PATCH failed — will PUT full collection")
            patch_succeeded = False

    if not patch_succeeded:
        upsert_collection(api_key, workspace_id, collection, target_uid)
        put_performed = True

    # -------------------------------
    # LINKED COLLECTION SYNC (ONCE)
    # -------------------------------
    if use_patch and do_sync:
        from postman_api import sync_linked_collections
        sync_linked_collections(api_key, workspace_id, collection)
        print("✅ Linked collections synced")

    # -------------------------------
    # ENVIRONMENTS
    # -------------------------------
    environments = {
        "Dev": env("DEV_BASE_URL"),
        "QA": env("QA_BASE_URL"),
        "UAT": env("UAT_BASE_URL"),
        "Prod": env("PROD_BASE_URL"),
    }

    env_ids = {}

    for name, base_url in environments.items():
        payload = {
            "name": f"Payments – Refund API – {name}",
            "values": [
                {"key": "base_url", "value": base_url, "enabled": True},
                {"key": "jwt_issuer", "value": env("JWT_ISSUER"), "enabled": True},
                {"key": "jwt_audience", "value": env("JWT_AUDIENCE"), "enabled": True},
                {"key": "jwt_secret", "value": env("JWT_SECRET"), "enabled": True},
            ],
        }

        uid = upsert_environment(api_key, workspace_id, payload, None)
        env_ids[name.lower()] = uid
        print(f"✅ {name} environment upserted")

    # -------------------------------
    # STATE WRITE (FINAL AUTHORITY)
    # -------------------------------
    state = {
        "spec_sha256": spec_sha256,
        "collection_uid": target_uid,
        "collection_uid_source": uid_source,
        "environments": env_ids,
        "last_synced_at": datetime.now(timezone.utc).isoformat(),
    }

    state_file.write_text(json.dumps(state, indent=2))
    print("\n🎉 Ingestion complete. No duplicates. Deterministic. Demo-safe.")


if __name__ == "__main__":
    main()
