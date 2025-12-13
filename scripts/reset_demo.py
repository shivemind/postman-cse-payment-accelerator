import os
import sys
import json
from pathlib import Path
from dotenv import load_dotenv
from postman_api import (
    delete_collection,
    delete_environment,
    get_collection_by_name,
    get_environment_by_name,
)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated"


def env(name):
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"Missing env var: {name}")
    return v


def main():
    load_dotenv()
    api_key = env("POSTMAN_API_KEY")
    workspace_id = env("POSTMAN_WORKSPACE_ID")

    ids_file = OUT / "postman_ids.json"
    state_file = OUT / "state.json"
    collection_uid = None
    env_uids = {}
    # If a secret override is provided, prefer it (explicit intent).
    provided_uid = os.getenv("POSTMAN_COLLECTION_UID", "").strip() or None
    if provided_uid:
        collection_uid = provided_uid

    # If no explicit UID provided, try postman_ids.json artifact first (created by ingest job)
    if not collection_uid and ids_file.exists():
        try:
            obj = json.loads(ids_file.read_text())
            collection_uid = obj.get("collection_uid")
            env_uids = obj.get("environments") or {}
        except Exception:
            pass

    # Next fallback: read generated/state.json which may contain a persisted bootstrap UID
    if not collection_uid and state_file.exists():
        try:
            obj = json.loads(state_file.read_text())
            collection_uid = obj.get("collection_uid")
        except Exception:
            pass

    # Resolve by name if not present
    if not collection_uid:
        collection_uid = get_collection_by_name(api_key, workspace_id, "Payment Refund API")

    env_names = {
        "dev": "Payments – Refund API – Dev",
        "qa": "Payments – Refund API – QA",
        "uat": "Payments – Refund API – UAT",
        "prod": "Payments – Refund API – Prod",
    }

    for key, name in env_names.items():
        if not env_uids.get(key):
            uid = get_environment_by_name(api_key, workspace_id, name)
            if uid:
                env_uids[key] = uid

    errors = []

    if collection_uid:
        print(f"Deleting collection: {collection_uid}")
        try:
            delete_collection(api_key, collection_uid)
            print("Deleted collection")
        except Exception as e:
            msg = str(e)
            low = msg.lower()
            # Treat HTTP 404 with instanceNotFoundError as already-deleted (non-fatal)
            if "404" in msg and "instancenotfounderror" in low:
                print("Already deleted")
            else:
                print("Failed to delete collection:", e)
                errors.append(str(e))
    else:
        print("No collection UID found; skipping collection delete")

    for k, uid in env_uids.items():
        if not uid:
            continue
        print(f"Deleting environment {k}: {uid}")
        try:
            delete_environment(api_key, uid)
            print("Deleted environment")
        except Exception as e:
            msg = str(e)
            low = msg.lower()
            if "404" in msg and "instancenotfounderror" in low:
                print("Already deleted")
            else:
                print(f"Failed to delete environment {k}:", e)
                errors.append(str(e))

    if errors:
        print("Completed with errors:")
        for e in errors:
            print("-", e)
        sys.exit(1)

    print("Reset completed successfully")


if __name__ == "__main__":
    main()
