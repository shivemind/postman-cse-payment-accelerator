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
from postman_api import (
    import_openapi,
    create_environment,
    upsert_collection,
    upsert_environment,
    create_spec,
    generate_collection,
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

    # Allow forcing regeneration via CLI flag or env var
    force_run = ("--force" in sys.argv) or (os.getenv("POSTMAN_FORCE", "").lower() in ("1", "true", "yes"))

    OUT.mkdir(exist_ok=True)
    (OUT / "environments").mkdir(exist_ok=True)
    log_file = OUT / "postman_actions.log"

    def _write_log(action: str, status: str, details: dict | str | None = None):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "status": status,
            "details": details
        }
        try:
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write(_json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            # Logging must not break the main flow; write to stderr as fallback
            sys.stderr.write("Failed to write log entry: " + traceback.format_exc())

    api_key = env("POSTMAN_API_KEY")
    workspace_id = env("POSTMAN_WORKSPACE_ID")

    print("🔹 Reading OpenAPI spec")
    spec_content = SPEC_PATH.read_text()
    # Derive spec metadata (name/version) from the OpenAPI file when env vars are not provided
    try:
        spec_obj = yaml.safe_load(spec_content) or {}
    except Exception:
        spec_obj = {}

    spec_name = os.getenv("POSTMAN_SPEC_NAME") or spec_obj.get("info", {}).get("title") or "Refund API Spec"
    spec_version = os.getenv("POSTMAN_SPEC_VERSION") or spec_obj.get("info", {}).get("version") or "1.0.0"

    # Compute SHA256 of the spec to detect drift and avoid unnecessary churn
    state_file = OUT / "state.json"
    spec_sha256 = hashlib.sha256(spec_content.encode("utf-8")).hexdigest()
    prev_hash = None
    prev_state = {}
    try:
        if state_file.exists():
            prev_state = json.loads(state_file.read_text())
            prev_hash = prev_state.get("spec_sha256")
    except Exception:
        prev_hash = None

    if prev_hash == spec_sha256 and not force_run:
        print("🔒 No spec drift detected; skipping Postman import/regen.")
        _write_log("spec_hash_check", "unchanged", {"spec_sha256": spec_sha256})
        # Verify environments exist; if missing, upsert them
        try:
            from postman_api import get_environment_by_name
            missing = []
            for name in ("Dev", "QA", "UAT", "Prod"):
                env_name = f"Payments – Refund API – {name}"
                uid = get_environment_by_name(api_key, workspace_id, env_name)
                if not uid:
                    missing.append(name)
            if missing:
                print(f"⚠️ Environments missing: {missing}. Upserting missing environments.")
                # fall through to normal upsert flow to create missing envs
            else:
                print("This is safe to run on every merge. It's idempotent and avoids churn.")
                print("To force regeneration, run with `--force` or set `POSTMAN_FORCE=true`.")
                return
        except Exception:
            # If verification fails, proceed with normal flow to be safe
            pass
    else:
        _write_log("spec_hash_check", "changed", {"prev": prev_hash, "now": spec_sha256})

    # Choose flow: Spec Hub (create_spec -> generate_collection) or Import API.
    use_spec_hub = os.getenv("USE_SPEC_HUB", "false").lower() in ("1", "true", "yes")
    collection = None
    if use_spec_hub:
        print("🔹 Creating Spec in Spec Hub")
        _write_log("create_spec_attempt", "starting", {"name": spec_name, "version": spec_version})
        try:
            spec_id = create_spec(api_key, workspace_id, spec_name, spec_content, spec_version)
            print(f"✅ Spec created: {spec_id}")
            _write_log("create_spec", "success", {"spec_id": spec_id})

            print("🔹 Generating Collection from Spec")
            _write_log("generate_collection_attempt", "starting", {"spec_id": spec_id})
            collection = generate_collection(api_key, spec_id)
            _write_log("generate_collection", "success", {"spec_id": spec_id, "collection_preview": (collection.get('info', {}).get('name') if isinstance(collection, dict) else None)})
        except Exception as e:
            err = str(e)
            print("⚠️ Spec Hub flow failed, falling back to Import API:", err)
            _write_log("create_spec", "failed", {"error": err})

    if collection is None:
        print("🔹 Importing OpenAPI spec via Postman Import API")
        _write_log("import_openapi_attempt", "starting", {"name": spec_name})
        collection = import_openapi(api_key, workspace_id, spec_name, spec_content)
        # Try to extract a UID if Postman created the collection on import
        try:
            imported_uid = (
                (collection.get("uid") if isinstance(collection, dict) else None)
                or (collection.get("collection") or {}).get("uid")
                or (collection.get("collection") or {}).get("id")
            )
        except Exception:
            imported_uid = None
        _write_log("import_openapi", "success", {"imported_uid": imported_uid})
        print(f"✅ Collection generated")

    # If the import/generation returned a collection with no `item` entries,
    # fall back to a local converter to ensure the collection contains requests.
    from postman_api import openapi_to_collection
    coll_for_write = collection
    if not isinstance(collection, dict) or (isinstance(collection, dict) and not (collection.get("item") or collection.get("items"))):
        print("⚠️ Imported collection contains no requests; generating items locally from OpenAPI spec")
        _write_log("local_conversion", "starting", {"reason": "import_missing_items"})
        try:
            coll_for_write = openapi_to_collection(spec_content, spec_name)
            _write_log("local_conversion", "success", {"generated_items": len(coll_for_write.get("item") or [])})
        except Exception as e:
            _write_log("local_conversion", "failed", {"error": str(e)})
            print("Failed to convert OpenAPI to collection locally:", e)

    print("🔹 Injecting JWT pre-request script")
    jwt_code = JWT_SCRIPT.read_text().splitlines()
    collection.setdefault("event", []).append({
        "listen": "prerequest",
        "script": {
            "type": "text/javascript",
            "exec": jwt_code
        }
    })

    # Upsert the collection to Postman (use existing UID if provided)
    collection_path = OUT / "refund.collection.json"
    # Write the converted or imported collection (prefer collection object wrapped)
    collection_path.write_text(json.dumps({"collection": coll_for_write}, indent=2))
    print(f"✅ Collection written to {collection_path}")
    _write_log("write_collection_file", "success", {"path": str(collection_path)})

    # Prefer an explicit env override, otherwise try to reuse any UID returned
    # by the Import/OpenAPI (or Spec Hub) call so we update the existing
    # imported collection instead of creating a duplicate.
    def _extract_uid(coll_obj):
        if not coll_obj or not isinstance(coll_obj, dict):
            return None
        # common shapes: {"uid": ...} or {"collection": {"uid": ...}}
        return (
            coll_obj.get("uid")
            or (coll_obj.get("collection") or {}).get("uid")
            or coll_obj.get("id")
            or (coll_obj.get("collection") or {}).get("id")
        )

    env_collection_uid = os.getenv("POSTMAN_COLLECTION_UID")
    returned_uid = _extract_uid(collection)
    collection_uid = env_collection_uid or returned_uid

    # Determine whether to perform a PATCH-style partial update
    use_patch = os.getenv("POSTMAN_USE_PATCH", "false").lower() in ("1", "true", "yes")
    print("🔹 Upserting collection to Postman")
    used_patch = False
    if use_patch and collection_uid:
        # When using PATCH, we send only the parts that changed. For simplicity we
        # send the full collection wrapped as-is; the Postman API may accept PATCH
        # or will raise; callers can set POSTMAN_USE_PATCH to false if PATCH fails.
        try:
            from postman_api import patch_collection
            coll_result = patch_collection(api_key, collection_uid, {"collection": coll_for_write})
            used_patch = True
        except Exception as e:
            print("⚠️ PATCH failed, falling back to upsert PUT/POST:", e)
            coll_result = upsert_collection(api_key, workspace_id, coll_for_write, collection_uid)
    else:
        coll_result = upsert_collection(api_key, workspace_id, coll_for_write, collection_uid)
    # coll_result may be a UID string or a richer object; normalize to uid
    collection_uid_result = None
    if isinstance(coll_result, str):
        collection_uid_result = coll_result
    elif isinstance(coll_result, dict):
        collection_uid_result = coll_result.get("collection") or coll_result.get("uid") or coll_result.get("id")
    else:
        collection_uid_result = str(coll_result)

    print(f"✅ Collection upsert result: {collection_uid_result}")
    _write_log("upsert_collection", "success", {"uid": collection_uid_result})

    if used_patch:
        _write_log("patch_collection", "success", {"uid": collection_uid_result})

    # Sync any linked collections declared inside the collection payload
    try:
        from postman_api import sync_linked_collections
        linked_results = sync_linked_collections(api_key, workspace_id, coll_for_write)
        if linked_results:
            _write_log("sync_linked_collections", "success", {"results": linked_results})
            print(f"✅ Synced {len(linked_results)} linked collections")
    except Exception as e:
        _write_log("sync_linked_collections", "failed", {"error": str(e)})
        print("⚠️ Failed to sync linked collections:", e)

    environments = {
        "Dev": env("DEV_BASE_URL"),
        "QA": env("QA_BASE_URL"),
        "UAT": env("UAT_BASE_URL"),
        "Prod": env("PROD_BASE_URL")
    }

    for name, base_url in environments.items():
        print(f"🔹 Creating/Upserting {name} environment")
        env_payload = {
            "name": f"Payments – Refund API – {name}",
            "values": [
                {"key": "base_url", "value": base_url, "enabled": True},
                {"key": "jwt_issuer", "value": env("JWT_ISSUER"), "enabled": True},
                {"key": "jwt_audience", "value": env("JWT_AUDIENCE"), "enabled": True},
                {"key": "jwt_secret", "value": env("JWT_SECRET"), "enabled": True}
            ]
        }

        # Check for per-environment UID env var (e.g. POSTMAN_ENV_UID_DEV) or generic POSTMAN_ENV_UID
        env_uid_key = f"POSTMAN_ENV_UID_{name.upper()}"
        env_uid = os.getenv(env_uid_key) or os.getenv("POSTMAN_ENV_UID")

        uid = upsert_environment(api_key, workspace_id, env_payload, env_uid)

        out_file = OUT / "environments" / f"{name.lower()}.environment.json"
        out_file.write_text(json.dumps({"uid": uid, "payload": env_payload}, indent=2))
        print(f"✅ {name} environment upserted: {uid}")
        _write_log("upsert_environment", "success", {"environment": name, "uid": uid})

    # Persist UIDs for cleanup or later actions
    postman_ids = {
        "collection_uid": collection_uid_result,
        "environments": {}
    }

    for name in environments.keys():
        env_file = OUT / "environments" / f"{name.lower()}.environment.json"
        try:
            obj = json.loads(env_file.read_text())
            postman_ids["environments"][name.lower()] = obj.get("uid") or obj.get("payload", {}).get("name")
        except Exception:
            postman_ids["environments"][name.lower()] = None

    ids_file = OUT / "postman_ids.json"
    ids_file.write_text(json.dumps(postman_ids, indent=2))
    print(f"✅ Wrote Postman IDs to {ids_file}")

    # Persist spec hash/state so future runs can skip work if nothing changed
    try:
        state_obj = {
            "spec_sha256": spec_sha256,
            "last_synced_at": datetime.now(timezone.utc).isoformat(),
            "collection_uid": collection_uid_result,
            "environments": postman_ids.get("environments", {}),
        }
        # include spec_id if available from spec hub flow
        try:
            if 'spec_id' in locals() and spec_id:
                state_obj["spec_id"] = spec_id
        except Exception:
            pass

        state_file.write_text(json.dumps(state_obj, indent=2))
        _write_log("state_write", "success", {"path": str(state_file)})
    except Exception as e:
        _write_log("state_write", "failed", {"error": str(e)})

    print("\n🎉 Ingestion complete. Postman is now an accelerator, not a checkbox.")

if __name__ == "__main__":
    main()
