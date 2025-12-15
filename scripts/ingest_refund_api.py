import os
import json
import sys
import traceback
import hashlib
import copy
from pathlib import Path
from datetime import datetime, timezone

from dotenv import load_dotenv
import yaml

import json as _json  # for logs

from postman_api import (
    # Spec Hub / Collection
    create_spec,
    generate_collection,
    get_collection,
    openapi_to_collection,
    # Collections lifecycle
    upsert_collection,
    create_empty_collection,
    resolve_collection_uid,
    delete_collection,
    # Environments
    upsert_environment,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "specs" / "payment-refund-api-openapi.yaml"
JWT_SCRIPT = ROOT / "scripts" / "jwt_prerequest.js"
OUT = ROOT / "generated"


def env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing env var: {name}")
    return value


def main():
    load_dotenv()

    # Allow forcing regeneration via CLI flag or env var
    force_run = ("--force" in sys.argv) or (
        os.getenv("POSTMAN_FORCE", "").lower() in ("1", "true", "yes")
    )

    OUT.mkdir(exist_ok=True)
    (OUT / "environments").mkdir(exist_ok=True)
    log_file = OUT / "postman_actions.log"

    def _write_log(action: str, status: str, details=None):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "status": status,
            "details": details,
        }
        try:
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write(_json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            # Logging must not break the main flow
            sys.stderr.write("Failed to write log entry: " + traceback.format_exc())

    api_key = env("POSTMAN_API_KEY")
    workspace_id = env("POSTMAN_WORKSPACE_ID")

    print("🔹 Reading OpenAPI spec")
    spec_content = SPEC_PATH.read_text(encoding="utf-8")

    # Derive spec metadata (name/version) from the OpenAPI file when env vars are not provided
    try:
        spec_obj = yaml.safe_load(spec_content) or {}
    except Exception:
        spec_obj = {}

    spec_name = (
        os.getenv("POSTMAN_SPEC_NAME")
        or spec_obj.get("info", {}).get("title")
        or "Refund API Spec"
    )
    spec_version = (
        os.getenv("POSTMAN_SPEC_VERSION")
        or spec_obj.get("info", {}).get("version")
        or "1.0.0"
    )

    # Compute SHA256 of the spec to detect drift and avoid unnecessary churn
    state_file = OUT / "state.json"
    spec_sha256 = hashlib.sha256(spec_content.encode("utf-8")).hexdigest()

    prev_state = {}
    prev_hash = None
    try:
        if state_file.exists():
            prev_state = json.loads(state_file.read_text(encoding="utf-8"))
            prev_hash = prev_state.get("spec_sha256")
    except Exception:
        prev_state = {}
        prev_hash = None

    # ---- Resolve a stable target collection UID (this is the key to idempotency) ----
    provided_raw = os.getenv("POSTMAN_COLLECTION_UID", "")
    provided = provided_raw.strip() if provided_raw and provided_raw.strip() else None

    state_uid = prev_state.get("collection_uid") if isinstance(prev_state, dict) else None

    target_uid = None
    uid_source = None

    # 1) Try env-provided UID (if set)
    if provided:
        try:
            resolved_uid, reason = resolve_collection_uid(api_key, workspace_id, provided)
        except Exception as e:
            _write_log("collection_uid_resolution", "error", {"error": str(e)})
            resolved_uid, reason = None, "error"

        if resolved_uid:
            target_uid = resolved_uid
            uid_source = f"env:{reason or 'resolved'}"
            _write_log(
                "collection_uid_resolution",
                "verified_existing" if reason == "verified_existing" else "recovered",
                {"source": "env", "reason": reason},
            )
        else:
            _write_log(
                "collection_uid_resolution",
                "not_found",
                {"source": "env", "reason": reason},
            )
            # If env UID is stale, try to fall back to a previously bootstrapped UID in state.json
            if state_uid:
                target_uid = state_uid
                uid_source = "state_fallback_from_stale_env"
                _write_log(
                    "collection_uid_resolution",
                    "using_state_fallback",
                    {"note": "env invalid; using state uid", "uid_omitted": True},
                )

    # 2) If still no target, try state uid
    if not target_uid and state_uid:
        target_uid = state_uid
        uid_source = "state"

    # ---- Drift short-circuit (only safe if we have a target UID and we are not forcing) ----
    if prev_hash == spec_sha256 and not force_run and target_uid:
        print("🔒 No spec drift detected; skipping collection regeneration.")
        _write_log("spec_hash_check", "unchanged", {"spec_sha256": spec_sha256})
        print("This is safe to run on every merge. It's idempotent and avoids churn.")
        print("To force regeneration, run with `--force` or set `POSTMAN_FORCE=true`.")
        return
    else:
        _write_log("spec_hash_check", "changed", {"prev": prev_hash, "now": spec_sha256})

    # ---- Decide whether to use Spec Hub generation ----
    # Key rule to prevent duplicates:
    #   If we have a resolved target_uid (env or state), DO NOT generate a new collection from Spec Hub.
    use_spec_hub_flag = os.getenv("USE_SPEC_HUB", "false").lower() in ("1", "true", "yes")
    allow_bootstrap = os.getenv("POSTMAN_ALLOW_BOOTSTRAP_CREATE", "false").lower() in (
        "1",
        "true",
        "yes",
    )

    should_use_spec_hub_for_collection = bool(use_spec_hub_flag) and not bool(target_uid)

    # Always produce a collection payload to write/upsert
    collection = None
    imported_uid = None
    spec_id = None

    # ---- If we don't have a target_uid, we must create one (bootstrap), otherwise we'll create duplicates forever ----
    if not target_uid:
        if not allow_bootstrap:
            print("FATAL: No POSTMAN_COLLECTION_UID provided and no persisted UID found.")
            print("Bootstrap creation is disabled. Set POSTMAN_ALLOW_BOOTSTRAP_CREATE=true or provide POSTMAN_COLLECTION_UID.")
            sys.exit(1)

        print("🔹 Creating empty Postman collection (first-run bootstrap enabled)")
        try:
            target_uid = create_empty_collection(api_key, workspace_id, "Payments – Refund API")
            uid_source = "created_bootstrap"
            _write_log("create_empty_collection", "success", {"uid_omitted": True})
        except Exception as e:
            _write_log("create_empty_collection", "failed", {"error": str(e)})
            raise

    # ---- Optional Spec Hub: create spec + generate collection ONLY on first run (no target_uid existed before bootstrap) ----
    # Note: we may have just created target_uid above; we still do NOT generate a new collection if target_uid exists.
    if should_use_spec_hub_for_collection:
        print("🔹 Creating Spec in Spec Hub")
        _write_log("create_spec_attempt", "starting", {"name": spec_name, "version": spec_version})
        try:
            spec_id = create_spec(api_key, workspace_id, spec_name, spec_content, spec_version)
            print(f"✅ Spec created: {spec_id}")
            _write_log("create_spec", "success", {"spec_id": spec_id})

            print("🔹 Generating Collection from Spec")
            _write_log("generate_collection_attempt", "starting", {"spec_id": spec_id})

            gen = generate_collection(api_key, spec_id, name="Payments – Refund API")
            # generation response can vary; try to extract uid and then fetch
            generated_uid = (
                (gen or {}).get("collectionUid")
                or (gen or {}).get("collection_id")
                or (gen or {}).get("collectionId")
                or ((gen or {}).get("collection") or {}).get("uid")
                or ((gen or {}).get("collection") or {}).get("id")
                or (gen or {}).get("uid")
                or (gen or {}).get("id")
            )

            if generated_uid:
                try:
                    full = get_collection(api_key, generated_uid)
                    if isinstance(full, dict) and "collection" in full and isinstance(full["collection"], dict):
                        full = full["collection"]
                    collection = full
                    imported_uid = generated_uid
                    _write_log("get_generated_collection", "success", {"uid": generated_uid})
                except Exception as e:
                    _write_log("get_generated_collection", "failed", {"uid": generated_uid, "error": str(e)})
                    collection = None

            _write_log(
                "generate_collection",
                "success",
                {"spec_id": spec_id, "collection_preview": (collection or {}).get("info", {}).get("name")},
            )

        except Exception as e:
            err = str(e)
            print("⚠️ Spec Hub flow failed; will fall back to local conversion:", err)
            _write_log("spec_hub_flow", "failed", {"error": err})
            collection = None

    # ---- Local conversion is the stable path for idempotent upserts to a fixed UID ----
    if not collection:
        _write_log("local_conversion", "starting", {"reason": "stable_upsert_to_target_uid", "target_uid_present": True})
        coll_for_write = openapi_to_collection(spec_content, spec_name)
        _write_log("local_conversion", "success", {"generated_items": len(coll_for_write.get("item") or [])})
        print("✅ Generated collection from OpenAPI locally.")

    else:
        coll_for_write = collection
        # If spec hub returned a collection without items, generate items locally
        if not (coll_for_write.get("item") or coll_for_write.get("items")):
            print("⚠️ Generated collection contains no requests; generating items locally from OpenAPI")
            _write_log("local_conversion", "starting", {"reason": "generated_missing_items"})
            coll_for_write = openapi_to_collection(spec_content, spec_name)
            _write_log("local_conversion", "success", {"generated_items": len(coll_for_write.get("item") or [])})

    if not isinstance(coll_for_write, dict) or not coll_for_write.get("info") or not (coll_for_write.get("item") or coll_for_write.get("items")):
        raise RuntimeError("Generated collection is missing required fields ('info' and 'item').")

    # ---- Normalize name so the Postman UI looks right ----
    coll_for_write.setdefault("info", {})
    coll_for_write["info"]["name"] = "Payments – Refund API"

    # ---- Inject JWT pre-request script ----
    print("🔹 Injecting JWT pre-request script")
    jwt_code = JWT_SCRIPT.read_text(encoding="utf-8").splitlines()
    coll_for_write.setdefault("event", []).append(
        {
            "listen": "prerequest",
            "script": {"type": "text/javascript", "exec": jwt_code},
        }
    )

    # ---- Inject linked collections (optional) ----
    linked_env = os.getenv("POSTMAN_LINKED_COLLECTION_UIDS", "").strip()
    if linked_env:
        uids = [u.strip() for u in linked_env.split(",") if u.strip()]
        if uids:
            coll_for_write["linked_collections"] = uids
            _write_log("linked_collections_injected", "success", {"count": len(uids)})

    # ---- Write generated collection JSON artifact ----
    collection_path = OUT / "refund.collection.json"
    collection_path.write_text(json.dumps({"collection": coll_for_write}, indent=2), encoding="utf-8")
    print(f"✅ Collection written to {collection_path}")
    _write_log("write_collection_file", "success", {"path": str(collection_path)})

    # ---- Upsert collection (PATCH + PUT fallback) ----
    use_patch = os.getenv("POSTMAN_USE_PATCH", "false").lower() in ("1", "true", "yes")
    do_sync_linked = os.getenv("SYNC_LINKED_COLLECTIONS", "false").lower() in ("1", "true", "yes")

    print("🔹 Upserting collection to Postman")

    patch_attempted = False
    patch_succeeded = False
    put_performed = False
    patch_reason = None
    item_hash = None

    if use_patch and target_uid:
        patch_attempted = True
        try:
            from postman_api import patch_collection_metadata_only

            patch_payload = copy.deepcopy(coll_for_write)
            schema_removed = False
            if isinstance(patch_payload, dict) and isinstance(patch_payload.get("info"), dict) and "schema" in patch_payload["info"]:
                del patch_payload["info"]["schema"]
                schema_removed = True

            _write_log("patch_payload_sanitized", "success", {"schema_removed": bool(schema_removed)})
            if schema_removed:
                print("🔹 PATCH payload sanitized: removed collection.info.schema")

            patch_collection_metadata_only(api_key, target_uid, patch_payload)
            patch_succeeded = True
            _write_log("patch_collection", "success", {"uid": target_uid})
            print("✅ PATCH (metadata-only) succeeded")

        except Exception as e:
            patch_succeeded = False
            _write_log("patch_collection", "failed", {"error": str(e)})
            print("⚠️ PATCH failed, will fall back to PUT upsert:", e)

        # decide if we need PUT based on item hash
        try:
            items = coll_for_write.get("item") or coll_for_write.get("items") or []
            item_hash = hashlib.sha256(json.dumps(items, sort_keys=True).encode("utf-8")).hexdigest()
        except Exception:
            item_hash = None

        prev_item_hash = (prev_state or {}).get("item_hash") or (prev_state or {}).get("item_sha256")

        if (not patch_succeeded) or (item_hash and prev_item_hash != item_hash):
            if not patch_succeeded:
                patch_reason = "patch_failed"
                print("PATCH failed; performing PUT upsert")
            else:
                patch_reason = "structure_changed"
                print("Item structure changed; performing PUT upsert")

            coll_result = upsert_collection(api_key, workspace_id, coll_for_write, target_uid)
            put_performed = True
        else:
            patch_reason = "structure_unchanged"
            coll_result = target_uid

    else:
        coll_result = upsert_collection(api_key, workspace_id, coll_for_write, target_uid)
        patch_reason = "patch_disabled_or_no_uid"

    # Sync linked collections once (only after successful patch/put path)
    if use_patch and do_sync_linked and patch_attempted and (patch_succeeded or put_performed):
        try:
            from postman_api import sync_linked_collections

            linked_results = sync_linked_collections(api_key, workspace_id, coll_for_write)
            _write_log("sync_linked_collections", "success", {"results": linked_results})
            if linked_results:
                print(f"✅ Synced {len(linked_results)} linked collections")
        except Exception as e:
            _write_log("sync_linked_collections", "failed", {"error": str(e)})
            print("⚠️ Failed to sync linked collections:", e)

    # Normalize result uid
    if isinstance(coll_result, str):
        collection_uid_result = coll_result
    elif isinstance(coll_result, dict):
        collection_uid_result = (
            (coll_result.get("collection") or {}).get("uid")
            or (coll_result.get("collection") or {}).get("id")
            or coll_result.get("uid")
            or coll_result.get("id")
        )
    else:
        collection_uid_result = str(coll_result)

    print(f"✅ Collection upsert result: {collection_uid_result}")
    _write_log("upsert_collection", "success", {"uid": collection_uid_result})

    # If spec hub generation created a different collection, delete it (best-effort)
    try:
        if imported_uid and collection_uid_result and imported_uid != collection_uid_result:
            delete_collection(api_key, imported_uid)
            _write_log("delete_imported_collection", "success", {"imported_uid": imported_uid})
    except Exception as e:
        _write_log("delete_imported_collection", "failed", {"error": str(e)})

    if patch_attempted:
        summary = {
            "patch_attempted": patch_attempted,
            "patch_succeeded": patch_succeeded,
            "put_performed": put_performed,
            "patch_reason": patch_reason,
            "collection_uid": collection_uid_result,
        }
        _write_log("patch_summary", "info", summary)
        print(
            f"🔹 PATCH summary: attempted={patch_attempted} succeeded={patch_succeeded} "
            f"put_performed={put_performed} reason={patch_reason}"
        )

    # ---- Environments ----
    environments = {
        "Dev": env("DEV_BASE_URL"),
        "QA": env("QA_BASE_URL"),
        "UAT": env("UAT_BASE_URL"),
        "Prod": env("PROD_BASE_URL"),
    }

    for name, base_url in environments.items():
        print(f"🔹 Creating/Upserting {name} environment")
        env_payload = {
            "name": f"Payments – Refund API – {name}",
            "values": [
                {"key": "base_url", "value": base_url, "enabled": True},
                {"key": "jwt_issuer", "value": env("JWT_ISSUER"), "enabled": True},
                {"key": "jwt_audience", "value": env("JWT_AUDIENCE"), "enabled": True},
                {"key": "jwt_secret", "value": env("JWT_SECRET"), "enabled": True},
            ],
        }

        env_uid_key = f"POSTMAN_ENV_UID_{name.upper()}"
        env_uid = os.getenv(env_uid_key) or os.getenv("POSTMAN_ENV_UID")

        uid = upsert_environment(api_key, workspace_id, env_payload, env_uid)

        out_file = OUT / "environments" / f"{name.lower()}.environment.json"
        out_file.write_text(json.dumps({"uid": uid, "payload": env_payload}, indent=2), encoding="utf-8")
        print(f"✅ {name} environment upserted: {uid}")
        _write_log("upsert_environment", "success", {"environment": name, "uid": uid})

    # ---- Write postman_ids.json ----
    postman_ids = {"collection_uid": collection_uid_result, "environments": {}}
    for name in environments.keys():
        env_file = OUT / "environments" / f"{name.lower()}.environment.json"
        try:
            obj = json.loads(env_file.read_text(encoding="utf-8"))
            postman_ids["environments"][name.lower()] = obj.get("uid")
        except Exception:
            postman_ids["environments"][name.lower()] = None

    ids_file = OUT / "postman_ids.json"
    ids_file.write_text(json.dumps(postman_ids, indent=2), encoding="utf-8")
    print(f"✅ Wrote Postman IDs to {ids_file}")

    # ---- Persist state.json ----
    try:
        state_obj = {
            "spec_sha256": spec_sha256,
            "last_synced_at": datetime.now(timezone.utc).isoformat(),
            "collection_uid": collection_uid_result,
            "collection_uid_source": uid_source or "unknown",
            "environments": postman_ids.get("environments", {}),
        }
        if spec_id:
            state_obj["spec_id"] = spec_id
        if item_hash:
            state_obj["item_hash"] = item_hash

        state_file.write_text(json.dumps(state_obj, indent=2), encoding="utf-8")
        _write_log("state_write", "success", {"path": str(state_file)})
    except Exception as e:
        _write_log("state_write", "failed", {"error": str(e)})

    print("\n🎉 Ingestion complete. Postman is now an accelerator, not a checkbox.")


if __name__ == "__main__":
    main()
