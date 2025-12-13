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

    # Read any previously persisted collection UID (do not assume it's valid here)
    state_uid = prev_state.get("collection_uid") if prev_state else None

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
    # Resolve target collection UID (support numeric-prefixed UID or plain UUID id)
    from postman_api import resolve_collection_uid, collection_exists, delete_collection

    provided_raw = os.getenv("POSTMAN_COLLECTION_UID", "")
    provided = provided_raw.strip() if provided_raw else None
    target_uid = None
    collection_uid_source = None
    if provided:
        # Resolve the provided POSTMAN_COLLECTION_UID to a workspace collection UID.
        try:
            resolved_uid, reason = resolve_collection_uid(api_key, workspace_id, provided)
        except Exception as e:
            _write_log("collection_uid_resolution", "error", {"error": str(e)})
            resolved_uid = None
            reason = "error"

        if resolved_uid:
            target_uid = resolved_uid
            collection_uid_source = reason or "env_resolved"
            _write_log("collection_uid_resolution", "verified_existing" if reason == "verified_existing" else "recovered", {"source": "env", "reason": reason})
        else:
            # If the provided UID cannot be resolved, check if a previous run
            # created and persisted a collection UID via state.json. In that
            # case prefer the persisted (created) UID so future runs remain
            # deterministic and do not recreate collections repeatedly.
            _write_log("collection_uid_resolution", "not_found", {"source": "env", "reason": reason})

            prev_created_uid = prev_state.get("collection_uid") if prev_state else None
            prev_created_source = prev_state.get("collection_uid_source") if prev_state else None
            if prev_created_uid and isinstance(prev_created_source, str) and prev_created_source.startswith("created"):
                # A prior bootstrap run created the collection; prefer that persisted UID.
                target_uid = prev_created_uid
                collection_uid_source = "state_created_preferred"
                _write_log("collection_uid_resolution", "using_persisted_bootstrap_uid", {"note": "provided env invalid; using persisted created uid", "uid_omitted": True})
                print("🔹 Provided POSTMAN_COLLECTION_UID could not be resolved, but a previously created UID exists in generated/state.json; using that persisted UID (value omitted).")
            else:
                # No persisted UID to prefer. Offer explicit bootstrap when allowed.
                allow_bootstrap = os.getenv("POSTMAN_ALLOW_BOOTSTRAP_CREATE", "false").lower() in ("1", "true", "yes")
                if not allow_bootstrap:
                    print("FATAL: POSTMAN_COLLECTION_UID is set but could not be resolved/found in this workspace for this API key. Refusing to create a new collection.")
                    print("")
                    print("Likely cause:")
                    print(" - The collection UID no longer exists in the workspace (it may have been deleted/reset).")
                    print("")
                    print("Fix options:")
                    print(" - Clear the POSTMAN_COLLECTION_UID secret so the pipeline can create a new UID via state.json (recommended for one-time bootstrap).")
                    print(" - Or enable one-time bootstrap by setting POSTMAN_ALLOW_BOOTSTRAP_CREATE=true in CI to allow this run to create a new collection.")
                    print("")
                    print("Diagnostics:")
                    print(" - Run 'python scripts/diagnose_postman_access.py' to inspect workspace and collection visibility.")
                    _write_log("collection_uid_resolution", "not_found_no_bootstrap", {"source": "env", "reason": reason})
                    sys.exit(1)

                # Bootstrap allowed: create a new collection and persist it so
                # subsequent runs use the persisted UID instead of the stale secret.
                from postman_api import create_empty_collection
                print("🔹 POSTMAN_COLLECTION_UID could not be resolved; POSTMAN_ALLOW_BOOTSTRAP_CREATE enabled — creating a new collection now (one-time)")
                try:
                    created_uid = create_empty_collection(api_key, workspace_id, "Payments – Refund API")
                    _write_log("create_empty_collection", "success", {"created": True})
                    print("CREATED COLLECTION UID (persisted): [value omitted for secrets]")
                    # Persist the created UID immediately to state.json so subsequent runs reuse it
                    state_obj = {
                        "spec_sha256": spec_sha256,
                        "last_synced_at": datetime.now(timezone.utc).isoformat(),
                        "collection_uid": created_uid,
                        "collection_uid_source": "created_by_bootstrap",
                        "environments": prev_state.get("environments", {}) if prev_state else {}
                    }
                    state_file.write_text(json.dumps(state_obj, indent=2))
                    _write_log("state_write", "success", {"path": str(state_file)})
                    # Update in-memory prev_state and target for this run
                    prev_state = state_obj
                    target_uid = created_uid
                    collection_uid_source = "created_by_bootstrap"
                except Exception as e:
                    _write_log("create_empty_collection", "failed", {"error": str(e)})
                    raise

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

    # Decide creation/import behavior:
    # - If POSTMAN_COLLECTION_UID (provided) is set, we MUST NOT call Import API.
    # - If no provided UID but `state_uid` exists, reuse it (do not call Import API which may create new collections).
    # - If neither provided nor state_uid exist, create an empty collection via the API and persist its UID.
    imported_uid = None
    if collection is None and not provided and not state_uid:
        # First-run case: create an empty collection and persist its UID so future runs reuse it.
        # Bootstrapping a new collection is only allowed when explicitly enabled
        allow_bootstrap = os.getenv("POSTMAN_ALLOW_BOOTSTRAP_CREATE", "false").lower() in ("1", "true", "yes")
        if not allow_bootstrap:
            _write_log("bootstrap_attempt", "disabled", {"note": "POSTMAN_ALLOW_BOOTSTRAP_CREATE not enabled"})
            print("FATAL: No POSTMAN_COLLECTION_UID provided and no persisted UID found.")
            print("Bootstrap creation of a new collection is disabled by default.")
            print("To allow creating a new collection set POSTMAN_ALLOW_BOOTSTRAP_CREATE=true in CI, or supply POSTMAN_COLLECTION_UID.")
            sys.exit(1)

        from postman_api import create_empty_collection
        print("🔹 Creating empty Postman collection (first-run, bootstrap enabled)")
        try:
            created_uid = create_empty_collection(api_key, workspace_id, "Payments – Refund API")
            _write_log("create_empty_collection", "success", {"created": True})
            print(f"CREATED COLLECTION UID: {created_uid}")
            # Persist the created UID immediately to state.json so subsequent runs reuse it
            state_obj = {
                "spec_sha256": spec_sha256,
                "last_synced_at": datetime.now(timezone.utc).isoformat(),
                "collection_uid": created_uid,
                "environments": prev_state.get("environments", {}) if prev_state else {}
            }
            state_file.write_text(json.dumps(state_obj, indent=2))
            _write_log("state_write", "success", {"path": str(state_file)})
            # Treat the created UID as the authoritative target for this run
            target_uid = created_uid
            collection_uid_source = "created_uid"
        except Exception as e:
            _write_log("create_empty_collection", "failed", {"error": str(e)})
            raise
    else:
        # Do not call Import API when a provided UID exists (hard rule), nor when we have a persisted state UID.
        if provided:
            print("🔹 Skipping Postman Import API because POSTMAN_COLLECTION_UID is present; will generate locally and upsert to provided UID")
            _write_log("import_openapi", "skipped", {"reason": "POSTMAN_COLLECTION_UID_present"})
        else:
            _write_log("import_openapi", "skipped", {"reason": "state_uid_present_or_spec_hub"})
        # If collection was created by spec hub earlier, extract its UID
        try:
            imported_uid = (
                (collection.get("uid") if isinstance(collection, dict) else None)
                or (collection.get("collection") or {}).get("uid")
                or (collection.get("collection") or {}).get("id")
            )
        except Exception:
            imported_uid = None
        if collection:
            print(f"✅ Collection available (from spec hub or prior step)")

    # If the import/generation returned a collection with no `item` entries,
    # fall back to a local converter to ensure the collection contains requests.
    from postman_api import openapi_to_collection

    # Ensure we always have a valid collection dict to modify and write.
    # If we skipped the Import API because a target UID was provided/resolved,
    # generate the collection locally from the OpenAPI spec so we can inject
    # scripts and upsert into the existing collection.
    if not collection:
        _write_log("local_conversion", "starting", {"reason": "no_import_or_skipped", "target_uid_provided": bool(target_uid)})
        try:
            coll_for_write = openapi_to_collection(spec_content, spec_name)
            _write_log("local_conversion", "success", {"generated_items": len(coll_for_write.get("item") or [])})
            print("✅ Generated collection from OpenAPI locally (no import performed).")
        except Exception as e:
            _write_log("local_conversion", "failed", {"error": str(e)})
            raise RuntimeError(f"Failed to generate collection locally when import skipped: {e}")
    else:
        coll_for_write = collection
        # If an imported collection exists but lacks items, generate items locally
        if not isinstance(collection, dict) or not (collection.get("item") or collection.get("items")):
            print("⚠️ Imported collection contains no requests; generating items locally from OpenAPI spec")
            _write_log("local_conversion", "starting", {"reason": "import_missing_items"})
            try:
                coll_for_write = openapi_to_collection(spec_content, spec_name)
                _write_log("local_conversion", "success", {"generated_items": len(coll_for_write.get("item") or [])})
            except Exception as e:
                _write_log("local_conversion", "failed", {"error": str(e)})
                print("Failed to convert OpenAPI to collection locally:", e)

    # Validate the generated/selected collection structure before proceeding.
    if not coll_for_write or not isinstance(coll_for_write, dict):
        raise RuntimeError("Collection generation failed: collection is empty or not a dict. Aborting to avoid corrupting Postman state.")
    if not (coll_for_write.get("item") or coll_for_write.get("items")) or not coll_for_write.get("info"):
        raise RuntimeError("Generated collection missing required fields ('info' or 'item'). Ensure OpenAPI spec contains operations or allow Import API to run.")

    print("🔹 Injecting JWT pre-request script")
    jwt_code = JWT_SCRIPT.read_text().splitlines()
    # Defensive: ensure coll_for_write is a dict before mutating it
    if not isinstance(coll_for_write, dict):
        raise RuntimeError("Internal error: collection to write is not a dict; aborting to avoid corrupting Postman state.")
    coll_for_write.setdefault("event", []).append({
        "listen": "prerequest",
        "script": {
            "type": "text/javascript",
            "exec": jwt_code
        }
    })

    # Inject linked collection UIDs from env var POSTMAN_LINKED_COLLECTION_UIDS (CI-safe)
    linked_env = os.getenv("POSTMAN_LINKED_COLLECTION_UIDS", "").strip()
    if linked_env:
        uids = [u.strip() for u in linked_env.split(",") if u.strip()]
        if uids:
            coll_for_write["linked_collections"] = uids
            _write_log("linked_collections_injected", "success", {"count": len(uids)})

    # Upsert the collection to Postman (use existing UID if provided)
    collection_path = OUT / "refund.collection.json"
    # Write the converted or imported collection (prefer collection object wrapped)
    collection_path.write_text(json.dumps({"collection": coll_for_write}, indent=2))
    print(f"✅ Collection written to {collection_path}")
    _write_log("write_collection_file", "success", {"path": str(collection_path)})

    # Prefer an explicit env override (resolved `target_uid`), otherwise try to reuse
    # any UID from previous state or the import/generation step so we update the
    # same collection instead of creating a duplicate.
    def _extract_uid(coll_obj):
        if not coll_obj or not isinstance(coll_obj, dict):
            return None
        return (
            coll_obj.get("uid")
            or (coll_obj.get("collection") or {}).get("uid")
            or coll_obj.get("id")
            or (coll_obj.get("collection") or {}).get("id")
        )

    returned_uid = _extract_uid(collection)
    state_uid = prev_state.get("collection_uid")
    collection_uid = None
    uid_source = collection_uid_source or None

    if target_uid:
        collection_uid = target_uid
        uid_source = uid_source or "env_secret_resolved_uid"
        print("Using resolved collection UID from env/secret (not printing value)")
        _write_log("collection_uid_source", "env_secret_resolved_uid", {"note": "value omitted"})
    elif state_uid:
        collection_uid = state_uid
        uid_source = uid_source or "state.json"
        print("Using collection UID from state file (generated/state.json)")
        _write_log("collection_uid_source", "state", {"note": "value omitted"})
    elif returned_uid:
        collection_uid = returned_uid
        uid_source = uid_source or "import_returned"
        print("Using collection UID returned by import/spec hub (best-effort)")
        _write_log("collection_uid_source", "import_returned", {"note": "value omitted"})
    else:
        collection_uid = None
        uid_source = uid_source or "none"
        print("No collection UID found; will create a new collection")
        _write_log("collection_uid_source", "none", {"note": "no uid available; will create new collection"})

    # If the user provided POSTMAN_COLLECTION_UID it must have been resolved above
    # and collection_uid will be set to the resolved value. At this point we
    # should not attempt to create a new collection when POSTMAN_COLLECTION_UID was set.

    # Determine whether to perform a PATCH-style partial update
    use_patch = os.getenv("POSTMAN_USE_PATCH", "false").lower() in ("1", "true", "yes")
    do_sync_linked = os.getenv("SYNC_LINKED_COLLECTIONS", "false").lower() in ("1", "true", "yes")
    print("🔹 Upserting collection to Postman")

    # Track patch/put decisions for workflow summary
    patch_attempted = False
    patch_succeeded = False
    put_performed = False
    patch_reason = None

    if use_patch and collection_uid:
        patch_attempted = True
        try:
            from postman_api import patch_collection_metadata_only
            # Attempt a metadata-only PATCH (never sends `item`). Returns UID on success.
            coll_result = patch_collection_metadata_only(api_key, collection_uid, coll_for_write)
            patch_succeeded = True
            print("✅ PATCH (metadata-only) succeeded")
            _write_log("patch_collection", "success", {"uid": collection_uid})
        except Exception as e:
            patch_succeeded = False
            print("⚠️ PATCH failed, will consider PUT upsert:", e)
            _write_log("patch_collection", "failed", {"error": str(e)})

        # linked collection sync will occur once after the PATCH/PUT decision below

        # Compute item structure fingerprint and decide whether to PUT (structure change)
        import json as _j
        items = coll_for_write.get("item") or coll_for_write.get("items") or []
        try:
            item_hash = hashlib.sha256(_j.dumps(items, sort_keys=True).encode("utf-8")).hexdigest()
        except Exception:
            item_hash = None

        prev_item_hash = prev_state.get("item_hash") or prev_state.get("item_sha256")

        if not patch_succeeded:
            # If PATCH failed completely, perform a PUT upsert to ensure collection state
            print("Item structure change unknown because PATCH failed; performing PUT upsert")
            try:
                coll_result = upsert_collection(api_key, workspace_id, coll_for_write, collection_uid)
            except RuntimeError as e:
                if str(e).startswith("FATAL_UID_NOT_FOUND"):
                    _write_log("fatal_uid_not_found", "failed", {"error": str(e)})
                    print("FATAL: provided POSTMAN_COLLECTION_UID not found or inaccessible. Aborting to avoid creating a new collection.")
                    sys.exit(1)
                raise
            put_performed = True
            patch_reason = "patch_failed"
        else:
            if item_hash and prev_item_hash != item_hash:
                print("Item structure changed, performing PUT upsert")
                _write_log("item_hash_check", "changed", {"prev": prev_item_hash, "now": item_hash})
                try:
                    coll_result = upsert_collection(api_key, workspace_id, coll_for_write, collection_uid)
                except RuntimeError as e:
                    if str(e).startswith("FATAL_UID_NOT_FOUND"):
                        _write_log("fatal_uid_not_found", "failed", {"error": str(e)})
                        print("FATAL: provided POSTMAN_COLLECTION_UID not found or inaccessible. Aborting to avoid creating a new collection.")
                        sys.exit(1)
                    raise
                put_performed = True
                patch_reason = "structure_changed"
            else:
                print("PATCH-only update applied; structure unchanged")
                _write_log("item_hash_check", "unchanged", {"item_hash": item_hash})
                coll_result = collection_uid
                put_performed = False
                patch_reason = "structure_unchanged"

    else:
        # No PATCH requested or no existing UID — full upsert
        try:
            coll_result = upsert_collection(api_key, workspace_id, coll_for_write, collection_uid)
        except RuntimeError as e:
            if str(e).startswith("FATAL_UID_NOT_FOUND"):
                _write_log("fatal_uid_not_found", "failed", {"error": str(e)})
                print("FATAL: provided POSTMAN_COLLECTION_UID not found or inaccessible. Aborting to avoid creating a new collection.")
                sys.exit(1)
            raise
        if use_patch and not collection_uid:
            patch_attempted = False
            patch_succeeded = False
            patch_reason = "no_existing_uid"
    # After we've applied PATCH or PUT (as needed), optionally sync linked collections
    # but only when PATCH flow was used and the sync option is enabled. This
    # ensures linked collections are synced exactly once and only as part of
    # the PATCH/PUT decision path.
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

    # If we imported a collection earlier but we had a target_uid that we used instead,
    # attempt to delete the imported collection to avoid duplicates (best-effort).
    try:
        if imported_uid and collection_uid and imported_uid != collection_uid:
            try:
                delete_collection(api_key, imported_uid)
                _write_log("delete_imported_collection", "success", {"imported_uid": imported_uid})
            except Exception as e:
                _write_log("delete_imported_collection", "failed", {"imported_uid": imported_uid, "error": str(e)})
    except Exception:
        # non-fatal cleanup errors
        pass

    # Record PATCH/PUT summary if we attempted a patch
    try:
        if patch_attempted:
            summary = {
                "patch_attempted": bool(patch_attempted),
                "patch_succeeded": bool(patch_succeeded),
                "put_performed": bool(put_performed),
                "patch_reason": patch_reason,
                "collection_uid": collection_uid_result,
            }
            _write_log("patch_summary", "info", summary)
            print(f"🔹 PATCH summary: attempted={patch_attempted} succeeded={patch_succeeded} put_performed={put_performed} reason={patch_reason}")
    except NameError:
        # Older runs may not have patch flags; ignore
        pass

    # (linked collections sync removed here to ensure it only runs as part of the
    # PATCH/PUT decision path above when requested)

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
            "collection_uid_source": uid_source,
            "environments": postman_ids.get("environments", {}),
        }
        # include spec_id if available from spec hub flow
        try:
            if 'spec_id' in locals() and spec_id:
                state_obj["spec_id"] = spec_id
        except Exception:
            pass

        # include item_hash if computed during a PATCH decision
        try:
            if 'item_hash' in locals() and item_hash:
                state_obj["item_hash"] = item_hash
        except Exception:
            pass

        state_file.write_text(json.dumps(state_obj, indent=2))
        _write_log("state_write", "success", {"path": str(state_file)})
    except Exception as e:
        _write_log("state_write", "failed", {"error": str(e)})

    print("\n🎉 Ingestion complete. Postman is now an accelerator, not a checkbox.")

if __name__ == "__main__":
    main()
