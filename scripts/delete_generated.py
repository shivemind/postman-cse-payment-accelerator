#!/usr/bin/env python3
"""
Delete generated Postman collection and (optionally) environments using saved UIDs in `generated/postman_ids.json`.

Usage:
  python scripts/delete_generated.py    # reads generated/postman_ids.json and deletes the collection

Requires `POSTMAN_API_KEY` env var set.
"""
import os
import json
from pathlib import Path
from dotenv import load_dotenv
from postman_api import delete_collection, delete_environment

load_dotenv()
ROOT = Path(__file__).resolve().parents[1]
IDS_PATH = ROOT / "generated" / "postman_ids.json"


def main():
    api_key = os.getenv("POSTMAN_API_KEY")
    if not api_key:
        raise RuntimeError("Missing POSTMAN_API_KEY environment variable")

    # Prepare log file
    LOG_PATH = ROOT / "generated" / "postman_delete.log"
    log_entries = []

    def write_log():
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as lf:
                for e in log_entries:
                    lf.write(json.dumps(e, ensure_ascii=False) + "\n")
        except Exception as ex:
            print("Failed to write log:", ex)

    # 1) Attempt to find collection UID in generated/refund.collection.json
    coll_file = ROOT / "generated" / "refund.collection.json"
    collection_uid = None
    if coll_file.exists():
        try:
            coll_obj = json.loads(coll_file.read_text())
            # support payload with top-level 'collection' wrapper or direct 'collection' object
            coll = coll_obj.get("collection") if isinstance(coll_obj, dict) and "collection" in coll_obj else coll_obj.get("collection") if isinstance(coll_obj, dict) else coll_obj
            if isinstance(coll, dict):
                collection_uid = coll.get("uid") or coll.get("id")
        except Exception as e:
            log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "action": "read_collection", "file": str(coll_file), "status": "error", "message": str(e)})

    # If we didn't find a UID in the generated collection file, try the persisted ids file
    if not collection_uid and IDS_PATH.exists():
        try:
            ids = json.loads(IDS_PATH.read_text())
            collection_uid = ids.get("collection_uid")
        except Exception:
            pass

    # If still not found, fallback to reading the audit log for last successful upsert_collection
    if not collection_uid:
        actions_log = ROOT / "generated" / "postman_actions.log"
        if actions_log.exists():
            try:
                with open(actions_log, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            obj = json.loads(line)
                            if obj.get("action") == "upsert_collection" and obj.get("status") == "success":
                                details = obj.get("details") or {}
                                uid = details.get("uid")
                                if uid:
                                    collection_uid = uid
                        except Exception:
                            continue
            except Exception as e:
                log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "action": "read_actions_log", "file": str(actions_log), "status": "error", "message": str(e)})

    if collection_uid:
        print(f"Deleting collection: {collection_uid}")
        try:
            delete_collection(api_key, collection_uid)
            msg = "deleted"
            print("✅ Collection deleted")
            log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "resource": "collection", "uid": collection_uid, "status": "deleted"})
        except Exception as e:
            msg = str(e)
            print("Failed to delete collection:", e)
            log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "resource": "collection", "uid": collection_uid, "status": "error", "message": msg})
    else:
        print("No collection file/uid found to delete.")
        log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "resource": "collection", "uid": None, "status": "skipped", "message": "no uid found"})

    # 2) Find environment UIDs in generated/environments/*.environment.json and delete them
    env_dir = ROOT / "generated" / "environments"
    if env_dir.exists():
        for env_file in env_dir.glob("*.environment.json"):
            try:
                obj = json.loads(env_file.read_text())
                env_uid = obj.get("uid") or (obj.get("payload") or {}).get("uid")
                name = (obj.get("payload") or {}).get("name") or env_file.stem
                if env_uid:
                    print(f"Deleting environment {name}: {env_uid}")
                    try:
                        delete_environment(api_key, env_uid)
                        print(f"✅ Environment deleted: {name}")
                        log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "resource": "environment", "name": name, "uid": env_uid, "status": "deleted"})
                    except Exception as e:
                        print(f"Failed to delete environment {name}:", e)
                        log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "resource": "environment", "name": name, "uid": env_uid, "status": "error", "message": str(e)})
                else:
                    print(f"No uid found in environment file: {env_file}")
                    log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "resource": "environment", "file": str(env_file), "status": "skipped", "message": "no uid"})
            except Exception as e:
                print(f"Failed to read environment file {env_file}:", e)
                log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "resource": "environment", "file": str(env_file), "status": "error", "message": str(e)})
    else:
        print("No generated/environments directory found")
        log_entries.append({"ts": __import__("datetime").datetime.utcnow().isoformat(), "resource": "environments", "status": "skipped", "message": "no directory"})

    # Persist log entries
    write_log()
    print(f"Wrote deletion log to {LOG_PATH}")

    # Remove postman_ids.json if present
    if IDS_PATH.exists():
        try:
            IDS_PATH.unlink()
            print(f"Removed local ids file: {IDS_PATH}")
        except Exception as e:
            print("Could not remove ids file:", e)


if __name__ == '__main__':
    main()
