#!/usr/bin/env python3
"""CI-safe diagnostic for Postman API access.

Prints workspace status and collection list for a given POSTMAN_API_KEY and
POSTMAN_WORKSPACE_ID. Attempts to resolve POSTMAN_COLLECTION_UID when provided.

Does NOT print POSTMAN_API_KEY. Exits non-zero if any API call returns non-200.
"""
import os
import sys
import requests
import json
from postman_api import resolve_collection_uid, list_collections

BASE_URL = "https://api.getpostman.com"


def truncated(text, limit=500):
    if not text:
        return ""
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def main():
    api_key = os.getenv("POSTMAN_API_KEY")
    workspace_id = os.getenv("POSTMAN_WORKSPACE_ID")
    if not api_key or not workspace_id:
        print("FATAL: POSTMAN_API_KEY and POSTMAN_WORKSPACE_ID must be set for diagnostics.")
        return 2

    headers = {"X-Api-Key": api_key}

    # Check workspace
    ws_url = f"{BASE_URL}/workspaces/{workspace_id}"
    try:
        r = requests.get(ws_url, headers=headers, timeout=15)
    except Exception as e:
        print(f"FATAL: workspace request failed: {e}")
        return 3
    if r.status_code != 200:
        print(f"FATAL: workspace request returned {r.status_code}")
        print(truncated(r.text))
        return 4
    try:
        ws = r.json().get("workspace") or r.json()
    except Exception:
        print("FATAL: failed to parse workspace response JSON")
        return 5
    print(f"Workspace status: {r.status_code}")
    print(f"Workspace name: {ws.get('name')}")

    # List collections
    try:
        cols = list_collections(api_key, workspace_id)
    except Exception as e:
        print(f"FATAL: list_collections call failed: {e}")
        return 6
    print(f"Collection count: {len(cols)}")
    for entry in cols:
        coll = entry.get("collection") if isinstance(entry, dict) else entry
        uid = (coll or {}).get("uid") or (coll or {}).get("id") or entry.get("uid") or entry.get("id")
        name = (coll or {}).get("info", {}).get("name") or (coll or {}).get("name")
        print(f"- {uid}: {name}")

    provided = os.getenv("POSTMAN_COLLECTION_UID", "").strip()
    if provided:
        print("Checking provided POSTMAN_COLLECTION_UID...")
        try:
            resolved, reason = resolve_collection_uid(api_key, workspace_id, provided)
        except Exception as e:
            print(f"Resolution error: {e}")
            return 7
        if resolved:
            print(f"UID FOUND: resolved to {resolved} (reason={reason})")
        else:
            print("UID NOT FOUND: the provided POSTMAN_COLLECTION_UID could not be resolved in this workspace")
            return 8

    print("Diagnostics completed successfully.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
