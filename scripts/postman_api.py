import requests
import re
import time

BASE_URL = "https://api.getpostman.com"


def headers(api_key: str):
    # Specs (API Builder) endpoints often require a versioned Accept header.
    # This is safe to include for all requests.
    return {
        "X-Api-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/vnd.api.v10+json",
    }


def sanitize_collection_for_patch(collection: dict) -> dict:
    """Return a deep-copied collection suitable for PATCH: strip info.schema if present.

    This ensures we don't mutate the original collection object which may be
    reused for PUT or for writing to disk.
    """
    import copy as _copy

    if not collection or not isinstance(collection, dict):
        return collection

    sanitized = _copy.deepcopy(collection)

    try:
        info = None
        if "collection" in sanitized and isinstance(sanitized["collection"], dict):
            info = sanitized["collection"].get("info")
        elif isinstance(sanitized, dict):
            info = sanitized.get("info")

        if isinstance(info, dict) and "schema" in info:
            del info["schema"]
            print("DEBUG: stripped collection.info.schema for PATCH")
    except Exception:
        # Defensive: if sanitization fails, return the deepcopy unchanged
        pass

    return sanitized


def _infer_spec_type(raw_spec: str) -> str:
    """Infer Postman Spec Hub 'type' from OpenAPI version.

    Postman expects type values like: OPENAPI:3.0, OPENAPI:3.1, OPENAPI:2.0
    """
    try:
        import yaml
        spec = yaml.safe_load(raw_spec) or {}
        v = str(spec.get("openapi") or spec.get("swagger") or "")
    except Exception:
        v = ""

    if v.startswith("3.1"):
        return "OPENAPI:3.1"
    if v.startswith("3.0"):
        return "OPENAPI:3.0"
    if v.startswith("2.0") or v.startswith("2.") or v == "2":
        return "OPENAPI:2.0"
    # Default to 3.0 if unknown
    return "OPENAPI:3.0"


def create_spec(api_key: str, workspace_id: str, name: str, raw_spec: str, version: str | None = None):
    """Create a Spec Hub spec via POST /specs?workspaceId=...

    Postman expects a payload shaped like:
      {
        "name": "...",
        "type": "OPENAPI:3.0",
        "files": [{"path": "index.yaml", "content": "..."}]
      }

    NOTE: "version" is not consistently accepted across all accounts/tenants for create_spec.
    Keep it out unless you confirm your tenant supports it.
    """
    spec_type = _infer_spec_type(raw_spec)

    payload = {
        "name": name,
        "type": spec_type,
        "files": [
            {
                "path": "index.yaml",
                "content": raw_spec
            }
        ]
    }

    r = requests.post(
        f"{BASE_URL}/specs?workspaceId={workspace_id}",
        headers=headers(api_key),
        json=payload,
        timeout=30,
    )

    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman create_spec failed: {r.status_code} - {r.text}")

    data = r.json()

    # Flexible parsing
    if isinstance(data, dict):
        if isinstance(data.get("spec"), dict):
            spec = data["spec"]
            spec_id = spec.get("id") or spec.get("uid")
            if spec_id:
                return spec_id
        if "id" in data:
            return data["id"]
        if "uid" in data:
            return data["uid"]

    raise RuntimeError(f"Postman create_spec did not return an id/uid: {data}")


def generate_collection(api_key: str, spec_id: str, name: str | None = None):
    url = f"{BASE_URL}/specs/{spec_id}/generations/collection"

    # Different tenants/versions accept different enum casings/values.
    # Try the most common openapi-to-postman option combinations first.
    option_variants = [
        {"requestParametersResolution": "schema",  "exampleParametersResolution": "schema"},
        {"requestParametersResolution": "example", "exampleParametersResolution": "example"},
        {"requestParametersResolution": "schema",  "exampleParametersResolution": "example"},
        {"requestParametersResolution": "example", "exampleParametersResolution": "schema"},
    ]

    last_err = None
    for opts in option_variants:
        payload = {
            "name": name or "Generated Collection",
            "options": opts
        }

        r = requests.post(url, headers=headers(api_key), json=payload, timeout=30)

        if r.status_code < 400:
            data = r.json()
            if isinstance(data, dict) and isinstance(data.get("collection"), dict):
                return data["collection"]
            return data

        last_err = (r.status_code, r.text, payload)

    status, text, payload = last_err
    raise RuntimeError(
        f"Postman generate_collection failed for all option variants. "
        f"Last status={status} body={text} payload={payload}"
    )


def import_openapi(api_key, workspace_id, name, raw_spec):
    """
    Use the Postman Import API to convert an OpenAPI/YAML string into a Postman collection.
    Returns the generated collection object.
    """
    url = f"{BASE_URL}/import/openapi?workspace={workspace_id}"

    tried = []
    for t in ("openapi", "openapi3", "yaml", "string"):
        payload = {"type": t, "input": raw_spec, "name": name}
        tried.append(t)
        r = requests.post(url, headers=headers(api_key), json=payload, timeout=90)
        if 400 <= r.status_code < 500:
            continue
        r.raise_for_status()

        data = r.json()
        collections = data.get("collections") or []
        if not collections:
            coll = data.get("collection") or data
            if isinstance(coll, dict) and (coll.get("item") or coll.get("items")):
                return coll
            continue

        first = collections[0]
        coll = first.get("collection") or first
        if isinstance(coll, dict) and (coll.get("item") or coll.get("items")):
            return coll

    if 'data' in locals():
        collections = data.get("collections") or []
        if collections:
            coll = collections[0].get("collection") or collections[0]
            return coll
        coll = data.get("collection") or data
        return coll

    raise RuntimeError(f"Import failed for all tried types: {tried}")


def upsert_collection(api_key: str, workspace_id: str, coll_payload: dict, collection_uid: str | None = None):
    """Create or update a collection. If `collection_uid` is provided, PUT; else POST."""
    headers_ = headers(api_key)

    if collection_uid:
        url = f"{BASE_URL}/collections/{collection_uid}"
        body = coll_payload if isinstance(coll_payload, dict) and "collection" in coll_payload else {"collection": coll_payload}
        print(f"DEBUG: upsert_collection PUT body keys: {list(body.keys())}")
        if "collection" in body and isinstance(body["collection"], dict):
            coll = body["collection"]
            print(f"DEBUG: collection keys: {list(coll.keys())}")
            if "info" not in coll:
                coll["info"] = {"name": coll.get("name") or coll.get("id"), "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}
            if "item" not in coll:
                coll["item"] = coll.get("items") or []
        resp = requests.put(url, headers=headers_, json=body, timeout=30)
    else:
        url = f"{BASE_URL}/collections?workspace={workspace_id}"
        body = coll_payload if isinstance(coll_payload, dict) and "collection" in coll_payload else {"collection": coll_payload}
        print(f"DEBUG: upsert_collection POST body keys: {list(body.keys())}")
        if "collection" in body and isinstance(body["collection"], dict):
            coll = body["collection"]
            print(f"DEBUG: collection keys: {list(coll.keys())}")
            if "info" not in coll:
                coll["info"] = {"name": coll.get("name") or coll.get("id"), "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}
            if "item" not in coll:
                coll["item"] = coll.get("items") or []
        resp = requests.post(url, headers=headers_, json=body, timeout=30)

    if resp.status_code == 404 and collection_uid:
        raise RuntimeError(f"FATAL_UID_NOT_FOUND: collection_uid provided but not found or not accessible: {collection_uid}")

    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman upsert_collection failed: {resp.status_code} - {resp.text}")

    data = resp.json()
    uid = data.get("collection", {}).get("uid") or data.get("collection", {}).get("id") or data.get("uid")
    if uid:
        return str(uid)
    return data


def patch_collection(api_key: str, collection_uid: str, partial_body: dict):
    """Apply a PATCH-style partial update to a collection."""
    url = f"{BASE_URL}/collections/{collection_uid}"
    headers_ = headers(api_key)

    # Accept either {'collection': {...}} or {...}
    if isinstance(partial_body, dict) and "collection" in partial_body:
        coll = partial_body.get("collection")
    elif isinstance(partial_body, dict):
        coll = partial_body
    else:
        raise RuntimeError("patch_collection expects a dict or {'collection': {...}} payload")

    if not isinstance(coll, dict):
        raise RuntimeError("patch_collection payload did not contain a dict collection")

    # IMPORTANT: Actually use the sanitized copy
    coll = sanitize_collection_for_patch(coll)

    def make_payload(include_event=True, include_variable=True):
        payload_coll = {}
        if coll.get("info"):
            info = coll.get("info")
            payload_coll["info"] = {k: v for k, v in info.items() if k in ("name", "description", "schema")}
        if include_event and coll.get("event"):
            payload_coll["event"] = coll.get("event")
        if include_variable and coll.get("variable"):
            payload_coll["variable"] = coll.get("variable")
        return {"collection": payload_coll}

    attempts = [(True, True), (False, True), (False, False)]
    last_exc = None

    for include_event, include_variable in attempts:
        payload = make_payload(include_event=include_event, include_variable=include_variable)
        try:
            resp = requests.request("PATCH", url, headers=headers_, json=payload, timeout=30)
            if resp.status_code >= 400:
                last_exc = RuntimeError(f"Postman patch_collection failed: {resp.status_code} - {resp.text}")
                continue
            data = resp.json()
            return data.get("collection", {}).get("uid") or data.get("collection", {}).get("id") or data.get("uid") or data
        except requests.exceptions.RequestException as e:
            last_exc = e
            continue

    if last_exc:
        raise last_exc
    raise RuntimeError("Postman patch_collection failed: unknown error")


def patch_collection_metadata_only(api_key: str, collection_uid: str, collection: dict):
    """Attempt a metadata-only PATCH that never includes `item`."""
    return patch_collection(api_key, collection_uid, {"collection": collection})


def get_collection(api_key: str, collection_uid: str):
    url = f"{BASE_URL}/collections/{collection_uid}"
    resp = requests.get(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman get_collection failed: {resp.status_code} - {resp.text}")
    data = resp.json()
    return data.get("collection") or data


def list_environments(api_key: str, workspace_id: str):
    url = f"{BASE_URL}/environments?workspace={workspace_id}"
    resp = requests.get(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman list_environments failed: {resp.status_code} - {resp.text}")
    data = resp.json()
    return data.get("environments") or []


def get_environment_by_name(api_key: str, workspace_id: str, name: str):
    if not name:
        return None
    envs = list_environments(api_key, workspace_id)
    for e in envs:
        if e.get("name") == name:
            return e.get("uid") or e.get("id")
    return None


def list_collections(api_key: str, workspace_id: str):
    url = f"{BASE_URL}/collections?workspace={workspace_id}"
    resp = requests.get(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman list_collections failed: {resp.status_code} - {resp.text}")
    data = resp.json()
    return data.get("collections") or []


def resolve_collection_uid(api_key: str, workspace_id: str, provided: str | None):
    if not provided:
        return None, None
    provided = provided.strip()

    def _extract_uid_from_entry(entry):
        coll = entry.get("collection") if isinstance(entry, dict) else entry
        if not coll:
            return None
        return coll.get("uid") or coll.get("id") or entry.get("uid") or entry.get("id")

    if re.match(r"^\d+-[0-9a-fA-F\-]{36}$", provided):
        try:
            if collection_exists(api_key, provided):
                return provided, "verified_existing"
        except Exception:
            pass
        try:
            suffix = provided.split("-", 1)[1]
            cols = list_collections(api_key, workspace_id)
            for entry in cols:
                uid = _extract_uid_from_entry(entry)
                if uid and uid.lower().endswith(suffix.lower()):
                    return uid, "recovered_by_suffix"
        except Exception:
            pass
        return None, "not_found"

    if re.match(r"^[0-9a-fA-F\-]{36}$", provided):
        try:
            cols = list_collections(api_key, workspace_id)
            for entry in cols:
                uid = _extract_uid_from_entry(entry)
                if not uid:
                    continue
                if uid.lower() == provided.lower():
                    return uid, "resolved_exact"
                if uid.lower().endswith(provided.lower()):
                    return uid, "resolved_suffix"
        except Exception:
            pass
        return None, "not_found"

    return None, "invalid_format"


def collection_exists(api_key: str, collection_uid: str) -> bool:
    if not collection_uid:
        return False
    url = f"{BASE_URL}/collections/{collection_uid}"
    resp = requests.get(url, headers=headers(api_key), timeout=30)
    if resp.status_code == 404:
        return False
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman collection_exists failed: {resp.status_code} - {resp.text}")
    return True


def get_collection_by_name(api_key: str, workspace_id: str, name: str):
    if not name:
        return None
    cols = list_collections(api_key, workspace_id)
    for c in cols:
        coll = c.get("collection") or c
        if coll.get("info", {}).get("name") == name or coll.get("name") == name:
            return coll.get("uid") or coll.get("id")
    return None


def sync_linked_collections(api_key: str, workspace_id: str, collection: dict):
    if not collection or not isinstance(collection, dict):
        return []

    coll = collection.get("collection") if "collection" in collection else collection
    linked = coll.get("linked_collections") or coll.get("linkedCollections")
    results = []
    if not linked:
        return results

    for entry in linked:
        try:
            if isinstance(entry, str):
                uid = entry
                remote = get_collection(api_key, uid)
                res = upsert_collection(api_key, workspace_id, remote, uid)
                results.append({"uid": uid, "result": res})
            elif isinstance(entry, dict):
                uid = entry.get("uid")
                payload = entry.get("collection") or entry.get("payload") or entry
                res = upsert_collection(api_key, workspace_id, payload, uid)
                results.append({"uid": uid, "result": res})
        except Exception as e:
            results.append({"error": str(e), "entry": entry})

    return results


def openapi_to_collection(raw_spec: str, name: str):
    import yaml
    try:
        spec = yaml.safe_load(raw_spec)
    except Exception:
        return {"info": {"name": name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": []}

    base = "{{base_url}}"
    collection = {"info": {"name": name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": []}

    paths = spec.get("paths") or {}
    for path, methods in paths.items():
        for method, op in (methods.items() if isinstance(methods, dict) else []):
            try:
                op_obj = op or {}
                op_name = op_obj.get("summary") or op_obj.get("operationId") or f"{method.upper()} {path}"
                raw_url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"

                body = None
                rb = op_obj.get("requestBody") or {}
                content = rb.get("content") or {}
                if content:
                    app_json = content.get("application/json") or {}
                    examples = app_json.get("examples") or {}
                    schema = app_json.get("schema") or {}
                    example_value = None
                    if examples:
                        first = list(examples.values())[0]
                        example_value = first.get("value")
                    elif schema and isinstance(schema, dict):
                        example_value = None

                    if example_value is not None:
                        import json as _json
                        body = {"mode": "raw", "raw": _json.dumps(example_value, indent=2), "options": {"raw": {"language": "json"}}}

                url_obj = {"raw": raw_url, "host": [base]}
                p = path.lstrip("/")
                url_obj["path"] = p.split("/") if p else []

                request = {
                    "name": op_name,
                    "request": {
                        "method": method.upper(),
                        "header": [],
                        "body": body or {},
                        "url": url_obj
                    }
                }

                collection["item"].append(request)
            except Exception:
                continue

    return collection


def upsert_environment(api_key: str, workspace_id: str, env_payload: dict, env_uid: str | None = None):
    headers_ = headers(api_key)

    if not env_uid:
        try:
            existing = get_environment_by_name(api_key, workspace_id, env_payload.get("name"))
            if existing:
                env_uid = existing
        except Exception:
            env_uid = None

    if env_uid:
        url = f"{BASE_URL}/environments/{env_uid}"
        resp = requests.put(url, headers=headers_, json={"environment": env_payload}, timeout=30)
    else:
        url = f"{BASE_URL}/environments?workspace={workspace_id}"
        resp = requests.post(url, headers=headers_, json={"environment": env_payload}, timeout=30)

    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman upsert_environment failed: {resp.status_code} - {resp.text}")

    data = resp.json()
    return data.get("environment", {}).get("uid") or data.get("environment", {}).get("id") or data


def delete_collection(api_key: str, collection_uid: str):
    url = f"{BASE_URL}/collections/{collection_uid}"
    resp = requests.delete(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman delete_collection failed: {resp.status_code} - {resp.text}")
    return True


def delete_environment(api_key: str, environment_uid: str):
    url = f"{BASE_URL}/environments/{environment_uid}"
    resp = requests.delete(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman delete_environment failed: {resp.status_code} - {resp.text}")
    return True


def create_environment(api_key, workspace_id, name, values):
    payload = {"environment": {"name": name, "values": values}}
    r = requests.post(
        f"{BASE_URL}/environments?workspace={workspace_id}",
        headers=headers(api_key),
        json=payload,
        timeout=30
    )
    r.raise_for_status()
    return r.json()


def create_empty_collection(api_key: str, workspace_id: str, name: str) -> str:
    payload = {
        "collection": {
            "info": {
                "name": name,
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": []
        }
    }
    url = f"{BASE_URL}/collections?workspace={workspace_id}"
    resp = requests.post(url, headers=headers(api_key), json=payload, timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman create_empty_collection failed: {resp.status_code} - {resp.text}")

    data = resp.json()
    uid = data.get("collection", {}).get("uid") or data.get("collection", {}).get("id") or data.get("uid")
    if not uid:
        raise RuntimeError(f"Postman create_empty_collection did not return a uid: {data}")
    return str(uid)
