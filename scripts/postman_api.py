import requests
import re

BASE_URL = "https://api.getpostman.com"

def headers(api_key: str):
    return {
        "X-Api-Key": api_key,
        "Content-Type": "application/json"
    }

def create_spec(api_key, workspace_id, name, raw_spec, version):
    # Try a few payload shapes and contentType values to find what the API accepts.
    content_types = ("yaml", "openapi", "application/yaml")
    payload_shapes = []

    # Shape A: nested under `spec` (original)
    def shape_a(ct):
        return {"spec": {"name": name, "content": raw_spec, "contentType": ct, "version": version}}

    # Shape B: top-level fields
    def shape_b(ct):
        return {"name": name, "content": raw_spec, "contentType": ct, "version": version}

    # Shape C: top-level `spec` is raw content, with metadata at top-level
    def shape_c(ct):
        return {"spec": raw_spec, "name": name, "contentType": ct, "version": version}

    payload_shapes = (shape_a, shape_b, shape_c)

    attempts = []
    last_response = None
    for shape_fn in payload_shapes:
        for ct in content_types:
            payload = shape_fn(ct)
            attempts.append({"shape": shape_fn.__name__, "contentType": ct})
            r = requests.post(
                f"{BASE_URL}/specs?workspaceId={workspace_id}",
                headers=headers(api_key),
                json=payload,
                timeout=30,
            )

            if r.status_code == 201:
                return r.json()["spec"]["id"]

            last_response = r
            if r.status_code != 400:
                raise RuntimeError(f"Postman create_spec failed (attempts={attempts}): {r.status_code} - {r.text}")

    # If we get here all attempts returned 400. Surface the last response and payload attempts.
    raise RuntimeError(f"Postman create_spec malformed request (attempts={attempts}): {last_response.status_code} - {last_response.text}")

def generate_collection(api_key, spec_id):
    payload = {
        "options": {
            "requestParametersResolution": "example",
            "exampleParametersResolution": "example"
        }
    }

    r = requests.post(
        f"{BASE_URL}/specs/{spec_id}/generations/collection",
        headers=headers(api_key),
        json=payload,
        timeout=30
    )
    r.raise_for_status()
    return r.json()["collection"]


def import_openapi(api_key, workspace_id, name, raw_spec):
    """
    Use the Postman Import API to convert an OpenAPI/YAML string into a Postman collection.
    Returns the generated collection object.
    """
    url = f"{BASE_URL}/import/openapi?workspace={workspace_id}"

    # Try several `type` values; some Postman import backends accept different markers
    # for OpenAPI/YAML content. Prefer payloads that produce a collection with `item`.
    tried = []
    for t in ("openapi", "openapi3", "yaml", "string"):
        payload = {"type": t, "input": raw_spec, "name": name}
        tried.append(t)
        r = requests.post(url, headers=headers(api_key), json=payload, timeout=90)
        if r.status_code >= 400 and r.status_code < 500:
            # try next type
            continue
        r.raise_for_status()
        data = r.json()
        collections = data.get("collections") or []
        if not collections:
            # some responses may include `collection` at top-level
            coll = data.get("collection") or data
            # If the returned object contains items, return it
            if isinstance(coll, dict) and (coll.get("item") or coll.get("items")):
                return coll
            # otherwise continue trying other types
            continue

        # Extract the first collection object
        first = collections[0]
        coll = first.get("collection") or first
        # If collection contains requests/items, return immediately
        if isinstance(coll, dict) and (coll.get("item") or coll.get("items")):
            return coll
        # Otherwise keep iterating to try another payload type

    # If we get here we didn't find a collection with `item` in any attempt; return
    # the last successful payload's collection (if any) or raise.
    if 'data' in locals():
        collections = data.get("collections") or []
        if collections:
            coll = collections[0].get("collection") or collections[0]
            return coll
        coll = data.get("collection") or data
        return coll

    raise RuntimeError(f"Import failed for all tried types: {tried}")


def upsert_collection(api_key: str, workspace_id: str, coll_payload: dict, collection_uid: str | None = None):
    """Create or update a collection. If `collection_uid` is provided, performs a PUT to update, otherwise POST to create."""
    headers_ = headers(api_key)
    # If caller already passed a top-level 'collection' wrapper, use it directly to avoid double-wrapping.
    if collection_uid:
        url = f"{BASE_URL}/collections/{collection_uid}"
        body = coll_payload if isinstance(coll_payload, dict) and "collection" in coll_payload else {"collection": coll_payload}
        print(f"DEBUG: upsert_collection PUT body keys: {list(body.keys())}")
        if "collection" in body and isinstance(body["collection"], dict):
            coll = body["collection"]
            print(f"DEBUG: collection keys: {list(coll.keys())}")
            # Ensure required shape for Postman API: `collection.info` and `collection.item` must exist
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
            # Ensure required shape for Postman API: `collection.info` and `collection.item` must exist
            if "info" not in coll:
                coll["info"] = {"name": coll.get("name") or coll.get("id"), "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}
            if "item" not in coll:
                coll["item"] = coll.get("items") or []
        resp = requests.post(url, headers=headers_, json=body, timeout=30)

    # Handle 404 specifically when caller provided a collection_uid: this means
    # the caller attempted to PUT to a collection that doesn't exist or is
    # inaccessible with the API key. In that case we must NOT fallback to POST;
    # fail fast so callers can decide.
    if resp.status_code == 404 and collection_uid:
        raise RuntimeError(f"FATAL_UID_NOT_FOUND: collection_uid provided but not found or not accessible: {collection_uid}")
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman upsert_collection failed: {resp.status_code} - {resp.text}")

    # Newer responses use `uid`, older may use `collection.uid` - be flexible
    data = resp.json()
    uid = data.get("collection", {}).get("uid") or data.get("collection", {}).get("id") or data.get("uid")
    if uid:
        return str(uid)
    return data


def patch_collection(api_key: str, collection_uid: str, partial_body: dict):
    """Apply a PATCH-style partial update to a collection.

    Note: Postman's API primarily supports PUT for collection updates, but this helper
    uses HTTP PATCH when callers want a partial change. If the API rejects PATCH,
    the caller will receive an HTTP error.
    """
    url = f"{BASE_URL}/collections/{collection_uid}"
    headers_ = headers(api_key)

    # Accept either {'collection': {...}} or {...}
    coll = None
    if isinstance(partial_body, dict) and "collection" in partial_body:
        coll = partial_body.get("collection")
    elif isinstance(partial_body, dict):
        coll = partial_body
    else:
        raise RuntimeError("patch_collection expects a dict or {'collection': {...}} payload")

    # Build candidate payloads that omit 'item' (structures) since PATCH must not include them
    def make_payload(include_event=True, include_variable=True):
        payload_coll = {}
        if coll.get("info"):
            # Only include name/description/schema fields from info
            info = coll.get("info")
            payload_coll["info"] = {
                k: v for k, v in info.items() if k in ("name", "description", "schema")
            }
        if include_event and coll.get("event"):
            payload_coll["event"] = coll.get("event")
        if include_variable and coll.get("variable"):
            payload_coll["variable"] = coll.get("variable")
        return {"collection": payload_coll}

    attempts = [ (True, True), (False, True), (False, False) ]
    last_exc = None
    for include_event, include_variable in attempts:
        payload = make_payload(include_event=include_event, include_variable=include_variable)
        try:
            resp = requests.request("PATCH", url, headers=headers_, json=payload, timeout=30)
            if resp.status_code >= 400:
                # If bad request, try next reduced payload
                last_exc = RuntimeError(f"Postman patch_collection failed: {resp.status_code} - {resp.text}")
                # If the response indicates invalid parameter for 'event', try smaller payload
                continue
            data = resp.json()
            # normalize return similar to upsert_collection
            return data.get("collection", {}).get("uid") or data.get("collection", {}).get("id") or data.get("uid") or data
        except requests.exceptions.RequestException as e:
            last_exc = e
            continue

    # If we reach here, all attempts failed
    if last_exc:
        raise last_exc
    raise RuntimeError("Postman patch_collection failed: unknown error")


def patch_collection_metadata_only(api_key: str, collection_uid: str, collection: dict):
    """Attempt a metadata-only PATCH that never includes `item`.

    This wraps existing `patch_collection` behavior which already builds
    reduced payloads and omits `item`. On success returns the collection UID.
    On failure it will raise so callers can fall back to PUT.
    """
    return patch_collection(api_key, collection_uid, {"collection": collection})


def get_collection(api_key: str, collection_uid: str):
    """Retrieve an existing collection by UID."""
    url = f"{BASE_URL}/collections/{collection_uid}"
    resp = requests.get(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman get_collection failed: {resp.status_code} - {resp.text}")
    data = resp.json()
    return data.get("collection") or data


def list_environments(api_key: str, workspace_id: str):
    """List environments in a workspace. Returns a list of environment dicts."""
    url = f"{BASE_URL}/environments?workspace={workspace_id}"
    resp = requests.get(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman list_environments failed: {resp.status_code} - {resp.text}")
    data = resp.json()
    return data.get("environments") or []


def get_environment_by_name(api_key: str, workspace_id: str, name: str):
    """Return the UID of an environment in the workspace by its name, or None."""
    if not name:
        return None
    envs = list_environments(api_key, workspace_id)
    for e in envs:
        # Postman returns environment objects with `name` and `uid`/`id` keys
        if e.get("name") == name:
            return e.get("uid") or e.get("id")
    return None


def list_collections(api_key: str, workspace_id: str):
    """List collections in a workspace. Returns list of collection dicts."""
    url = f"{BASE_URL}/collections?workspace={workspace_id}"
    resp = requests.get(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman list_collections failed: {resp.status_code} - {resp.text}")
    data = resp.json()
    return data.get("collections") or []


def resolve_collection_uid(api_key: str, workspace_id: str, provided: str | None):
    """Resolve a provided collection identifier to a Postman collection UID.

    Returns a tuple `(resolved_uid_or_None, reason)` where `reason` is one of:
      - 'verified_existing' when provided uid exists as-is
      - 'recovered_by_suffix' when a suffix match was found
      - 'resolved_exact' when a plain UUID resolved by exact match
      - 'not_found' when no matching collection is found
      - 'invalid_format' when the provided string doesn't match expected patterns
    """
    if not provided:
        return None, None
    provided = provided.strip()

    def _extract_uid_from_entry(entry):
        coll = entry.get("collection") if isinstance(entry, dict) else entry
        if not coll:
            return None
        return coll.get("uid") or coll.get("id") or entry.get("uid") or entry.get("id")

    # Case 1: numeric-prefixed UID (e.g. '17451434-<uuid>')
    if re.match(r"^\d+-[0-9a-fA-F\-]{36}$", provided):
        # Verify existence directly
        try:
            if collection_exists(api_key, provided):
                return provided, "verified_existing"
        except Exception:
            # If existence check errors, continue to attempt suffix recovery
            pass
        # Attempt recovery by matching suffix after the first dash
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

    # Case 2: plain UUID
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
    """Return True if a collection with `collection_uid` exists, False if 404, else raise."""
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
    """Return the UID of a collection in the workspace by its name, or None."""
    if not name:
        return None
    cols = list_collections(api_key, workspace_id)
    for c in cols:
        coll = c.get("collection") or c
        if coll.get("info", {}).get("name") == name or coll.get("name") == name:
            return coll.get("uid") or coll.get("id")
    return None


def sync_linked_collections(api_key: str, workspace_id: str, collection: dict):
    """Sync any linked collections declared in the collection payload.

    Look for a `linked_collections` top-level key (list). Each entry may be either a
    UID string or an object with `uid` and optional `collection` payload. For entries
    that provide a `collection` payload, we upsert that collection (using the uid
    if provided). For UID-only entries we attempt to fetch the remote collection and
    call an upsert to ensure it exists in the target workspace.
    """
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
                # Fetch remote collection and re-upsert it into the workspace
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
    """Lightweight OpenAPI -> Postman collection converter.

    This is a minimal converter intended to produce usable requests for each
    operation in an OpenAPI 3.x spec. It does not implement every OpenAPI feature
    (servers arrays, complex parameter styles, auth flows), but it creates basic
    requests with method, url, and JSON example bodies when available.
    """
    import yaml
    try:
        spec = yaml.safe_load(raw_spec)
    except Exception:
        # If parsing fails, return a minimal collection
        return {"info": {"name": name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": []}

    # We prefer using an environment variable for the base URL so requests
    # in Postman show as `{{base_url}}/...` and respect the generated
    # environments (Dev/QA/UAT/Prod). We'll ignore the spec server host and
    # replace it with `{{base_url}}` for idempotent, environment-driven calls.
    base = "{{base_url}}"

    collection = {"info": {"name": name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": []}

    paths = spec.get("paths") or {}
    for path, methods in paths.items():
        for method, op in (methods.items() if isinstance(methods, dict) else []):
            try:
                op_obj = op or {}
                op_name = op_obj.get("summary") or op_obj.get("operationId") or f"{method.upper()} {path}"
                # Build URL raw using environment variable placeholder
                # Ensure leading slash between base and path
                if path.startswith("/"):
                    raw_url = f"{base}{path}"
                else:
                    raw_url = f"{base}/{path}"

                # Build request body if example exists
                body = None
                rb = op_obj.get("requestBody") or {}
                content = rb.get("content") or {}
                if content:
                    # Prefer application/json example
                    app_json = content.get("application/json") or {}
                    examples = app_json.get("examples") or {}
                    schema = app_json.get("schema") or {}
                    example_value = None
                    if examples:
                        # take first example value
                        first = list(examples.values())[0]
                        example_value = first.get("value")
                    elif schema and isinstance(schema, dict):
                        # no example; skip
                        example_value = None

                    if example_value is not None:
                        import json as _json
                        body = {"mode": "raw", "raw": _json.dumps(example_value, indent=2), "options": {"raw": {"language": "json"}}}

                # Construct a Postman-friendly URL object. Using `raw` plus
                # `host` and `path` helps the Postman app render variables
                # and path segments. We place the entire host/variable into
                # the first element of `host` so it remains a single token.
                url_obj = {"raw": raw_url}
                # host: keep as single entry to preserve `{{base_url}}`
                url_obj["host"] = [base]
                # path: split the path into segments (without leading slash)
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
    """Create or update an environment in Postman. Returns the environment UID or response body."""
    headers_ = headers(api_key)
    # If no env_uid provided, attempt to find an existing environment by name
    if not env_uid:
        try:
            existing = get_environment_by_name(api_key, workspace_id, env_payload.get("name"))
            if existing:
                env_uid = existing
        except Exception:
            # fall through to create if lookup fails
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
    """Delete a collection by UID.

    Returns True on success or raises a RuntimeError with the Postman error body.
    """
    url = f"{BASE_URL}/collections/{collection_uid}"
    resp = requests.delete(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman delete_collection failed: {resp.status_code} - {resp.text}")
    return True


def delete_environment(api_key: str, environment_uid: str):
    """Delete an environment by UID.

    Returns True on success or raises a RuntimeError with the Postman error body.
    """
    url = f"{BASE_URL}/environments/{environment_uid}"
    resp = requests.delete(url, headers=headers(api_key), timeout=30)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        raise RuntimeError(f"Postman delete_environment failed: {resp.status_code} - {resp.text}")
    return True

def create_environment(api_key, workspace_id, name, values):
    payload = {
        "environment": {
            "name": name,
            "values": values
        }
    }

    r = requests.post(
        f"{BASE_URL}/environments?workspace={workspace_id}",
        headers=headers(api_key),
        json=payload,
        timeout=30
    )
    r.raise_for_status()
    return r.json()
