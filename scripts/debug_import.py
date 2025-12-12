from dotenv import load_dotenv
from pathlib import Path
import os, json
load_dotenv()
from postman_api import import_openapi
ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / 'specs' / 'payment-refund-api-openapi.yaml'
api_key = os.getenv('POSTMAN_API_KEY')
workspace_id = os.getenv('POSTMAN_WORKSPACE_ID')
if not api_key or not workspace_id:
    print('Missing POSTMAN_API_KEY or POSTMAN_WORKSPACE_ID in environment')
    raise SystemExit(1)
raw = SPEC_PATH.read_text()
coll = import_openapi(api_key, workspace_id, 'Payment Refund API - debug', raw)
print('Type:', type(coll))
if isinstance(coll, dict):
    print('Top-level keys:', list(coll.keys()))
    print('Has item key?', 'item' in coll)
    if 'item' in coll:
        print('Item count:', len(coll['item']))
    # print first-level preview
    print('Preview (trimmed):')
    def trim(o, depth=0):
        if depth>2:
            return '...'
        if isinstance(o, dict):
            return {k: trim(v, depth+1) for k,v in list(o.items())[:10]}
        if isinstance(o, list):
            return [trim(v, depth+1) for v in o[:5]]
        return o
    print(json.dumps(trim(coll), indent=2))
else:
    print('Collection is not a dict, repr:')
    print(repr(coll))
