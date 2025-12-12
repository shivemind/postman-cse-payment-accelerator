from dotenv import load_dotenv
from pathlib import Path
import os, json
load_dotenv()
from postman_api import create_spec, generate_collection
ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / 'specs' / 'payment-refund-api-openapi.yaml'
api_key = os.getenv('POSTMAN_API_KEY')
workspace_id = os.getenv('POSTMAN_WORKSPACE_ID')
if not api_key or not workspace_id:
    print('Missing POSTMAN_API_KEY or POSTMAN_WORKSPACE_ID in environment')
    raise SystemExit(1)
raw = SPEC_PATH.read_text()
try:
    spec_id = create_spec(api_key, workspace_id, 'Payment Refund API - debug-spec', raw, '2.0')
    print('Spec created:', spec_id)
    coll = generate_collection(api_key, spec_id)
    print('Generated collection keys:', list(coll.keys()))
    print('Has item?', 'item' in coll)
    if 'item' in coll:
        print('Item count:', len(coll['item']))
    print(json.dumps({k: coll.get(k) for k in ['id','name','uid','info'] if k in coll}, indent=2))
except Exception as e:
    print('Spec hub flow failed:', e)
