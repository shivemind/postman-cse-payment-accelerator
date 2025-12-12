from dotenv import load_dotenv
from pathlib import Path
import os, json, re
load_dotenv()
from postman_api import delete_collection
ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / 'generated' / 'postman_actions.log'
if not LOG.exists():
    print('No postman_actions.log found')
    raise SystemExit(1)
# find last upsert_collection uid
uid = None
with LOG.open('r', encoding='utf-8') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
            if obj.get('action') == 'upsert_collection' and obj.get('status') == 'success':
                details = obj.get('details') or {}
                uid = details.get('uid')
        except Exception:
            continue
if not uid:
    print('No upsert_collection success entry with uid found in log')
    raise SystemExit(1)
print('Deleting collection UID from log:', uid)
api_key = os.getenv('POSTMAN_API_KEY')
if not api_key:
    print('Missing POSTMAN_API_KEY')
    raise SystemExit(1)
try:
    delete_collection(api_key, uid)
    print('Deleted collection:', uid)
except Exception as e:
    print('Failed to delete collection:', e)
