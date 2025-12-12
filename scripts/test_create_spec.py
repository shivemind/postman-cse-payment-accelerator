import os
from dotenv import load_dotenv
from postman_api import create_spec

load_dotenv()
api_key = os.getenv('POSTMAN_API_KEY')
workspace_id = os.getenv('POSTMAN_WORKSPACE_ID')

minimal_spec = """openapi: 3.0.0
info:
  title: Minimal Test Spec
  version: 1.0.0
paths: {}
"""

print('Attempting to create minimal spec...')
try:
    spec_id = create_spec(api_key, workspace_id, 'Minimal Test Spec', minimal_spec, '1.0.0')
    print('Created spec:', spec_id)
except Exception as e:
    print('Create spec failed:', e)
