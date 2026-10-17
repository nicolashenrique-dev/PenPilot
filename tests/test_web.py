import re
from fastapi.testclient import TestClient
from penpilot.web import create_app


def test_local_boundary_and_preview(tmp_path):
    with TestClient(create_app(tmp_path),base_url='http://127.0.0.1:8765') as c:
        page=c.get('/')
        assert page.status_code==200
        token=re.search(r'name="penpilot-token" content="([^"]+)"',page.text)[1]
        assert c.post('/api/preview',json={'targets':['127.0.0.1']}).status_code==403
        headers={'X-PenPilot-Token':token,'Origin':'https://evil.invalid'}
        assert c.post('/api/preview',json={'targets':['127.0.0.1']},headers=headers).status_code==403
        headers['Origin']='http://127.0.0.1:8765'
        result=c.post('/api/preview',json={'targets':['127.0.0.1']},headers=headers)
        assert result.status_code==200 and result.json()['profile']['directory_depth']==1
        assert c.get('/',headers={'Host':'evil.invalid'}).status_code==403
        assert c.get('/api/runs/nope/files/../../etc/passwd').status_code==404
        assert c.get('/api/config').status_code==200
