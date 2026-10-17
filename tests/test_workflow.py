import json
from pathlib import Path
from unittest.mock import Mock
import pytest
from fastapi.testclient import TestClient
from penpilot.auth import import_request
from penpilot.models import Profile
from penpilot.workspace import Workspace
from penpilot.preflight import inspect, session_hint
from penpilot.analysis import next_steps, visual_comparison
from penpilot.service import unit_text, manage
from penpilot.web import create_app


def test_import_burp_and_curl_without_execution():
    raw='GET /api/me HTTP/2\nHost: lab.example:8443\nAuthorization: Bearer test-secret\nCookie: sid=cookie-secret\n\n'
    result=import_request(raw)
    assert result['url']=='https://lab.example:8443/api/me'
    assert result['session']==dict(origin='https://lab.example:8443',token='test-secret',cookie='sid=cookie-secret')
    curl="curl 'http://127.0.0.1/api/me' -H 'Authorization: Bearer test-secret' -b 'sid=cookie-secret' --compressed"
    assert import_request(curl)['session']['cookie']=='sid=cookie-secret'
    assert import_request('GET / HTTP/1.1\nHost: localhost\n',scheme='http')['url']=='http://localhost/'


@pytest.mark.parametrize('value',[
    '',
    "curl https://lab.example --data 'x=1'",
    "curl https://lab.example ; touch /tmp/should-not-run",
    "curl https://lab.example -H @secrets",
    "curl https://lab.example -b @secrets",
    "curl https://lab.example -X POST",
    'GET / HTTP/1.1\nHost: lab.example\nAuthorization: Basic abc',
    'GET / HTTP/1.1\nHost: lab.example\nCookie: a=1\nCookie: b=2',
    'GET / HTTP/1.1\n',
    'GET / HTTP/1.1\nHost: lab.example\n\nbody',
])
def test_import_rejects_unsupported_and_ambiguous(value):
    with pytest.raises(ValueError):import_request(value)


def test_projects_persist_config_only_and_archive_is_reversible(tmp_path):
    workspace=Workspace(tmp_path)
    saved=workspace.project(dict(name='Local lab',targets=['127.0.0.1'],profile=Profile.build('quick').json(),credentials={'http':{'token':'DO-NOT-SAVE'}}))
    assert 'DO-NOT-SAVE' not in workspace.path.read_text()
    assert Workspace(tmp_path).data['projects'][0]['name']=='Local lab'
    workspace.metadata('run1',dict(name='Baseline',archived=True))
    workspace.metadata('run1',dict(archived=False))
    assert Workspace(tmp_path).data['runs']['run1']==dict(name='Baseline',archived=False)
    with pytest.raises(ValueError):workspace.project(dict(name='Query',targets=['https://lab.example/?token=secret']))
    with pytest.raises(ValueError):workspace.project(dict(name='Unknown',id='bad',targets=['127.0.0.1']))
    assert saved['allowed']==['127.0.0.1']


def test_preflight_local_checks_expiry_and_no_target_http(monkeypatch):
    import base64
    monkeypatch.setattr('penpilot.preflight.doctor',lambda:{'nmap':dict(available=True),'smbclient':dict(available=False,install='Install smbclient')})
    payload=base64.urlsafe_b64encode(json.dumps({'exp':1}).encode()).decode().rstrip('=')
    auth={'http':dict(origin='http://127.0.0.1',token='header.'+payload+'.signature')}
    result=inspect(['127.0.0.1'],Profile.build('quick'),credentials=auth)
    assert not result['ready']
    assert any(c['title']=='Sessão' and c['level']=='error' for c in result['checks'])
    assert inspect(['127.0.0.1'],Profile.build('quick'))['ready']
    assert not inspect(['127.0.0.1'],Profile.build('quick'),allowed=['127.0.0.2'])['ready']
    assert session_hint({'http':dict(origin='http://127.0.0.1',token='opaque')})['level']=='info'


def test_next_steps_and_visual_pairing():
    state={'tasks':[dict(plugin='http',host='lab',status='timeout',reason='Network timeout')], 'findings':[dict(kind='web',source='http://lab/',data=dict(url='http://lab/',status=403,headers={})),dict(kind='screenshot',source='http://lab/',data={},evidence=['hosts/a.png'])]}
    steps=next_steps(state)
    assert any(s['view']=='tasks' for s in steps)
    assert any('não comprova expiração' in s['action'] for s in steps)
    after={**state,'findings':[dict(kind='screenshot',source='http://lab/',data={},evidence=['hosts/b.png'])]}
    assert visual_comparison(state,after)==[dict(url='http://lab/',before='hosts/a.png',after='hosts/b.png')]


def test_service_install_does_not_enable_or_start(tmp_path,monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME',str(tmp_path/'config'))
    monkeypatch.setattr('penpilot.service.shutil.which',lambda name:'/usr/bin/systemctl')
    run=Mock(return_value=Mock(returncode=0));monkeypatch.setattr('penpilot.service.subprocess.run',run)
    assert manage('install',tmp_path/'outputs with spaces')==0
    assert run.call_args.args[0]==['systemctl','--user','daemon-reload']
    text=next((tmp_path/'config/systemd/user').glob('*.service')).read_text()
    assert 'outputs with spaces' in text and '--port' in text and 'UMask=0077' in text
    with pytest.raises(ValueError):unit_text(tmp_path,99999)


def test_workflow_endpoints_boundary_and_single_scheduler(tmp_path):
    import re
    with TestClient(create_app(tmp_path),base_url='http://127.0.0.1:8765') as client:
        token=re.search(r'name="penpilot-token" content="([^"]+)"',client.get('/').text)[1]
        headers={'X-PenPilot-Token':token}
        assert client.post('/api/session/import',json={}).status_code==403
        result=client.post('/api/session/import',headers=headers,json={'text':'GET / HTTP/1.1\nHost: localhost\nCookie: sid=private'})
        assert result.status_code==200
        assert 'no-store' in result.headers['cache-control']
        saved=client.post('/api/projects',headers=headers,json={'name':'Lab','targets':['127.0.0.1'],'profile':Profile.build('quick').json(),'credentials':{'token':'SECRET'}})
        assert saved.status_code==200
        assert client.get('/api/projects').json()[0]['name']=='Lab'
        assert 'SECRET' not in (tmp_path/'.workspace.json').read_text()
        with pytest.raises(ValueError,match='Já existe um painel'):
            with TestClient(create_app(tmp_path,port=8766),base_url='http://127.0.0.1:8766'):pass


def test_service_unit_syntax(tmp_path):
    import shutil, subprocess
    if not shutil.which('systemd-analyze'):pytest.skip('systemd-analyze ausente')
    path=tmp_path/'penpilot-validation.service'
    path.write_text(unit_text(tmp_path/'output with spaces',18766))
    result=subprocess.run(['systemd-analyze','--user','verify',str(path)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr


def test_resolved_retries_do_not_remain_next_steps():
    state={'tasks':[dict(plugin='http',host='lab',node='one',status='timeout'),dict(plugin='http',host='lab',node='one',status='completed')], 'findings':[dict(kind='web',source='http://lab/',data={'status':401}),dict(kind='web',source='http://lab/',data={'status':200,'headers':{'content-type':'application/json'}})]}
    assert next_steps(state)==[]
