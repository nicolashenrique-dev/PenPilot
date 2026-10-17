import asyncio
import copy
import json
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from penpilot.engine import Engine, TaskError
from penpilot.models import Profile
from penpilot.auth import validate, headers
from penpilot.plugins import http, fetch, screenshot
from penpilot.analysis import application_map, compare, review, cookie_metadata, burp_archive
from penpilot.monitor import MonitorStore


@pytest.fixture
def feature_server():
    calls=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            calls.append((self.path,self.headers.get('Authorization'),self.headers.get('Cookie')))
            self.send_response(200)
            self.send_header('Content-Type','application/json' if self.path=='/api/data' else 'text/html')
            self.send_header('Set-Cookie','session=fake-cookie-secret; Secure; HttpOnly; SameSite=Lax')
            if self.path=='/app':
                body=b'''<html><body><div id="result">Waiting</div><script>fetch('/api/data',{headers:localStorage.getItem('token')?{Authorization:'Bearer '+localStorage.getItem('token')}:{}}).then(r=>r.json()).then(d=>document.querySelector('#result').textContent='JS ready '+d.ok);fetch('/write',{method:'POST',body:'no'});fetch('http://outside.invalid/');</script></body></html>'''
            elif self.path=='/api/data':body=b'{"ok":true}'
            else:body=b'<html><title>Generic</title><body>Same application shell</body></html>'
            self.end_headers();self.wfile.write(body)
        def do_POST(self):
            calls.append(('POST',None,None));self.send_response(500);self.end_headers()
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield server.server_port,calls
    server.shutdown();server.server_close();thread.join()


def prepared(tmp_path,port,**overrides):
    url=f'http://127.0.0.1:{port}'
    auth={'http':{'origin':url,'token':'fake-bearer-secret','cookie':'sid=fake-cookie-secret'}}
    e=Engine.create(tmp_path,[url],Profile.build('quick',modules=['http'],rate=100,**overrides),credentials=auth)
    host=e.state['nodes'][0]
    service=e.node('service','HTTP',host['id'],host='127.0.0.1',port=port,protocol='http',ip='127.0.0.1')
    node=e.node('url',url,service['id'],host='127.0.0.1',url=url+'/app')
    return e,e.enqueue('http',node['id'])


def test_exact_origin_auth_cookie_metadata_and_redaction(tmp_path,feature_server):
    port,calls=feature_server;e,t=prepared(tmp_path,port)
    asyncio.run(http(e,t));e.checkpoint()
    assert calls[0][1:] == ('Bearer fake-bearer-secret','sid=fake-cookie-secret')
    assert headers(e.credentials,'http://127.0.0.1:1/')=={}
    assert headers(e.credentials,'https://127.0.0.1:'+str(port)+'/')=={}
    assert e.state['findings'][-1]['data']['cookies']==[dict(name='session',secure=True,httponly=True,samesite='Lax')]
    for path in e.root.rglob('*'):
        if path.is_file():
            assert b'fake-bearer-secret' not in path.read_bytes()
            assert b'fake-cookie-secret' not in path.read_bytes()
    loaded=Engine.load(e.root)
    with pytest.raises(TaskError,match='Sessão web necessária'):
        asyncio.run(fetch(loaded,t,f'http://127.0.0.1:{port}/'))


def test_generic_probe_is_exact_and_cached(tmp_path,feature_server):
    port,calls=feature_server;e,t=prepared(tmp_path,port,generic_check=True)
    e.get_node(t['node'])['url']=f'http://127.0.0.1:{port}/wild'
    asyncio.run(http(e,t))
    assert e.state['findings'][-1]['data']['generic_response'] is True
    asyncio.run(http(e,t))
    assert len([x for x in calls if 'penpilot-missing' in x[0]])==1
    assert any(i['code']=='generic' for i in review(e.state))


def test_real_js_capture_observes_api_and_blocks_writes(tmp_path,feature_server):
    pytest.importorskip('playwright')
    port,calls=feature_server;e,t=prepared(tmp_path,port,render_js=True,browser_wait_ms=500)
    task=e.enqueue('screenshot',t['node'])
    asyncio.run(screenshot(e,task))
    item=e.state['findings'][-1]
    assert item['kind']=='browser'
    assert 'JS ready true' in (e.root/'hosts'/__import__('penpilot.models',fromlist=['uid']).uid('127.0.0.1')/'screenshot'/task['id']/'rendered.txt').read_text()
    assert any(r['url'].endswith('/api/data') and r['status']==200 for r in item['data']['requests'])
    assert any(r['method']=='POST' and r.get('blocked') for r in item['data']['requests'])
    assert not any(c[0]=='POST' for c in calls)
    assert all(c[1]=='Bearer fake-bearer-secret' for c in calls)
    mapped=application_map(e.state)
    assert any(n['url'].endswith('/api/data') and n['observed'] for n in mapped['nodes'])
    assert any(n['host']=='outside.invalid' and not n['observed'] for n in mapped['nodes'])


@pytest.mark.parametrize('auth',[{'origin':'http://127.0.0.1/','token':'x\r\nInjected: yes'},{'origin':'http://127.0.0.1/path','token':'x'},{'origin':'http://u:p@127.0.0.1/','token':'x'},{'origin':'http://127.0.0.1/','storage':{'session':123}}])
def test_invalid_auth_rejected(auth):
    with pytest.raises(ValueError):validate({'http':auth})


def test_diff_map_and_burp_are_offline_and_secret_free(tmp_path):
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick'))
    t=e.state['tasks'][0]
    e.finding(t,'Web',{'url':'https://127.0.0.1/me?session=private-value','status':200,'body_sha256':'one','headers':{},'links':['https://other.invalid/']},kind='web',source='https://127.0.0.1/me')
    before=copy.deepcopy(e.state)
    e.state['findings'][-1]['data']['status']=403
    delta=compare(before,e.state)
    assert delta['has_changes'] and len(delta['changed'])==1 and delta['comparable']
    assert not compare(e.state,e.state)['has_changes']
    with zipfile.ZipFile(burp_archive(e.root,e.state)) as z:
        text=''.join(z.read(n).decode() for n in z.namelist())
        assert 'private-value' not in text
        assert 'session=REDACTED' in text
        assert len(json.loads(z.read('requests.har'))['log']['entries'])==1
    assert any(not n['observed'] for n in application_map(e.state)['nodes'])


def test_monitor_persistence_pause_and_no_unchanged_events(tmp_path,monkeypatch):
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick'))
    e.state['status']='completed';e.checkpoint()
    store=MonitorStore(tmp_path);item=store.create(e,60)
    async def fake_run(self):self.state['status']='completed';self.checkpoint()
    monkeypatch.setattr(Engine,'run',fake_run)
    item['next_at']=0
    asyncio.run(store.tick())
    assert not item['events'] and item['last_run']!=e.state['id']
    store.toggle(item['id'],False)
    assert MonitorStore(tmp_path).items[0]['active'] is False
    with pytest.raises(ValueError):store.create(e,1)


def test_new_web_endpoints_and_monitor_controls(tmp_path):
    import re
    from fastapi.testclient import TestClient
    from penpilot.web import create_app
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick'))
    e.state['status']='completed';e.checkpoint()
    with TestClient(create_app(tmp_path),base_url='http://127.0.0.1:8765') as client:
        token=re.search(r'name="penpilot-token" content="([^"]+)"',client.get('/').text)[1]
        headers_={'X-PenPilot-Token':token}
        base='/api/runs/'+e.state['id']
        assert client.get(base+'/analysis').status_code==200
        assert client.get(base+'/compare/'+e.state['id']).json()['has_changes'] is False
        assert client.post(base+'/burp',json={}).status_code==403
        response=client.post(base+'/burp',json={},headers=headers_)
        assert client.get(response.json()['url']).status_code==200
        created=client.post('/api/monitors',json={'template':e.state['id'],'interval':3600},headers=headers_)
        assert created.status_code==200
        identity=created.json()['id']
        assert client.post('/api/monitors/'+identity,json={'active':False},headers=headers_).json()['active'] is False
        assert client.get('/api/monitors').json()[0]['active'] is False
        assert client.get(base).json()['auth_ready']==[]


def test_monitor_emits_one_event_for_change_then_stays_quiet(tmp_path,monkeypatch):
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick'))
    e.state['status']='completed';e.checkpoint()
    store=MonitorStore(tmp_path);item=store.create(e,60)
    async def fake_run(self):
        t=self.state['tasks'][0]
        self.finding(t,'response',{'url':'http://127.0.0.1/','status':200,'body_sha256':'stable','headers':{}},kind='web',source='http://127.0.0.1/')
        self.state['status']='completed';self.checkpoint()
    monkeypatch.setattr(Engine,'run',fake_run)
    async def scenario():
        item['next_at']=0;await store.tick()
        assert len(item['events'])==1
        item['next_at']=0;await store.tick()
        assert len(item['events'])==1
    asyncio.run(scenario())


def test_review_cookie_and_tls_checks_are_contextual():
    state=dict(created='2026-10-14T00:00:00+00:00',findings=[dict(kind='web',source='https://lab.invalid/',data=dict(url='https://lab.invalid/',status=200,headers={'content-type':'text/html'},cookies=cookie_metadata(['preference=private; SameSite=Lax']),tls=dict(verified=True,version='TLSv1.1',certificate={'notAfter':'Oct 20 00:00:00 2026 GMT'})))])
    items=review(state)
    assert {'cookie:preference','tls-legacy','tls-expiry','hsts','content-security-policy'} <= {i['code'] for i in items}
    assert 'private' not in json.dumps(items)
    assert all(i['action'] and i['evidence'] for i in items)



def test_localstorage_session_authorization_forwarded_only_in_scope(tmp_path,feature_server):
    pytest.importorskip('playwright')
    from penpilot.storage import Redactor
    port,calls=feature_server;e,t=prepared(tmp_path,port,render_js=True,browser_wait_ms=500)
    e.credentials=validate({'http':{'origin':f'http://127.0.0.1:{port}','storage':{'token':'localstorage-secret'}}})
    e.redactor=Redactor(e.credentials)
    task=e.enqueue('screenshot',t['node'])
    asyncio.run(screenshot(e,task))
    assert any(path=='/api/data' and auth=='Bearer localstorage-secret' for path,auth,_ in calls)
    for path in e.root.rglob('*'):
        if path.is_file():assert b'localstorage-secret' not in path.read_bytes()


def test_same_length_content_not_filtered_as_generic(tmp_path,monkeypatch):
    from penpilot import plugins
    words=tmp_path/'words.txt';words.write_text('real')
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick',modules=['content'],wordlist=str(words)))
    host=e.state['nodes'][0]
    service=e.node('service','HTTP',host['id'],host='127.0.0.1',port=80,protocol='http',ip='127.0.0.1')
    node=e.node('url','root',service['id'],host='127.0.0.1',url='http://127.0.0.1/')
    task=e.enqueue('content',node['id'],depth=0)
    async def fake_fetch(e,t,url,**kwargs):
        return dict(url=url,status=200,bytes=4,headers={}), 'REAL' if url.endswith('/real') else 'BASE'
    monkeypatch.setattr(plugins,'fetch',fake_fetch)
    asyncio.run(plugins.content(e,task))
    assert any(f['kind']=='path' and f['source'].endswith('/real') for f in e.state['findings'])


def test_watch_one_iteration_does_not_sleep_or_repeat(tmp_path,monkeypatch,capsys):
    from penpilot.monitor import watch
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick'))
    e.state['status']='completed';e.checkpoint()
    calls=[]
    async def fake_run(self):calls.append(self);self.state['status']='completed';self.checkpoint()
    monkeypatch.setattr(Engine,'run',fake_run)
    assert asyncio.run(watch(e.root,60,1))==0
    assert len(calls)==1
    assert 'Monitor ativo' in capsys.readouterr().out


def test_browser_cross_origin_session_and_preflight(tmp_path):
    """A separate API origin receives only scoped credentials and real CORS headers."""
    pytest.importorskip('playwright')
    from penpilot.storage import Redactor
    calls=[]
    class API(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_OPTIONS(self):
            calls.append(('OPTIONS',self.headers.get('Authorization'),self.headers.get('Origin')))
            self.send_response(204)
            self.send_header('Access-Control-Allow-Origin',self.headers['Origin'])
            self.send_header('Access-Control-Allow-Methods','GET')
            self.send_header('Access-Control-Allow-Headers','Authorization')
            self.end_headers()
        def do_GET(self):
            calls.append(('GET',self.headers.get('Authorization'),self.headers.get('Origin')))
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Access-Control-Allow-Origin',self.headers.get('Origin','null'))
            self.end_headers();self.wfile.write(b'{"ok":true}')
    api=ThreadingHTTPServer(('127.0.0.1',0),API)
    api_origin=f'http://127.0.0.1:{api.server_port}'
    class Page(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
            self.wfile.write(('<body><p id="result">Waiting</p><script>fetch('+json.dumps(api_origin+'/data')+',{headers:{Authorization:"Bearer "+localStorage.getItem("token")}}).then(r=>r.json()).then(d=>document.querySelector("#result").textContent="Cross origin ready "+d.ok)</script></body>').encode())
    page=ThreadingHTTPServer(('127.0.0.1',0),Page)
    threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (api,page)]
    for thread in threads:thread.start()
    try:
        e,t=prepared(tmp_path,page.server_port,render_js=True,browser_wait_ms=800,browser_origins=[api_origin])
        e.credentials=validate({'http':{'origin':api_origin,'storage_origin':f'http://127.0.0.1:{page.server_port}','storage':{'token':'cross-origin-secret'}}})
        e.redactor=Redactor(e.credentials)
        task=e.enqueue('screenshot',t['node'])
        asyncio.run(screenshot(e,task))
        text=''.join(p.read_text() for p in e.root.rglob('rendered.txt'))
        assert 'Cross origin ready true' in text
        assert any(c[0]=='GET' and c[1]=='Bearer cross-origin-secret' for c in calls)
        assert all(c[1] is None for c in calls if c[0]=='OPTIONS')
        assert all(c[2]==f'http://127.0.0.1:{page.server_port}' for c in calls)
    finally:
        for server in (api,page):server.shutdown();server.server_close()
        for thread in threads:thread.join()
