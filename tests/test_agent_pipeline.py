import asyncio
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import threading
import pytest
import httpx
from penpilot.engine import Engine
from penpilot.models import Profile
from penpilot.intel import IntelStore
from penpilot.repeater import repeat
from penpilot.tooling import proxy,plan,execute_tool


@pytest.fixture(autouse=True)
def cheap_doctor(monkeypatch):monkeypatch.setattr('penpilot.engine.doctor',lambda:{})

@pytest.fixture
def lab():
    requests=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            requests.append((self.path,self.headers.get('Authorization')))
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
            self.wfile.write(json.dumps({'message':'PenPilot lab','path':self.path,'token':'must-not-be-retained'}).encode())
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield f'http://127.0.0.1:{server.server_port}',requests
    server.shutdown();server.server_close();thread.join()


def engine(tmp_path,url='http://127.0.0.1'):
    return Engine.create(tmp_path,[url],Profile.build('quick',modules=['http']))


def test_context_import_redacts_and_paginates_without_network(tmp_path,monkeypatch):
    e=engine(tmp_path);store=IntelStore(e.root)
    def forbidden(*args,**kwargs):raise AssertionError('Unexpected DNS')
    monkeypatch.setattr('socket.getaddrinfo',forbidden)
    har={'log':{'entries':[{'request':{'url':'http://127.0.0.1/api/user?id=secret-value','method':'GET','headers':[{'name':'Authorization','value':'Bearer private-token'}]},'response':{'status':200,'headers':[],'content':{'text':'{"token":"response-secret"}','mimeType':'application/json'}}}]}}
    file=tmp_path/'test.har';file.write_text(json.dumps(har))
    store.ingest(file,'har')
    data=store.context(2000)
    serialized=json.dumps(data)
    assert 'private-token' not in serialized and 'response-secret' not in serialized and 'secret-value' not in serialized
    assert data['records'][0]['auth_present'] is True
    assert 'REDACTED' in data['records'][0]['url']
    revision=store.read()['revision'];store.ingest(file,'har');assert store.read()['revision']==revision
    store.put([store.endpoint('http://127.0.0.1/'+str(i),'test') for i in range(30)])
    first=store.context(2000);second=store.context(2000,first['next_cursor'],revision=first['revision'])
    assert not {r['id'] for r in first['records']} & {r['id'] for r in second['records']}
    assert len(json.dumps(first,ensure_ascii=False))<=2000
    with pytest.raises(ValueError):store.context(revision=revision)


def test_js_openapi_refs_triage_and_handoff(tmp_path):
    e=engine(tmp_path);store=IntelStore(e.root)
    js=tmp_path/'app.js';js.write_text('fetch("/api/users?id=secret"); el.innerHTML = input; fetch("https://outside.invalid/a");\n//# sourceMappingURL=app.js.map')
    store.ingest(js,'js','http://127.0.0.1/app.js')
    doc={'openapi':'3.0.3','servers':[{'url':'/api'}],'paths':{'/users/{id}':{'get':{'parameters':[{'$ref':'#/components/parameters/id'}],'security':[{'bearer':[]}]}},'/unsafe':{'post':{'requestBody':{'$ref':'https://external.invalid/body'}}}},'components':{'parameters':{'id':{'name':'id','in':'path','required':True}}}}
    file=tmp_path/'api.json';file.write_text(json.dumps(doc));store.ingest(file,'openapi','http://127.0.0.1/openapi.json')
    records=store.read()['records']
    assert any(r.get('in_scope') is False for r in records)
    assert any(r.get('url')=='http://127.0.0.1/api/users/{id}' and r['parameters'][0]['name']=='id' for r in records)
    assert any(r.get('category')=='dom-html' for r in records)
    with pytest.raises(ValueError):store.decision(records[0]['id'],'validated')
    store.decision(records[0]['id'],'discarded','Teste sem efeito')
    result=store.handoff();assert Path(result['context']).is_file()


def test_repeater_pinned_no_redirect_raw_body_or_auth_leak(tmp_path,lab):
    url,calls=lab;e=engine(tmp_path,url);e.credentials={'http':{'origin':url,'token':'local-secret'}}
    first=asyncio.run(repeat(e,url+'/?id=1'));second=asyncio.run(repeat(e,url+'/?id=1',query=['id=2'],compare=first['id']))
    assert calls[0][1]=='Bearer local-secret'
    assert 'body_sha256' in second['comparison']['changes']
    text=''.join(p.read_text() for p in (e.root/'intel').rglob('*.json'))
    assert 'local-secret' not in text and 'must-not-be-retained' not in text
    with pytest.raises(ValueError):asyncio.run(repeat(e,'http://outside.invalid/'))
    with pytest.raises(ValueError):asyncio.run(repeat(e,url,method='POST'))


def test_scanner_plans_are_explicit_and_reject_unsafe_templates(tmp_path,lab):
    url,_=lab;e=engine(tmp_path,url)
    template=tmp_path/'safe.yaml';template.write_text('id: test\ninfo: {name: Test, author: local, severity: info}\nhttp:\n - method: GET\n   path: ["{{BaseURL}}/"]\n   matchers:\n    - type: word\n      words: ["PenPilot lab"]\n')
    spec,argv=plan(e,'nuclei',url,template=template)
    assert '-dr' in argv and '-ni' in argv and spec['status']=='planned'
    _,argv=plan(e,'sqlmap',url+'/?id=1',parameter='id')
    assert '--risk=1' in argv and '--technique=BE' in argv and '--ignore-redirects' in argv
    template.write_text('id: unsafe\nhttp:\n - raw: ["POST / HTTP/1.1"]\n')
    with pytest.raises(ValueError):plan(e,'nuclei',url,template=template)
    with pytest.raises(ValueError):plan(e,'sqlmap',url+'/?id=1',parameter='other')


@pytest.mark.skipif(not shutil.which('mitmdump'),reason='mitmdump not installed')
def test_real_scoped_proxy_enforces_origin_method_budget(tmp_path,lab):
    url,calls=lab;e=engine(tmp_path,url)
    async def scenario():
        async with proxy(e,[url],e.root/'intel/traffic.jsonl',max_requests=2,rate=20) as running:
            async with httpx.AsyncClient(proxy=running['url'],trust_env=False,timeout=20) as client:
                assert (await client.get(url+'/one')).status_code==200
                assert (await client.post(url+'/write',content='no')).status_code==405
                assert (await client.get('http://outside.invalid/')).status_code==403
                assert (await client.get(url+'/two')).status_code==200
                assert (await client.get(url+'/three')).status_code==429
    asyncio.run(scenario())
    assert len(calls)==2
    assert 'must-not-be-retained' not in (e.root/'intel/traffic.jsonl').read_text()


@pytest.mark.skipif(not shutil.which('nuclei') or not shutil.which('mitmdump'),reason='nuclei or mitmdump absent')
def test_real_nuclei_local_template(tmp_path,lab):
    url,calls=lab;e=engine(tmp_path,url)
    template=tmp_path/'match.yaml';template.write_text('id: penpilot-local-test\ninfo:\n  name: Local fixture\n  author: penpilot\n  severity: info\nhttp:\n - method: GET\n   path: ["{{BaseURL}}/"]\n   matchers:\n    - type: word\n      words: ["PenPilot lab"]\n')
    result=asyncio.run(execute_tool(e,'nuclei',url,template=template,max_requests=5,rate=10,timeout=30))
    assert result['status']=='completed',result
    assert result['matches']==1,result
    assert len(calls)<=5
    assert any(r['kind']=='scanner-match' and r['confidence']=='unverified' for r in IntelStore(e.root).read()['records'])


@pytest.mark.skipif(not shutil.which('sqlmap') or not shutil.which('mitmdump'),reason='sqlmap or mitmdump absent')
def test_real_sqlmap_bounded_local_run(tmp_path,lab):
    url,calls=lab;e=engine(tmp_path,url)
    result=asyncio.run(execute_tool(e,'sqlmap',url+'/?id=1',parameter='id',max_requests=8,rate=20,timeout=20))
    assert result['status'] in ('completed','limited'),result
    assert 0<len(calls)<=8
    assert result['proxy']['sent']==len(calls)
    assert 'must-not-be-retained' not in json.dumps(result)


def test_explicit_url_runs_even_if_discovery_fails(tmp_path,lab,monkeypatch):
    from penpilot.plugins import REGISTRY,Plugin
    from penpilot.engine import TaskError
    from penpilot.summary import summarize
    url,calls=lab;e=engine(tmp_path,url)
    async def unavailable(e,t):raise TaskError('timeout','Simulated discovery timeout')
    monkeypatch.setitem(REGISTRY,'discovery',Plugin('discovery',(),(),'','','',unavailable))
    asyncio.run(e.run())
    assert any(f['kind']=='web' for f in e.state['findings'])
    assert calls and summarize(e.state)['services'][0]['protocol']=='http'
    assert e.state['status']=='partial'
    assert (e.root/'intel/HANDOFF.md').exists()


def test_inconclusive_discovery_does_not_claim_absence(tmp_path):
    from penpilot.summary import summarize
    e=engine(tmp_path);e.state['tasks'][0].update(status='timeout',reason='timeout');e.state['status']='partial'
    assert 'inconclusiva' in summarize(e.state)['message']


def test_agent_api_boundaries_and_import(tmp_path):
    import re
    from fastapi.testclient import TestClient
    from penpilot.web import create_app
    e=engine(tmp_path)
    with TestClient(create_app(tmp_path),base_url='http://127.0.0.1:8765') as client:
        token=re.search(r'name="penpilot-token" content="([^"]+)"',client.get('/').text)[1]
        headers={'X-PenPilot-Token':token};base='/api/runs/'+e.state['id']+'/agent'
        assert client.post(base+'/import',json={}).status_code==403
        result=client.post(base+'/import',headers=headers,json={'format':'js','base':'http://127.0.0.1/app.js','text':'fetch("/api/data");'})
        assert result.status_code==200,result.text
        context=client.get(base).json();identity=context['records'][0]['id']
        assert client.get(base+'/record/'+identity).status_code==200
        assert client.post(base+'/record/'+identity,headers=headers,json={'status':'validated'}).status_code==400
        assert client.post(base+'/record/'+identity,headers=headers,json={'status':'investigating','note':'Local test'}).status_code==200
        handoff=client.post(base+'/handoff',headers=headers,json={}).json()
        assert client.get(handoff['url']).status_code==200


@pytest.mark.skipif(not shutil.which('mitmdump'),reason='mitmproxy absent')
def test_native_mitm_dump_import_offline(tmp_path):
    import subprocess
    e=engine(tmp_path);path=tmp_path/'capture.mitm'
    # Use the same system Python as the installed mitmdump, without adding a dependency to PenPilot.
    script='''from mitmproxy import connection,http,io
import sys
flow=http.HTTPFlow(connection.Client(peername=('127.0.0.1',1000),sockname=('127.0.0.1',8081)),connection.Server(address=('127.0.0.1',80)))
flow.request=http.Request.make('GET','http://127.0.0.1/api/test',headers={'Authorization':'Bearer private-import'})
flow.response=http.Response.make(200,b'{"secret":"private-body"}',{'Content-Type':'application/json'})
with open(sys.argv[1],'wb') as file:io.FlowWriter(file).add(flow)
'''
    subprocess.run(['/usr/bin/python3','-c',script,str(path)],check=True)
    result=IntelStore(e.root).ingest(path,'mitm')
    assert result['added']==1
    text=(e.root/'intel/index.json').read_text()
    assert 'private-import' not in text and 'private-body' not in text


def test_bounty_report_requires_operator_validation(tmp_path):
    e=engine(tmp_path);store=IntelStore(e.root)
    store.put([store.endpoint('http://127.0.0.1/api/test','fixture',observed=True)])
    identity=store.read()['records'][0]['id']
    assert store.report()['records']==0
    store.decision(identity,'validated','Reproduced in local fixture; impact reviewed')
    result=store.report()
    assert result['records']==1 and result['submitted'] is False
    assert 'Reproduced in local fixture' in Path(result['path']).read_text()
