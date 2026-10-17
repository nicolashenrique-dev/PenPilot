import asyncio
import json
import sys
import time
import zipfile
from pathlib import Path

import pytest
from penpilot.engine import Engine, TaskError
from penpilot.models import Profile, Scope, canonical_url
from penpilot.plugins import Plugin, REGISTRY, classify
from penpilot.storage import Redactor, archive


def make(tmp_path, **kwargs):
    return Engine.create(tmp_path, ['127.0.0.1'], Profile.build('quick', **kwargs))


def test_profile_validation_and_roundtrip():
    p=Profile.build('custom', directory_depth=2, crawl_depth=0)
    assert Profile.build(**p.json()).json()==p.json()
    for values in [dict(ports='80;id'),dict(ports='0'),dict(directory_depth=9),dict(modules=['evil']),dict(rate=0)]:
        with pytest.raises(ValueError): Profile.build(**values)


def test_scope_exclusion_and_pinning(monkeypatch):
    import socket
    calls=[]
    def resolve(*args, **kwargs):
        calls.append(args)
        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',0))]
    monkeypatch.setattr(socket,'getaddrinfo',resolve)
    s=Scope(['lab.local'])
    assert s.resolve('lab.local')==['127.0.0.1']
    assert s.resolve('lab.local')==['127.0.0.1'] and len(calls)==1
    assert not s.permits_url('http://evil.local/')
    with pytest.raises(ValueError): Scope(['lab.local'],['127.0.0.0/8']).resolve('lab.local')
    with pytest.raises(ValueError): Scope(['-oX'])
    with pytest.raises(ValueError): canonical_url('http://user:password@127.0.0.1')


def test_protocol_requires_probe():
    assert classify(dict(name='http',method='table',conf='3')) is None
    assert classify(dict(name='http',method='probed',conf='10'))=='http'
    assert classify(dict(name='http',method='probed',conf='10',tunnel='ssl'))=='https'
    assert classify(dict(name='microsoft-ds',method='probed',conf='10'))=='smb'


def test_redaction_does_not_corrupt_json():
    r=Redactor({'smb':{'username':'private-user','password':'a"b\\c'}})
    value=r.obj({'test':'private-user a"b\\c', 'headers':'Set-Cookie: secret\npublic: yes', 'url':'/?token=secret'})
    assert json.loads(json.dumps(value))==value
    assert 'private-user' not in str(value) and 'secret' not in str(value)


def test_atomic_checkpoint_and_archive(tmp_path):
    e=make(tmp_path)
    t=e.state['tasks'][0]
    ev=e.evidence(t,'test.txt','evidence')
    e.finding(t,'<script>alert(1)</script>',{'value':'observed'},evidence=[ev])
    e.checkpoint()
    assert Engine.load(e.root).state['id']==e.state['id']
    report=(e.root/'report.html').read_text()
    assert '<script>alert' not in report and '&lt;script&gt;' in report
    with zipfile.ZipFile(archive(e.root)) as z:
        assert ev in z.namelist() and 'writeup.md' in z.namelist()
    with zipfile.ZipFile(archive(e.root,True,['127.0.0.1'])) as z:
        assert not any(p.startswith('hosts/') for p in z.namelist())
        assert '127.0.0.1' not in z.read('writeup.md').decode()


def test_resume_does_not_repeat_completed(tmp_path, monkeypatch):
    e=make(tmp_path)
    calls=[]
    async def run(e,t): calls.append(t['id'])
    monkeypatch.setitem(REGISTRY,'discovery',Plugin('discovery',(),(),'test','none',(),run))
    asyncio.run(e.run())
    loaded=Engine.load(e.root)
    asyncio.run(loaded.run(resume=True))
    assert len(calls)==1
    loaded.repeat(loaded.state['nodes'][0]['id'])
    asyncio.run(loaded.run())
    assert len(calls)==2
    assert [t['attempt'] for t in loaded.state['tasks']]==[1,2]


def test_branch_cancel_isolation_and_dedup(tmp_path):
    e=make(tmp_path)
    host=e.state['nodes'][0]
    a=e.node('service','HTTP',host['id'],host='127.0.0.1',port=1234,protocol='http')
    b=e.node('service','FTP',host['id'],host='127.0.0.1',port=4321,protocol='ftp')
    ta=e.enqueue('http',a['id']); tb=e.enqueue('ftp',b['id'])
    assert e.enqueue('http',a['id']) is None
    e.cancel(a['id'])
    assert ta['status']=='cancelled' and tb['status']=='pending'
    assert e.repeat(a['id'])['attempt']==2


def test_duration_leaves_partial_checkpoint(tmp_path,monkeypatch):
    e=make(tmp_path,max_duration=1)
    async def slow(e,t):
        e.finding(t,'Partial',{'observed':True})
        await asyncio.sleep(5)
    monkeypatch.setitem(REGISTRY,'discovery',Plugin('discovery',(),(),'test','none',(),slow))
    asyncio.run(e.run())
    state=json.loads((e.root/'state.json').read_text())
    assert state['status']=='partial'
    assert state['findings'][0]['title']=='Partial'
    assert state['tasks'][0]['status']=='limited'


def test_child_process_cancelled_and_secrets_redacted(tmp_path,monkeypatch):
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick',max_duration=1),credentials={'smb':{'username':'private-user','password':'secret-pass'}})
    async def subprocess_plugin(e,t):
        await e.command(t,[sys.executable,'-c',"import time; print('secret-pass',flush=True); time.sleep(10)"])
    monkeypatch.setitem(REGISTRY,'discovery',Plugin('discovery',(),(),'test','none',(),subprocess_plugin))
    start=time.monotonic();asyncio.run(e.run())
    assert time.monotonic()-start<4
    for file in e.root.rglob('*'):
        if file.is_file(): assert b'secret-pass' not in file.read_bytes()
    assert '[REDACTED]' in next((e.root/'logs').glob('*.stdout.log')).read_text()


def test_rate_budget_concurrent(tmp_path):
    e=make(tmp_path,max_requests=2,rate=100)
    async def run():
        return await asyncio.gather(*(e.request_slot('127.0.0.1') for _ in range(4)),return_exceptions=True)
    results=asyncio.run(run())
    assert sum(isinstance(x,TaskError) for x in results)==2
    assert e.state['requests']['127.0.0.1']==2


def test_multiple_addresses_have_distinct_service_and_url_nodes(tmp_path):
    e=make(tmp_path)
    h=e.state['nodes'][0]
    a=e.node('service','http',h['id'],host='127.0.0.1',port=80,ip='127.0.0.1')
    b=e.node('service','http',h['id'],host='127.0.0.1',port=80,ip='127.0.0.2')
    ua=e.node('url','base',a['id'],host='127.0.0.1',url='http://127.0.0.1/')
    ub=e.node('url','base',b['id'],host='127.0.0.1',url='http://127.0.0.1/')
    assert a['id']!=b['id'] and ua['id']!=ub['id']
    assert ua['ip']=='127.0.0.1' and ub['ip']=='127.0.0.2'


def test_cancelling_running_branch_preserves_other_host(tmp_path,monkeypatch):
    e=Engine.create(tmp_path,['127.0.0.1','127.0.0.2'],Profile.build('quick',concurrency=2))
    async def plugin(e,t):
        if t['host']=='127.0.0.1': await asyncio.sleep(5)
        else:
            await asyncio.sleep(.1)
            e.finding(t,'Other host result',{'observed':True})
    monkeypatch.setitem(REGISTRY,'discovery',Plugin('discovery',(),(),'test','none',(),plugin))
    async def run():
        job=asyncio.create_task(e.run())
        await asyncio.sleep(.05)
        e.cancel(next(n['id'] for n in e.state['nodes'] if n['host']=='127.0.0.1'))
        await job
    asyncio.run(run())
    assert {t['host']:t['status'] for t in e.state['tasks']}=={'127.0.0.1':'cancelled','127.0.0.2':'completed'}
    assert e.state['findings'][0]['title']=='Other host result'
