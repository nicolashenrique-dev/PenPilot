import asyncio
import json
import shutil
from pathlib import Path

import pytest
from penpilot.engine import Engine
from penpilot.models import Profile
from penpilot.plugins import http, content


def prepared(tmp_path,port,**kwargs):
    p=Profile.build('custom', ports=str(port), rate=100, max_duration=60, task_timeout=45, **kwargs)
    e=Engine.create(tmp_path,['127.0.0.1'],p)
    return e


@pytest.mark.skipif(not shutil.which('nmap'),reason='Nmap required for real loopback integration')
def test_real_nmap_nonstandard_http_end_to_end(tmp_path,lab_http):
    port, requests=lab_http
    e=prepared(tmp_path,port,modules=['http','smb','ftp'],crawl_depth=1)
    asyncio.run(e.run())
    services=[n for n in e.state['nodes'] if n['kind']=='service']
    assert any(n['port']==port and n['protocol']=='http' for n in services), e.state
    assert any(f['kind']=='web' and f['data']['title']=='PenPilot local lab' for f in e.state['findings'])
    assert all(t['status']=='skipped' for t in e.state['tasks'] if t['plugin'] in ('smb','ftp'))
    assert '/docs/' in requests
    assert not any('outside.invalid' in command for t in e.state['tasks'] for c in t['commands'] for command in c['argv'])
    for file in e.root.rglob('*'):
        if file.is_file(): assert b'do-not-log' not in file.read_bytes()


@pytest.mark.parametrize('depth',[0,1,2])
def test_directory_depth(tmp_path,lab_http,depth):
    port, requests=lab_http
    wl=tmp_path/'words.txt';wl.write_text('docs/\ndeeper/\n')
    e=prepared(tmp_path,port,modules=['content'],wordlist=str(wl),directory_depth=depth)
    host=e.state['nodes'][0]
    service=e.node('service','HTTP',host['id'],host='127.0.0.1',port=port,protocol='http')
    url=f'http://127.0.0.1:{port}/'
    n=e.node('url',url,service['id'],host='127.0.0.1',url=url)
    e.state['tasks'][0]['status']='completed'
    e.enqueue('content',n['id'],depth=0)
    asyncio.run(e.run())
    tasks=[t for t in e.state['tasks'] if t['plugin']=='content']
    assert max(t['params']['depth'] for t in tasks)==depth
    assert ('/docs/deeper/' in requests)==(depth>=1)
    assert ('/docs/deeper/deeper/' in requests)==(depth>=2)


def test_request_budget_keeps_partial_findings(tmp_path,lab_http):
    port,_=lab_http
    wl=tmp_path/'words';wl.write_text('docs/\nrobots.txt\nadmin/\n')
    e=prepared(tmp_path,port,modules=['content'],wordlist=str(wl),max_requests=2)
    host=e.state['nodes'][0];s=e.node('service','http',host['id'],host='127.0.0.1',port=port,protocol='http')
    n=e.node('url','base',s['id'],host='127.0.0.1',url=f'http://127.0.0.1:{port}/')
    e.state['tasks'][0]['status']='completed';e.enqueue('content',n['id'],depth=0)
    asyncio.run(e.run())
    assert e.state['requests']['127.0.0.1']==2
    assert any(f['kind']=='path' for f in e.state['findings'])
    assert e.state['status']=='partial'


def test_http_denied_is_not_empty_result(tmp_path,lab_http):
    port,_=lab_http;e=prepared(tmp_path,port,modules=['http'])
    host=e.state['nodes'][0];s=e.node('service','http',host['id'],host='127.0.0.1',port=port,protocol='http')
    n=e.node('url','admin',s['id'],host='127.0.0.1',url=f'http://127.0.0.1:{port}/admin/')
    e.state['tasks'][0]['status']='completed';t=e.enqueue('http',n['id'])
    asyncio.run(e.run())
    assert t['status']=='denied' and e.state['findings'][0]['data']['status']==403


@pytest.mark.skipif(not shutil.which('ffuf'),reason='ffuf optional')
def test_real_ffuf_loopback(tmp_path,lab_http):
    port,_=lab_http;wl=tmp_path/'words';wl.write_text('docs/\nmissing\n')
    e=prepared(tmp_path,port,modules=['content'],wordlist=str(wl),content_engine='ffuf',directory_depth=0)
    host=e.state['nodes'][0];s=e.node('service','http',host['id'],host='127.0.0.1',port=port,protocol='http')
    n=e.node('url','base',s['id'],host='127.0.0.1',url=f'http://127.0.0.1:{port}/')
    e.state['tasks'][0]['status']='completed';t=e.enqueue('content',n['id'])
    asyncio.run(e.run())
    assert t['status']=='completed',t
    assert any('/docs/' in m['url'] for f in e.state['findings'] for m in f['data'].get('matches',[]))


def test_real_screenshot_loopback(tmp_path,lab_http):
    pytest.importorskip('playwright')
    port,_=lab_http
    e=prepared(tmp_path,port,modules=['screenshot'])
    host=e.state['nodes'][0];s=e.node('service','http',host['id'],host='127.0.0.1',port=port,protocol='http')
    n=e.node('url','base',s['id'],host='127.0.0.1',url=f'http://127.0.0.1:{port}/')
    e.state['tasks'][0]['status']='completed';t=e.enqueue('screenshot',n['id'])
    asyncio.run(e.run())
    assert t['status']=='completed',t
    png=next(e.root.rglob('screenshot.png'))
    assert png.read_bytes().startswith(b'\x89PNG') and png.stat().st_size>1000
