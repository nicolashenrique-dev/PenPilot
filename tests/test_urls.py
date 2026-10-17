import asyncio
import shutil
import pytest
from penpilot.engine import Engine
from penpilot.models import Profile, Scope, canonical_url
from penpilot.plugins import register_services


def test_url_paths_ports_and_resume(tmp_path):
    urls = ['https://localhost:18443/App?q=A,B#section', 'https://localhost:18443/Other']
    engine = Engine.create(tmp_path, urls, Profile.build('quick', ports='80'))
    assert engine.state['targets'] == ['localhost']
    assert engine.profile.ports == '80,18443'
    task = engine.state['tasks'][0]
    register_services(engine, task, '<nmaprun><host><address addr="127.0.0.1"/><ports><port portid="18443"><state state="open"/><service name="http" tunnel="ssl" method="probed" conf="10"/></port></ports></host></nmaprun>')
    assert {n['url'] for n in engine.state['nodes'] if n['kind']=='url'} == {canonical_url(u) for u in urls}
    engine.checkpoint()
    assert Engine.load(engine.root).state['input_urls'] == [canonical_url(u) for u in urls]


@pytest.mark.parametrize('url', ['ftp://localhost/file', 'http://user:pass@localhost/', 'http://localhost:0/', 'https://localhost:99999/', 'https:///path'])
def test_invalid_url_rejected_before_output(tmp_path, url):
    with pytest.raises(ValueError):
        Engine.create(tmp_path, [url])
    assert not list(tmp_path.iterdir())


def test_url_scope_and_ipv6(tmp_path):
    assert Scope.normalize('https://[::1]:8443/Test') == '::1'
    with pytest.raises(ValueError):
        Engine.create(tmp_path, ['http://127.0.0.1/'], allowed=['127.0.0.2'])
    with pytest.raises(ValueError):
        Engine.create(tmp_path, ['http://127.0.0.1/'], excluded=['127.0.0.1'])


@pytest.mark.skipif(not shutil.which('nmap'), reason='Nmap required')
def test_url_real_http_path(tmp_path, lab_http):
    port, requests = lab_http
    url = f'http://127.0.0.1:{port}/docs/'
    engine = Engine.create(tmp_path, [url], Profile.build('quick', ports=str(port), modules=['http'], rate=50))
    asyncio.run(engine.run())
    assert '/docs/' in requests
    assert any(f['source']==url and f['data'].get('title')=='Documentation' for f in engine.state['findings'])
