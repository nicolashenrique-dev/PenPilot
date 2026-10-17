import asyncio
import pytest
from penpilot import plugins
from penpilot.engine import TaskError
from penpilot.models import Scope


class Context:
    scope = Scope(['127.0.0.1'])
    def __init__(self):
        self.evidence_items = []
    def evidence(self, task, name, value):
        self.evidence_items.append(value)


def test_https_upgrade_preserves_path_and_evidence(monkeypatch):
    calls = []
    async def fetch(e, t, url):
        calls.append(url)
        if url.startswith('http:'):
            return dict(url=url, status=301, headers={'location':'https://127.0.0.1/docs/?q=A'}), ''
        return dict(url=url, status=200, headers={}), 'final page'
    monkeypatch.setattr(plugins, 'fetch', fetch)
    context = Context()
    info, body, chain = asyncio.run(plugins.fetch_page(context, {}, 'http://127.0.0.1/'))
    assert calls == ['http://127.0.0.1/', 'https://127.0.0.1/docs/?q=A']
    assert body == 'final page' and info['status']==200
    assert len(chain)==len(context.evidence_items)==1


@pytest.mark.parametrize('destination', ['https://outside.invalid/', 'http://127.0.0.1:8080/', 'http://127.0.0.1/'])
def test_cross_origin_and_downgrade_not_fetched(monkeypatch, destination):
    calls=[]
    async def fetch(e,t,url):
        calls.append(url)
        return dict(url=url,status=302,headers={'location':destination}), ''
    monkeypatch.setattr(plugins, 'fetch', fetch)
    info, _, _=asyncio.run(plugins.fetch_page(Context(), {}, 'https://127.0.0.1/'))
    assert len(calls)==1 and info['redirect_blocked']==destination


def test_redirect_loop_is_bounded(monkeypatch):
    calls=[]
    async def fetch(e,t,url):
        calls.append(url)
        return dict(url=url,status=302,headers={'location':'/'}), ''
    monkeypatch.setattr(plugins, 'fetch', fetch)
    with pytest.raises(TaskError, match='circular'):
        asyncio.run(plugins.fetch_page(Context(), {}, 'http://127.0.0.1/'))
    assert len(calls)==1


def test_http_upgrade_records_confirmed_https_service(tmp_path, monkeypatch):
    from penpilot.engine import Engine
    from penpilot.models import Profile
    e=Engine.create(tmp_path, ['127.0.0.1'], Profile.build('quick', modules=['http']))
    host=e.state['nodes'][0]
    service=e.node('service','HTTP',host['id'],host='127.0.0.1',port=80,protocol='http',ip='127.0.0.1')
    unknown=e.node('service','443',host['id'],host='127.0.0.1',port=443,protocol=None,ip='127.0.0.1')
    node=e.node('url','HTTP',service['id'],host='127.0.0.1',url='http://127.0.0.1/')
    task=e.enqueue('http',node['id'])
    async def fetch(e,t,url):
        if url.startswith('http:'):
            return dict(url=url,status=301,headers={'location':'https://127.0.0.1/'}), ''
        return dict(url=url,status=200,headers={'content-type':'text/html'}), '<html><title>HTTPS OK</title></html>'
    monkeypatch.setattr(plugins,'fetch',fetch)
    asyncio.run(plugins.http(e,task))
    assert unknown['protocol']=='https' and unknown['method']=='http-response'
    assert node['final_url']=='https://127.0.0.1/'
    assert e.state['findings'][-1]['data']['title']=='HTTPS OK'
    assert e.state['findings'][-1]['data']['redirects'][0]['status']==301
