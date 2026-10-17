import asyncio
from penpilot.plugins import document_links, http
from penpilot.engine import Engine
from penpilot.models import Profile


def test_extract_sitemap_robots_and_js():
    base='https://lab.invalid/assets/main.js'
    assert document_links('const a="assets/chunk.js"; const b="/materias"; const c="/users/${id}";', 'application/javascript',base)==['https://lab.invalid/assets/chunk.js','https://lab.invalid/materias']
    assert document_links('<urlset xmlns="urn:test"><url><loc>https://lab.invalid/entrar</loc></url></urlset>','application/xml',base)==['https://lab.invalid/entrar']
    assert document_links('Disallow: /perfil\nSitemap: /sitemap.xml','text/plain','https://lab.invalid/robots.txt')==['https://lab.invalid/perfil','https://lab.invalid/sitemap.xml']
    assert document_links('<!DOCTYPE x><urlset><loc>/no</loc></urlset>','application/xml',base)==[]


def test_extracted_routes_obey_scope_and_depth(tmp_path,monkeypatch):
    from penpilot import plugins
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick',crawl_depth=1,modules=['http']))
    host=e.state['nodes'][0]
    service=e.node('service','HTTP',host['id'],host='127.0.0.1',port=80,protocol='http',ip='127.0.0.1')
    node=e.node('url','sitemap',service['id'],host='127.0.0.1',url='http://127.0.0.1/sitemap.xml')
    task=e.enqueue('http',node['id'],depth=0)
    async def fetch(*args):
        return {'url':node['url'],'status':200,'headers':{'content-type':'application/xml'}}, '<urlset><loc>/docs/</loc><loc>http://outside.invalid/private</loc></urlset>', []
    monkeypatch.setattr(plugins,'fetch_page',fetch)
    asyncio.run(http(e,task))
    urls=[e.get_node(t['node']).get('url') for t in e.state['tasks'] if t['plugin']=='http']
    assert 'http://127.0.0.1/docs/' in urls
    assert not any('outside.invalid' in u for u in urls)
    assert 'http://outside.invalid/private' in e.state['findings'][-1]['data']['links']
    e.profile.crawl_depth=0
    count=len(e.state['tasks'])
    asyncio.run(http(e,task))
    assert len(e.state['tasks'])==count
