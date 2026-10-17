from penpilot.web_summary import compact_web, hydrate_fingerprints


def observation(url, body_hash='same', status=200, mime='text/html'):
    return dict(title=url, lines=['original'], note='', evidence=[url.rsplit('/',1)[-1]+'.txt'], _web=dict(url=url, status=status, body_sha256=body_hash, headers={'content-type':mime}, links=['https://lab.test/unvisited']))


def test_identical_html_grouped_with_urls_and_evidence():
    items, coverage = compact_web([observation('https://lab.test/a'), observation('https://lab.test/b')])
    group = items[1]
    assert group['urls']==['https://lab.test/a','https://lab.test/b']
    assert group['evidence']==['a.txt','b.txt']
    assert 'Não comprova acesso' in group['lines'][2]
    assert coverage==dict(consulted=2,response_groups=1,candidates=1,unvisited=['https://lab.test/unvisited'])


def test_different_body_status_origin_and_unknown_hash_not_merged():
    values=[observation('https://lab.test/a'),observation('https://lab.test/b','other'),observation('https://lab.test/c',status=403),observation('https://other.test/a'),observation('https://lab.test/d',None),observation('https://lab.test/e',None)]
    _, coverage=compact_web(values)
    assert coverage['response_groups']==6


def test_legacy_fingerprints_only_read_evidence_inside_run(tmp_path):
    root=tmp_path/'run';root.mkdir()
    (root/'body.txt').write_text('exact response')
    (tmp_path/'body.txt').write_text('outside')
    state={'findings':[{'kind':'web','data':{},'evidence':['body.txt']},{'kind':'web','data':{},'evidence':['../body.txt']}]}
    hydrate_fingerprints(root,state)
    assert len(state['findings'][0]['data']['body_sha256'])==64
    assert 'body_sha256' not in state['findings'][1]['data']
