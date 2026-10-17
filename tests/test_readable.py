import json
from pathlib import Path

from fastapi.testclient import TestClient
from penpilot.engine import Engine
from penpilot.models import Profile
from penpilot.paths import default_output
from penpilot.summary import summarize
from penpilot.web import create_app


def test_default_output_does_not_depend_on_working_directory(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path/'home'))
    monkeypatch.chdir(tmp_path)
    assert default_output() == tmp_path/'home'/'PenPilot'/'execucoes'
    with TestClient(create_app(),base_url='http://127.0.0.1:8765') as c:
        assert c.get('/api/config').json()['output_directory'] == str(default_output())


def test_readable_outputs_and_web_report_keep_collected_html_inert(tmp_path):
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick'))
    host=e.state['nodes'][0]
    e.node('service','HTTP',host['id'],host='127.0.0.1',port=8080,protocol='http',product='Example',version='1.2')
    task=e.state['tasks'][0]
    evidence=e.evidence(task,'nmap.xml','<nmaprun/>')
    e.finding(task,'<script>alert(1)</script>',{'services':1,'ip':'127.0.0.1'},evidence=[evidence])
    task['status']='completed';e.state['status']='completed';e.checkpoint()
    text=(e.root/'resumo.txt').read_text()
    report=(e.root/'report.html').read_text()
    assert 'TCP 8080 | http | Example 1.2' in text
    assert '<table>' in report and '&lt;script&gt;' in report and '<script>' not in report
    assert '<pre>' not in report
    with TestClient(create_app(tmp_path),base_url='http://127.0.0.1:8765') as c:
        payload=c.get('/api/runs/'+e.state['id']).json()
        assert payload['output_directory'] == str(e.root)
        assert payload['summary']['services'][0]['port']==8080
        response=c.get('/api/runs/'+e.state['id']+'/report')
        assert response.headers['content-type'].startswith('text/html')
        assert '/files/hosts/' in response.text
        raw=c.get('/api/runs/'+e.state['id']+'/files/'+evidence)
        assert raw.headers['content-type'].startswith('text/plain')


def test_latest_attempt_resolves_issue_without_deleting_history(tmp_path):
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick'))
    task=e.state['tasks'][0];task['status']='timeout';task['reason']='fixture timeout'
    assert len(summarize(e.state)['issues'])==1
    e.enqueue('discovery',task['node'],attempt=2)['status']='completed'
    assert not summarize(e.state)['issues']
    assert e.state['tasks'][0]['status']=='timeout'


def test_multi_ip_summary_preserves_addresses_and_evidence(tmp_path):
    from penpilot.summary import summarize
    from penpilot.engine import Engine
    e = Engine.create(tmp_path, ['127.0.0.1'])
    host = e.state['nodes'][0]
    for ip in ['127.0.0.1', '127.0.0.2']:
        node = e.node('service', 'HTTP', host['id'], host='127.0.0.1', port=80, protocol='http', ip=ip)
        task = e.enqueue('screenshot', node['id'])
        task.update(status='failed', reason='Screenshot: ERR_HTTP_RESPONSE_CODE_FAILURE')
        e.finding(task, 'HTTP 301', {'status':301}, kind='web', source='http://127.0.0.1/', evidence=[ip+'.json'])
    summary = summarize(e.state)
    assert len(summary['services']) == 1
    assert summary['services'][0]['ips'] == ['127.0.0.1', '127.0.0.2']
    assert len(summary['issues']) == 1 and summary['issues'][0]['count']==2
    assert {e for item in summary['observations'] for e in item['evidence']}=={'127.0.0.1.json', '127.0.0.2.json'}
