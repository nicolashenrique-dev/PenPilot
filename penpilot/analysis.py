"""Offline application map, contextual review checks and stable run comparison."""
import base64
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from .models import canonical_url
from .storage import Redactor


def cookie_metadata(values):
    result = []
    for raw in values:
        parts = [p.strip() for p in raw.split(';')]
        if not parts or '=' not in parts[0]:
            continue
        name = parts[0].split('=', 1)[0]
        attrs = {p.split('=', 1)[0].lower(): p.split('=', 1)[1] if '=' in p else True for p in parts[1:]}
        result.append(dict(name=name, secure='secure' in attrs, httponly='httponly' in attrs, samesite=attrs.get('samesite', 'não informado')))
    return result


def application_map(state):
    nodes, edges = {}, {}
    def add(url, observed=False, status=None, kind='mentioned'):
        try:
            url = canonical_url(url)
        except (ValueError, TypeError):
            return None
        entry = nodes.setdefault(url, dict(url=url, host=urlsplit(url).hostname, observed=False, statuses=[], kind=kind))
        entry['observed'] |= observed
        if observed:
            entry['kind'] = kind
        if status is not None and status not in entry['statuses']:
            entry['statuses'].append(status)
        return url
    def edge(source, target, relation):
        a,b=add(source),add(target)
        if a and b:
            edges[(a,b,relation)] = dict(source=a,target=b,relation=relation)
    for f in state['findings']:
        d=f['data']
        if f['kind']=='web':
            source=add(d.get('url',f['source']),True,d.get('status'),'response')
            for url in d.get('links',[]):
                edge(source,url,'mentioned')
            for r in d.get('redirects',[]):
                edge(r['url'],r['destination'],'redirect')
        if f['kind']=='browser':
            source=add(d['url'],True,kind='rendered')
            for request in d.get('requests',[]):
                if request.get('method')=='OPTIONS':
                    edge(source,request['url'],'preflight')
                    continue
                add(request['url'],request.get('status') is not None,request.get('status'),'browser_response')
                edge(source,request['url'],'browser_request' if request.get('status') is not None else 'blocked_request')
    return dict(nodes=list(nodes.values()),edges=list(edges.values()))


def latest_web_findings(state):
    latest={}
    for finding in state['findings']:
        if finding['kind']=='web':
            latest[finding['data'].get('url',finding['source'])]=finding
    return list(latest.values())


def review(state):
    results=[]; seen=set()
    def item(code,url,title,evidence,action,level='review'):
        key=(code,url)
        if key not in seen:
            seen.add(key);results.append(dict(code=code,url=url,title=title,evidence=evidence,action=action,level=level))
    for f in latest_web_findings(state):
        d=f['data'];url=d.get('url',f['source']);h=d.get('headers',{})
        if d.get('generic_response'):
            item('generic',url,'Resposta igual à URL inexistente', 'Status, tipo e corpo coincidem com a sondagem de controle.', 'Não tratar HTTP 200 como confirmação da funcionalidade; revisar a página renderizada.', 'info')
        if d.get('status') in (401,403):
            item('access',url,'Acesso recusado',f"HTTP {d['status']}",'Se a área fizer parte do teste, fornecer uma sessão autorizada. Não é evidência de bypass.','info')
        if 'html' in h.get('content-type','') and d.get('status')==200:
            for key,title,action in [('content-security-policy','CSP não observada','Avaliar uma política compatível com os recursos da aplicação.'),('x-content-type-options','Proteção de tipo de conteúdo não observada','Verificar necessidade de X-Content-Type-Options: nosniff.')]:
                if key not in h:item(key,url,title,'Cabeçalho ausente nesta resposta.',action)
            if url.startswith('https:') and 'strict-transport-security' not in h:
                item('hsts',url,'HSTS não observado','Cabeçalho ausente nesta resposta.','Avaliar HTTPS em todo o domínio antes de habilitar HSTS.')
        for cookie in d.get('cookies',[]):
            missing=[k for k in ('secure','httponly') if not cookie[k]]
            if missing or cookie['samesite']=='não informado':
                item('cookie:'+cookie['name'],url,'Revisar atributos do cookie '+cookie['name'], 'Ausentes: '+', '.join(missing+(['SameSite'] if cookie['samesite']=='não informado' else [])), 'Verificar a finalidade do cookie; cookies acessados pelo JavaScript podem não usar HttpOnly.')
        tls=d.get('tls') or {}
        if tls.get('version') in ('TLSv1','TLSv1.1','SSLv3'):
            item('tls-legacy',url,'Versão TLS legada',str(tls['version']),'Avaliar atualização do servidor e compatibilidade dos clientes.')
        if tls and not tls.get('verified'):
            item('tls-unverified',url,'Certificado não validado','Coleta configurada para aceitar certificados não confiáveis.','Repetir com validação TLS para avaliar a cadeia do certificado.')
        expiry=tls.get('certificate',{}).get('notAfter')
        if expiry:
            try:
                end=datetime.strptime(expiry,'%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                at=datetime.fromisoformat(state['created'])
                days=(end-at).days
                if days<30:item('tls-expiry',url,'Validade do certificado',f'{days} dias restantes na data da coleta.','Revisar renovação do certificado.')
            except (ValueError,TypeError):pass
    return results


def snapshot(state):
    endpoints={}
    for f in state['findings']:
        if f['kind']=='web':
            d=f['data'];headers=d.get('headers',{})
            endpoints[d.get('url',f['source'])]=dict(status=d.get('status'),body=d.get('body_sha256'),headers={k:headers.get(k) for k in ('content-security-policy','strict-transport-security','x-content-type-options','server')})
        if f['kind']=='browser':
            for r in f['data'].get('requests',[]):
                if r.get('status') is not None and r.get('method','GET')=='GET':
                    endpoints.setdefault(r['url'],dict(status=r['status']))
    services=sorted({(n['host'],n['port'],n.get('protocol') or 'unknown',n.get('product',''),n.get('version','')) for n in state['nodes'] if n['kind']=='service'})
    return dict(endpoints=endpoints,services=services)


def compare(before,after):
    a,b=snapshot(before),snapshot(after)
    old,new=a['endpoints'],b['endpoints']
    changed=[dict(url=u,before=old[u],after=new[u]) for u in sorted(old.keys() & new.keys()) if old[u]!=new[u]]
    result=dict(added=sorted(new.keys()-old.keys()),not_observed=sorted(old.keys()-new.keys()),changed=changed,services_before=a['services'],services_after=b['services'], comparable=before['targets']==after['targets'] and before['profile']==after['profile'] and before.get('auth_required',[])==after.get('auth_required',[]),note='Não observado nesta coleta não significa removido. Compare escopo, orçamento e contexto de autenticação. Identidade do usuário e equivalência das credenciais não são verificadas.')
    # Copied wordlist paths differ between runs; compare the effective settings instead.
    pa={k:v for k,v in before['profile'].items() if k!='wordlist'};pb={k:v for k,v in after['profile'].items() if k!='wordlist'}
    result['comparable']=before['targets']==after['targets'] and pa==pb and before.get('scope',{}).get('allowed')==after.get('scope',{}).get('allowed') and before.get('scope',{}).get('excluded')==after.get('scope',{}).get('excluded') and before.get('auth_required',[])==after.get('auth_required',[])
    result['has_changes']=bool(result['added'] or result['not_observed'] or changed or a['services']!=b['services'])
    return result


def burp_archive(root,state):
    """Raw HTTP requests for Repeater, plus a standard HAR with no credentials."""
    root=Path(root);path=root/'burp-review.zip';entries=[];seen=set();redactor=Redactor()
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as archive:
        for node in application_map(state)['nodes']:
            if not node['observed']:continue
            p=urlsplit(node['url'])
            # Omit query values: session tokens can appear under arbitrary parameter names.
            query='&'.join(part.split('=',1)[0]+'=REDACTED' for part in p.query.split('&') if part)
            url=urlunsplit((p.scheme,p.netloc,p.path,query,''))
            if url in seen:continue
            seen.add(url);target=p.path or '/'
            if query:target+='?'+query
            request=f'GET {target} HTTP/1.1\r\nHost: {p.netloc}\r\nAccept: */*\r\n\r\n'
            archive.writestr(f'requests/{len(seen):03d}.http',redactor.text(request))
            entries.append(dict(startedDateTime=state['created'],time=0,request=dict(method='GET',url=url,httpVersion='HTTP/1.1',headers=[dict(name='Host',value=p.netloc)],queryString=[],cookies=[],headersSize=-1,bodySize=0),response=dict(status=(node['statuses'] or [0])[0],statusText='',httpVersion='HTTP/1.1',headers=[],cookies=[],content=dict(size=0,mimeType='application/octet-stream'),redirectURL='',headersSize=-1,bodySize=0),cache={},timings=dict(send=0,wait=0,receive=0)))
        archive.writestr('requests.har',json.dumps(dict(log=dict(version='1.2',creator=dict(name='PenPilot',version='0.1'),entries=entries)),ensure_ascii=False,indent=2))
        archive.writestr('LEIA-ME.txt','Abra um arquivo requests/*.http e cole no Burp Repeater, configurando host, porta e TLS conforme requests.har. Requisições GET reconstruídas para revisão; não são uma captura exata. Authorization, Cookie e valores de query não são exportados. Adicione sua sessão localmente, se necessário.\n')
    return path


def next_steps(state):
    """Prioritize coverage gaps without asserting vulnerabilities or session validity."""
    steps=[];seen=set()
    actions={
        'unavailable':'Abra Ferramentas e diagnóstico, instale a dependência indicada e retome a execução.',
        'limited':'Revise o orçamento de tempo e requisições antes de retomar.',
        'timeout':'Verifique conectividade e timeout; repita somente a etapa afetada.',
        'failed':'Abra os detalhes da tarefa e consulte a mensagem e as evidências.',
        'interrupted':'Retome a execução para continuar as etapas interrompidas.',
        'denied':'Confira a sessão e as permissões da conta para este recurso.'}
    latest_tasks={}
    for task in state['tasks']:
        latest_tasks[(task['plugin'],task.get('node',task['host']))]=task
    for task in latest_tasks.values():
        status=task['status']
        key=(task['plugin'],task['host'],status)
        if status in actions and key not in seen:
            seen.add(key)
            steps.append(dict(title=f"{task['host']} · {task['plugin']}",category='Pendente',evidence=task.get('reason') or status,action=actions[status],view='tasks'))
    for finding in latest_web_findings(state):
        d=finding['data']
        if d.get('status') in (401,403):
            status=d['status'];url=d.get('url',finding['source']);key=('session',url,status)
            if key in seen:continue
            seen.add(key)
            steps.append(dict(title=url,category='Sessão / acesso',evidence=f'HTTP {status}'+(' com credenciais fornecidas.' if state.get('auth_required') else ' sem sessão configurada.'),action='Renove a sessão se ela expirou. Um 401 também pode indicar credencial inválida.' if status==401 else 'Verifique as permissões da conta. Um 403 não comprova expiração da sessão.',view='web'))
    for item in review(state):
        if item['code']=='access':continue
        steps.append(dict(title=item['title'],category='Revisar',evidence=item['url']+' · '+item['evidence'],action=item['action'],view='review'))
    return steps


def visual_comparison(before, after):
    def captures(state):
        result={}
        for f in state['findings']:
            if f['kind'] not in ('browser','screenshot'):continue
            paths=[p for p in f.get('evidence',[]) if p.endswith('.png')]
            if paths:result[f['data'].get('url',f['source'])]=paths[-1]
        return result
    old,new=captures(before),captures(after)
    return [dict(url=url,before=old.get(url),after=new.get(url)) for url in sorted(old.keys()|new.keys())]
