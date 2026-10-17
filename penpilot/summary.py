"""Human-readable views derived from collected evidence, never from assumptions."""
import html
from pathlib import Path

LABELS = {'completed': 'Coleta encerrada', 'partial': 'Parcial', 'running': 'Em andamento', 'pending': 'Aguardando', 'failed': 'Falhou', 'denied': 'Acesso negado', 'timeout': 'Tempo esgotado', 'unavailable': 'Ferramenta indisponível', 'skipped': 'Não aplicável', 'cancelled': 'Cancelado', 'limited': 'Limite atingido', 'interrupted': 'Interrompido', 'unsupported': 'Não suportado'}
MODULES = {'discovery': 'Descoberta de serviços', 'confirm': 'Confirmação do serviço', 'http': 'Páginas web', 'content': 'Descoberta de caminhos', 'screenshot': 'Capturas de tela', 'smb': 'Compartilhamentos SMB', 'ftp': 'Arquivos FTP'}


def summarize(state, selected_only=False):
    grouped = {}
    for n in state['nodes']:
        if n['kind'] != 'service' or (n.get('input_url') and not n.get('protocol')):
            continue
        product = ' '.join(filter(None, [n.get('product'), n.get('version')]))
        key = (n['host'], n['port'], n.get('protocol') or 'Não confirmado', product)
        row = grouped.setdefault(key, dict(host=key[0], port=key[1], protocol=key[2], product=product, node=n['id'], ips=[]))
        if n.get('ip') and n['ip'] not in row['ips']:
            row['ips'].append(n['ip'])
    services = list(grouped.values())
    # Keep the latest outcome of each task type/node; old failures remain in the task history.
    latest = {}
    for task in state['tasks']:
        latest[(task['plugin'], task['node'])] = task
    issues = [dict(module=MODULES.get(t['plugin'], t['plugin']), status=('Inconclusivo' if t['plugin'] == 'confirm' and t['status'] == 'skipped' else LABELS.get(t['status'], t['status'])), reason=t.get('reason', ''), node=t['node']) for t in latest.values() if t['status'] in ('failed', 'denied', 'timeout', 'unavailable', 'limited', 'interrupted', 'unsupported') or (t['plugin'] == 'confirm' and t['status'] == 'skipped')]
    grouped_issues = {}
    for issue in issues:
        reason = issue['reason']
        if 'ERR_HTTP_RESPONSE_CODE_FAILURE' in reason:
            reason = 'A captura não foi concluída. A resposta HTTP ou um redirecionamento impediu a navegação; consulte a resposta web e os detalhes da tarefa.'
        key = (issue['module'], issue['status'], reason)
        entry = grouped_issues.setdefault(key, {**issue, 'reason': reason, 'count': 0})
        entry['count'] += 1
    issues = list(grouped_issues.values())
    for issue in issues:
        if issue['count'] > 1:
            issue['reason'] += f" ({issue['count']} tarefas afetadas.)"
    observations = []
    seen = {}
    for f in reversed(state['findings']):
        if selected_only and not f.get('selected', True):
            continue
        key = (f['kind'], f['source'], f['title'], f['data'].get('body_sha256'), f['data'].get('status'))
        if key in seen:
            seen[key]['evidence'] = list(dict.fromkeys(seen[key]['evidence'] + f.get('evidence', [])))
            continue
        d = f['data']; lines = []
        if f['kind'] == 'web':
            lines = [f"Endereço: {d.get('url', f['source'])}", f"Resposta: HTTP {d.get('status')}", f"Título: {d.get('title') or 'Sem título'}"]
            if d.get('status') in (301, 302, 303, 307, 308) and d.get('headers', {}).get('location'):
                lines.append('Redirecionamento anunciado: ' + d['headers']['location'])
                lines.append('Esta observação descreve a resposta de redirecionamento, não o conteúdo da página de destino.')
            if d.get('generic_response'):
                lines.append('Resposta genérica: coincide com uma URL inexistente. Funcionalidade não confirmada.')
            if d.get('redirects'):
                lines.append('Redirecionamentos: ' + ' → '.join([r['url'] for r in d['redirects']] + [d['url']]))
            if d.get('redirect_blocked'):
                lines.append('Redirecionamento não seguido (fora da origem permitida): ' + d['redirect_blocked'])
            if d.get('technologies'):
                lines.append('Tecnologias anunciadas: ' + ', '.join(map(str, d['technologies'].values())))
            for label, field in [('E-mails publicados', 'emails')]:
                if d.get(field):
                    lines.append(label + ': ' + '; '.join(map(str, d[field][:20])))
        elif f['kind'] == 'browser':
            d=f['data']
            ok=sum(r.get('status') is not None for r in d.get('requests',[]))
            blocked=len(d.get('requests',[]))-ok
            lines=[f"Página renderizada: {d['url']}",f"{ok} requisições com resposta · {blocked} bloqueadas ou incompletas.",f"Texto visível: {d.get('visible_text_chars',0)} caracteres."]
            lines += d.get('limitations',[])
        elif f['kind'] == 'content':
            lines = [f"{len(d.get('matches', []))} caminhos encontrados."] + [f"HTTP {m['status']} — {m['url']}" for m in d.get('matches', [])]
        elif f['kind'] == 'smb':
            lines = [f"{s['name']}: {s.get('access', 'Acesso não testado')}" for s in d.get('shares', [])] or [f"Acesso: {d.get('access', 'Consulte a evidência')} — {d.get('reason', '')}"]
        elif f['kind'] == 'ftp':
            lines = [f"Autenticação: {'aceita' if d.get('authenticated') else 'não confirmada'}", d.get('listing', 'Sem listagem coletada')]
        elif f['kind'] == 'path':
            lines = [f"HTTP {d.get('status')} — {d.get('url', f['source'])}"]
        elif f['kind'] == 'screenshot':
            lines = [f"Captura de {d.get('url', f['source'])}"]
        elif 'services' in d:
            lines = [f"{d['services']} serviço(s) encontrado(s) em {d.get('ip', '')}."]
        elif 'protocol' in d:
            lines = [f"{d['protocol']} confirmado na porta {d.get('port')}."]
        else:
            lines = ['Observação registrada; veja a evidência técnica para detalhes.']
        observation = dict(title=f['title'], lines=lines, note=f.get('note', ''), evidence=list(f.get('evidence', [])))
        if f['kind'] == 'web':
            observation['_web'] = {**d, 'url': d.get('url', f['source'])}
        if f['kind'] == 'path':
            observation['_path'] = d.get('url', f['source'])
        observations.append(observation)
        seen[key] = observation
    from .web_summary import compact_web
    observations, web_coverage = compact_web(observations)
    status = state['status']
    if status == 'running':
        message = 'Reconhecimento em andamento. Os resultados abaixo são parciais.'
    elif services:
        message = f"{len(services)} entrada(s) de serviço, agrupadas por alvo, porta e identificação. " + ('Há etapas que precisam de atenção.' if issues else 'Os resultados estão prontos para revisão.')
    elif any(t['plugin']=='discovery' and t['status'] in ('timeout','limited','failed','unavailable','interrupted') for t in state['tasks']):
        message = 'Descoberta TCP inconclusiva. Falha ou limite na descoberta não comprova ausência de serviços; consulte também as respostas das URLs informadas.'
    else:
        message = 'Nenhum serviço foi confirmado nas portas consultadas. Verifique as tarefas, o alvo e a seleção de portas.'
    limitations = [
        'Coleta anônima: áreas autenticadas e permissões de usuários não foram avaliadas.',
        'JavaScript não é executado. Capturas são estáticas e podem não representar a interface de aplicações dinâmicas.',
        'Rotas literais de scripts, robots.txt e sitemap são candidatas; só as consultadas têm resposta confirmada. Profundidade, escopo e orçamento limitam a cobertura.',
        'Encerrar a coleta não significa analisar todo o site nem comprovar ausência de vulnerabilidades.',
    ]
    if 'http' in state.get('auth_required',[]):
        limitations[0]='Sessão web fornecida para uma origem exata; isso não comprova acesso a todas as áreas nem valida permissões.'
    if state['profile'].get('render_js'):
        limitations[1]='JavaScript habilitado nas capturas. Somente GET e origens autorizadas; interações, POST e WebSocket não são exercitados.'
    from .analysis import review
    actionable=review(state)
    return dict(actionable=actionable, web_coverage=web_coverage, limitations=limitations, status=LABELS.get(status, status), message=message, services=services, issues=issues, observations=observations, limits=state.get('limits', []))


def readable_report(state):
    s = summarize(state, selected_only=True)
    esc = html.escape
    rows = ''.join('<tr>' + ''.join(f'<td>{esc(str(v))}</td>' for v in (n['host'], ', '.join(n['ips']) or 'Não registrado', n['port'], n['protocol'], n['product'] or 'Não identificada')) + '</tr>' for n in s['services'])
    limitations = '<section><h2>Alcance desta coleta</h2>' + ''.join(f'<p>{esc(x)}</p>' for x in s['limitations']) + '</section>'
    issues = ''.join(f"<li><strong>{esc(i['module'])}: {esc(i['status'])}</strong><br>{esc(i['reason'])}</li>" for i in s['issues'])
    action_html = '<section><h2>Revisões sugeridas</h2>' + ''.join(f"<details><summary>{esc(i['title'])}</summary><p>{esc(i['url'])}</p><p>{esc(i['evidence'])}</p><p>Próximo passo: {esc(i['action'])}</p></details>" for i in s['actionable']) + '<p>Observações contextuais; não são vulnerabilidades confirmadas.</p></section>' if s['actionable'] else ''
    findings = []
    for f in s['observations']:
        links = ''.join(f'<li><a href="{esc(e, quote=True)}">{esc(Path(e).name)} (evidência técnica)</a></li>' for e in f['evidence'])
        urls = ('<details><summary>Ver URLs (' + str(len(f.get('urls', []))) + ')</summary><ul>' + ''.join(f'<li>{esc(u)}</li>' for u in f.get('urls', [])) + '</ul></details>') if f.get('urls') else ''
        findings.append(f"<section><h2>{esc(f['title'])}</h2>" + ''.join(f'<p>{esc(line)}</p>' for line in f['lines']) + urls + (f"<p><strong>Nota:</strong> {esc(f['note'])}</p>" if f['note'] else '') + (f'<details><summary>Arquivos originais</summary><ul>{links}</ul></details>' if links else '') + '</section>')
    document = '<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'"><title>PenPilot — Resultados</title><style>body{font:15px/1.65 system-ui;color:#e2e8f0;background:#0b1018;color-scheme:dark;max-width:1000px;margin:40px auto;padding:24px}section{background:#141b26;padding:24px;border:1px solid #2b3748;border-radius:10px;margin:20px 0}h1{font-size:28px}h2{font-size:18px}td,th{text-align:left;padding:12px;border-bottom:1px solid #2b3748}table{width:100%;border-collapse:collapse}p,li{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#82aaff}summary{cursor:pointer;color:#a3b0c2}</style>'
    return document + f"<h1>Resultado do reconhecimento</h1><p><strong>{esc(', '.join(state['targets']))}</strong> · {esc(s['status'])}</p><p>{esc(s['message'])}</p><p>Início: {esc(state['created'])}</p><section><h2>Serviços encontrados</h2><table><thead><tr><th>Alvo</th><th>IPs observados</th><th>Porta TCP</th><th>Serviço</th><th>Versão anunciada</th></tr></thead><tbody>{rows}</tbody></table></section>" + (f'<section><h2>Atenção</h2><ul>{issues}</ul></section>' if issues else '') + action_html + limitations + ''.join(findings) + '<p>Portas consultadas: ' + esc(state['profile']['ports']) + '. Banners e versões não confirmam vulnerabilidades.</p></html>'


def write_readable(root, state):
    s = summarize(state)
    lines = ['PENPILOT — RESULTADOS', ', '.join(state['targets']), 'Estado: ' + s['status'], s['message'], '', 'SERVIÇOS ENCONTRADOS']
    for n in s['services']:
        lines.append(f"{n['host']} | TCP {n['port']} | {n['protocol']} | {n['product'] or 'Versão não identificada'} | IPs: {', '.join(n['ips']) or 'Não registrado'}")
    for f in s['observations']:
        lines += ['', f['title'], *f['lines']]
        if f['note']:
            lines.append('Nota: ' + f['note'])
    lines += ['', 'ETAPAS QUE PRECISAM DE ATENÇÃO']
    lines += [f"{i['module']}: {i['status']} — {i['reason']}" for i in s['issues']] or ['Nenhuma falha registrada nas últimas tentativas.']
    lines += ['', 'ALCANCE DESTA COLETA', *s['limitations'], *s['limits']]
    (Path(root) / 'resumo.txt').write_text('\n'.join(lines) + '\n')
    (Path(root) / 'report.html').write_text(readable_report(state))


def readable_markdown(state):
    s = summarize(state, selected_only=True)
    lines = ['# Resultado do reconhecimento', '', ', '.join(state['targets']), '', s['status'] + '. ' + s['message'], '', '## Serviços', '']
    for n in s['services']:
        lines.append(f"- {n['host']} · TCP {n['port']} · {n['protocol']} · {n['product'] or 'Versão não identificada'} · IPs: {', '.join(n['ips'])}")
    lines += ['', '## Alcance desta coleta', ''] + ['- ' + x for x in s['limitations'] + s['limits']]
    if s['actionable']:
        lines += ['', '## Revisões sugeridas', '']
        for item in s['actionable']:
            lines += [f"- {item['title']} · {item['url']}", f"  Evidência: {item['evidence']} Próximo passo: {item['action']}"]
    if s['issues']:
        lines += ['', '## Atenção', ''] + [f"- {i['module']}: {i['reason']}" for i in s['issues']]
    for f in s['observations']:
        lines += ['', '## ' + f['title'], '', *f['lines']]
        if f.get('urls'):
            lines += ['', '<details><summary>Ver URLs (' + str(len(f['urls'])) + ')</summary>', ''] + ['- ' + u for u in f['urls']] + ['', '</details>']
        if f['note']:
            lines += ['', f['note']]
        if f['evidence']:
            lines += ['', '<details><summary>Evidências técnicas</summary>', ''] + [f'- [{Path(e).name}]({e})' for e in f['evidence']] + ['', '</details>']
    return '\n'.join(lines) + '\n'
