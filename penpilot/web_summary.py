"""Conservative grouping: identical saved response bodies, never titles alone."""
import hashlib
from pathlib import Path
from urllib.parse import urlsplit


def hydrate_fingerprints(root, state):
    root = Path(root).resolve()
    for finding in state['findings']:
        if finding['kind'] != 'web' or finding['data'].get('body_sha256'):
            continue
        for name in finding.get('evidence', []):
            path = (root / name).resolve()
            if root in path.parents and path.name == 'body.txt' and path.is_file() and path.stat().st_size <= 4 * 1024 * 1024:
                finding['data']['body_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                break


def compact_web(observations):
    groups = {}
    rest = []
    visited, candidates = set(), set()
    for item in observations:
        data = item.pop('_web', None)
        if data is None:
            rest.append(item)
            continue
        url = data.get('url', '')
        visited.add(url)
        candidates.update(data.get('links', []))
        mime = data.get('headers', {}).get('content-type', '').split(';')[0].strip().lower()
        fingerprint = data.get('body_sha256')
        # Distinct statuses, origins, redirect destinations and media types stay separate.
        key = (urlsplit(url).netloc, urlsplit(url).scheme, data.get('status'), mime, fingerprint or url, data.get('headers', {}).get('location'))
        if key not in groups:
            groups[key] = {**item, 'urls': [], '_mime': mime, '_status': data.get('status'), '_hash': fingerprint}
        group = groups[key]
        if url not in group['urls']:
            group['urls'].append(url)
        group['evidence'] = list(dict.fromkeys(group['evidence'] + item['evidence']))
        if item['note'] and item['note'] not in group['note']:
            group['note'] += '\n' + item['note']
    for group in groups.values():
        mime, status, fingerprint = (group.pop(k) for k in ('_mime', '_status', '_hash'))
        if len(group['urls']) > 1 and fingerprint:
            group['title'] = f"HTTP {status} · {len(group['urls'])} URLs com resposta idêntica"
            group['lines'] = [f"Mesmo corpo de resposta salvo em {len(group['urls'])} URLs.", f"Tipo: {mime or 'não informado'}."]
            if 'html' in mime and status == 200:
                group['lines'].append('Compatível com uma página-base compartilhada. Não comprova acesso a conteúdo específico nem ausência de autenticação.')
            group['lines'].append('Agrupamento por SHA-256 do corpo salvo; evidências individuais preservadas.')
    # Path findings already represented by an HTTP response add no new information.
    rest = [item for item in rest if item.get('_path') not in visited]
    for item in rest:
        item.pop('_path', None)
    pending = sorted(candidates - visited)
    coverage = dict(consulted=len(visited), response_groups=len(groups), candidates=len(pending), unvisited=pending)
    overview = dict(title='Cobertura web', lines=[f'{len(visited)} URLs com resposta coletada · {len(groups)} grupos de resposta.', f'{len(pending)} URLs mencionadas, sem resposta coletada nesta execução.', 'URLs mencionadas podem estar fora da origem ou dos limites; não são endpoints confirmados.'], note='', evidence=[], urls=pending)
    return ([overview] if visited else []) + list(groups.values()) + rest, coverage
