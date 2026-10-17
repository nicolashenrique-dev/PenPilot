import html
import json
import os
import re
import tempfile
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path


def now():
    return datetime.now().astimezone().isoformat(timespec='seconds')


def atomic_json(path, value, indent=2):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.checkpoint-')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, ensure_ascii=False, indent=indent)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class Redactor:
    def __init__(self, credentials=None):
        self.secrets = sorted({str(v) for c in (credentials or {}).values() for k, v in c.items() if v and k in ('password', 'token', 'cookie', 'username')}, key=len, reverse=True)

        auth = (credentials or {}).get('http', {})
        extra = [auth.get('token', '').removeprefix('Bearer ').strip()]
        extra += [part.strip().split('=', 1)[1] for part in auth.get('cookie', '').split(';') if '=' in part]
        for value in auth.get('storage', {}).values():
            extra.append(value)
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    extra.extend(v for k,v in parsed.items() if isinstance(v,str) and ('token' in k.lower() or 'secret' in k.lower()))
            except (ValueError, TypeError):
                pass
        self.secrets = sorted(set(self.secrets + [x for x in extra if x]), key=len, reverse=True)

    def text(self, text):
        text = str(text)
        for secret in self.secrets:
            text = text.replace(secret, '[REDACTED]')
        text = re.sub(r'(?im)((?:authorization|proxy-authorization|set-cookie|cookie)\s*[:=]\s*)[^\r\n]+', r'\1[REDACTED]', text)
        text = re.sub(r'(?i)((?:password|passwd|token|api_key|secret)=)[^&\s"<>]+', r'\1[REDACTED]', text)
        return text

    def obj(self, value):
        # Traverse values rather than replacing serialized JSON (which could corrupt quoting).
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.obj(v) for v in value]
        if isinstance(value, dict):
            return {k: '[REDACTED]' if k.lower() in ('authorization', 'proxy-authorization', 'set-cookie', 'cookie', 'password', 'token', 'api_key') else self.obj(v) for k, v in value.items()}
        return value


def reports(root, state):
    root = Path(root)
    findings = state['findings']
    selected = [f for f in findings if f.get('selected', True)]
    coverage = dict(Counter(t['status'] for t in state['tasks']))
    checklist = [f'Reconhecimento: {reason}' for reason in state.get('limits', [])]
    for t in state['tasks']:
        if t['status'] != 'completed':
            checklist.append(f"Reconhecimento: {t['plugin']} — {t['status']}: {t.get('reason', '')}")
    for f in selected:
        if f.get('confidence') == 'hypothesis':
            checklist.append(f"Verificação: hipótese {f['title']}")
    lines = [f"# PenPilot · {state['id']}", '', f"Alvos: {', '.join(state['targets'])}", f"Início: {state['created']}", f"Estado: {state['status']}", '', '## Metodologia', '', 'Reconhecimento local condicionado a protocolos identificados. Versões e banners não confirmam vulnerabilidades.', '', 'Configuração e versões: [manifest.json](manifest.json). Escopo: [scope.json](scope.json).', '', '## Cobertura', '', '```json', json.dumps(coverage, ensure_ascii=False, indent=2), '```', '', '## Serviços observados', '']
    for n in state['nodes']:
        if n['kind'] == 'service':
            lines.append(f"- {n['label']} — identificação: {n.get('method')}, confiança {n.get('confidence')}; origem {n.get('source')}")
    lines += ['', '## Descobertas selecionadas', '']
    for f in selected:
        lines += [f"### {f['title']}", '', f"Origem: {f['source']} · contexto: {f.get('auth', 'anonymous')} · confiança: {f.get('confidence', 'observed')}", '', '```json', json.dumps(f['data'], ensure_ascii=False, indent=2).replace('```', '\\u0060\\u0060\\u0060'), '```', '', f.get('note', ''), '']
        for evidence in f.get('evidence', []):
            lines.append(f"- [Evidência]({evidence})")
    lines += ['', '## Comandos e tentativas', '']
    for t in state['tasks']:
        lines += [f"- {t['id']} · {t['plugin']} · tentativa {t['attempt']} · {t['status']}", f"  - [Comando](commands/{t['id']}.json) · [stdout](logs/{t['id']}.stdout.log) · [stderr](logs/{t['id']}.stderr.log)"]
    lines += ['', '## Pendências e limitações', ''] + [f'- {c}' for c in checklist]
    lines += ['- Não foram executadas exploração nem verificações específicas de CVEs.', '- Taxa HTTP interna é controlada por host; Nmap e processos externos têm limites conservadores, sem garantia de taxa agregada exata.', '', '## Linha do tempo', '', '[Eventos](events.jsonl) · [Resultados](results.json)']
    md = '\n'.join(lines)
    (root / 'technical.md').write_text(md)
    from .summary import readable_markdown
    (root / 'writeup.md').write_text(readable_markdown(state))
    from .summary import write_readable
    write_readable(root, state)
    from .analysis import application_map, review
    atomic_json(root / 'map.json', application_map(state))
    atomic_json(root / 'review.json', review(state))
    return checklist, coverage


def archive(root, publication=False, replacements=()):
    """Publication is a separate text-only review copy. Screenshots/raw logs stay private."""
    root = Path(root)
    destination = root / ('publication-review.zip' if publication else 'evidence.zip')
    redactor = Redactor()
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in sorted(root.rglob('*')):
            if not p.is_file() or p.is_symlink() or p.suffix == '.zip' or p.name.startswith('.'):
                continue
            relative = p.relative_to(root)
            if publication:
                if str(relative) not in ('writeup.md', 'report.html'):
                    continue
                text = redactor.text(p.read_text())
                for value in replacements:
                    if value:
                        text = text.replace(value, '[REDACTED]')
                # Link targets are deliberately omitted from this review copy.
                text += '\n\nREVISÃO NECESSÁRIA: evidências originais e screenshots não incluídos. Revise dados pessoais e remova links de evidência antes de publicar.\n'
                z.writestr(str(relative), text)
            else:
                z.write(p, relative)
        if publication:
            z.writestr('LEIA-ME.txt', 'Cópia de revisão textual. Não publicada. Links apontam para evidências omitidas. Revise textos; selecione, sanitize e adicione imagens manualmente. Sanitização automática não é perfeita.')
    return destination
