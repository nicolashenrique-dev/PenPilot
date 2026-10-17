"""Non-invasive validation: DNS, local dependencies and offline session hints."""
import base64
import json
import time
from .auth import validate
from .models import Scope, origin
from .engine import doctor


def session_hint(credentials):
    auth=validate(credentials).get('http')
    if not auth: return dict(level='info',message='Coleta sem sessão autenticada.')
    token=auth.get('token','').removeprefix('Bearer ').strip()
    try:
        payload=token.split('.')[1]
        claims=json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))
        exp=claims.get('exp') if isinstance(claims,dict) else None
        if isinstance(exp,(int,float)):
            remaining=exp-time.time()
            if remaining<=0:return dict(level='error',message='O JWT informa validade expirada. Importe uma sessão atual.')
            if remaining<300:return dict(level='warning',message='O JWT informa menos de 5 minutos de validade. Renove antes da coleta.')
    except (ValueError,IndexError,TypeError):pass
    return dict(level='info',message='Sessão configurada. Validade e permissões só serão conhecidas pelas respostas; o JWT não foi verificado criptograficamente.')


def inspect(targets, profile, allowed=None, excluded=(), credentials=None):
    checks=[]
    def add(level,title,message):checks.append(dict(level=level,title=title,message=message))
    try:
        scope=Scope(allowed or targets,excluded)
        hosts=scope.targets(targets)
        for host in hosts:add('ok',host,'DNS / escopo: '+', '.join(scope.pins[host]))
        auth=validate(credentials).get('http',{})
        for value in profile.browser_origins+[auth[k] for k in ('origin','storage_origin') if auth.get(k)]:
            scope.resolve(origin(value)[1])
        add('ok','Escopo','Alvos e origens adicionais permitidos pelas regras informadas.')
    except (ValueError,OSError) as ex:add('error','Alvos e escopo',str(ex))
    tools=doctor()
    required=['nmap']
    if 'screenshot' in profile.modules:required.append('playwright')
    if 'smb' in profile.modules:required.append('smbclient')
    if 'content' in profile.modules and profile.content_engine=='ffuf':required.append('ffuf')
    for name in required:
        available=tools.get(name,{}).get('available',False)
        if name=='playwright' and available:
            import shutil
            if not (shutil.which('chromium') or shutil.which('google-chrome')):
                from pathlib import Path
                try:
                    from playwright.sync_api import sync_playwright
                    with sync_playwright() as browser:
                        available=Path(browser.chromium.executable_path).is_file()
                except Exception:
                    available=False
        add('ok' if available else ('error' if name=='nmap' and not any('://' in t for t in targets) else 'warning'),name,'Disponível.' if available else 'Ausente. '+tools.get(name,{}).get('install','Verifique o diagnóstico local.'))
    hint=session_hint(credentials)
    add(hint['level'],'Sessão',hint['message'])
    return dict(ready=not any(c['level']=='error' for c in checks),checks=checks,note='Consulta DNS e dependências locais. Não envia credenciais ao alvo nem comprova acesso à aplicação.')
