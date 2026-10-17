"""One scoped request at a time; compare structured responses without raw secrets."""
import hashlib
import json
from pathlib import Path
import time
import uuid
from urllib.parse import parse_qsl,urlencode,urlsplit,urlunsplit
import httpx
from .auth import headers as auth_headers
from .intel import IntelStore, safe_url, SAFE_HEADERS
from .storage import atomic_json,now
from .tooling import endpoint_scope
from .models import origin


def prepare(engine,url,method='GET',query=(),headers=(),body=None,allow_writes=False):
    url=endpoint_scope(engine,url);method=method.upper()
    if method not in ('GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE'):raise ValueError('Método não suportado')
    if method not in ('GET','HEAD','OPTIONS') and not allow_writes:raise ValueError('Métodos de escrita requerem --allow-writes explícito')
    if body is not None and method in ('GET','HEAD'):raise ValueError('GET/HEAD não aceitam corpo neste Repeater')
    p=urlsplit(url);pairs=parse_qsl(p.query,keep_blank_values=True)
    for value in query:
        if '=' not in value:raise ValueError('--set-query requer nome=valor')
        key,val=value.split('=',1);pairs=[(k,v) for k,v in pairs if k!=key]+[(key,val)]
    url=urlunsplit((p.scheme,p.netloc,p.path,urlencode(pairs),''))
    outgoing={}
    for value in headers:
        if ':' not in value or '\r' in value or '\n' in value:raise ValueError('Cabeçalho inválido')
        key,val=value.split(':',1)
        if key.lower().strip() in ('host','authorization','cookie','proxy-authorization','content-length','transfer-encoding','connection'):raise ValueError('Use configuração de sessão para credenciais; cabeçalhos de transporte não são alteráveis')
        outgoing[key.strip()]=val.strip()
    if body and len(body)>1024*1024:raise ValueError('Corpo excede 1 MiB')
    return url,method,outgoing


async def repeat(engine,url,method='GET',query=(),headers=(),body=None,allow_writes=False,compare=None):
    url,method,outgoing=prepare(engine,url,method,query,headers,body,allow_writes)
    p=urlsplit(url);ip=engine.scope.resolve(p.hostname)[0];authority=f'[{ip}]' if ':' in ip else ip
    target=urlunsplit((p.scheme,f'{authority}:{origin(url)[2]}',p.path,p.query,''))
    outgoing.update(auth_headers(engine.credentials,url));outgoing['Host']=p.netloc
    started=time.monotonic()
    async with httpx.AsyncClient(timeout=engine.profile.timeout,verify=not engine.profile.insecure_tls,trust_env=False,follow_redirects=False) as client:
        async with client.stream(method,target,headers=outgoing,content=body,extensions={'sni_hostname':p.hostname.encode()}) as response:
            chunks=[];size=0
            async for chunk in response.aiter_bytes():
                size+=len(chunk)
                if size>2*1024*1024:raise ValueError('Resposta excede 2 MiB')
                chunks.append(chunk)
            raw=b''.join(chunks)
            shape={}
            try:
                value=json.loads(raw)
                if isinstance(value,dict):shape={'keys':sorted(value)[:100]}
                elif isinstance(value,list):shape={'array_length':len(value)}
            except (ValueError,UnicodeDecodeError):pass
            result=dict(id=uuid.uuid4().hex[:12],created=now(),url=safe_url(url),method=method,status=response.status_code,bytes=len(raw),body_sha256=hashlib.sha256(raw).hexdigest(),elapsed_ms=round((time.monotonic()-started)*1000),response_headers={k:v for k,v in response.headers.items() if k in SAFE_HEADERS},json_shape=shape,authenticated=bool(auth_headers(engine.credentials,url)),raw_body_retained=False)
    directory=engine.root/'intel'/'repeater';directory.mkdir(parents=True,exist_ok=True)
    if compare:
        if not __import__('re').fullmatch(r'[a-f0-9]{12}',compare):raise ValueError('ID de comparação inválido')
        path=directory/(compare+'.json')
        if not path.exists():raise ValueError('Repetição anterior não encontrada')
        previous=json.loads(path.read_text())
        fields=('status','bytes','body_sha256','json_shape','response_headers')
        result['comparison']=dict(before=compare,changes={k:dict(before=previous.get(k),after=result.get(k)) for k in fields if previous.get(k)!=result.get(k)},note='Diferença de resposta não comprova vulnerabilidade; controle sessão, dados e estado.')
    result=engine.redactor.obj(result)
    atomic_json(directory/(result['id']+'.json'),result)
    store=IntelStore(engine.root)
    store.put([store.endpoint(url,'repeater:'+result['id'],method,True,result['status'],body_sha256=result['body_sha256'],evidence=[f'intel/repeater/{result["id"]}.json'])])
    return result
