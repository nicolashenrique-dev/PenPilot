"""Ephemeral credentials scoped to a single explicit HTTP origin."""
from .models import canonical_url, origin
from urllib.parse import urlsplit


def validate(credentials):
    credentials = credentials or {}
    if not isinstance(credentials, dict):
        raise ValueError('Credenciais devem ser um objeto')
    for key, value in credentials.items():
        if key not in ('http', 'smb', 'ftp') or not isinstance(value, dict):
            raise ValueError('Contexto de autenticação inválido')
    auth = credentials.get('http', {})
    if auth:
        allowed = {'origin', 'token', 'cookie', 'storage', 'storage_origin'}
        if set(auth) - allowed or not all(isinstance(v, str) for k,v in auth.items() if k!='storage'):
            raise ValueError('Autenticação web: use origin, token e cookie')
        if 'storage' in auth and (not isinstance(auth['storage'],dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in auth['storage'].items())):
            raise ValueError('storage deve mapear chaves para strings de localStorage')
        url = canonical_url(auth.get('origin', ''))
        p = urlsplit(url)
        if p.path != '/' or p.query:
            raise ValueError('Origem da sessão deve conter apenas protocolo, host e porta')
        if not auth.get('token') and not auth.get('cookie') and not auth.get('storage'):
            raise ValueError('Informe token ou cookie da sessão')
        if any('\r' in v or '\n' in v for v in auth.values() if isinstance(v,str)):
            raise ValueError('Credenciais não podem conter quebras de linha')
        if auth.get('storage_origin'):
            sp=urlsplit(canonical_url(auth['storage_origin']))
            if sp.path!='/' or sp.query:
                raise ValueError('storage_origin deve ser uma origem exata')
        if len(str(auth)) > 65536:
            raise ValueError('Credenciais excedem o limite')
    return credentials


def headers(credentials, url):
    auth = credentials.get('http', {})
    if not auth or origin(auth['origin']) != origin(url):
        return {}
    result = {}
    if auth.get('token'):
        result['Authorization'] = 'Bearer ' + auth['token'].removeprefix('Bearer ').strip()
    if auth.get('cookie'):
        result['Cookie'] = auth['cookie']
    return result


def import_request(text, scheme='https'):
    """Parse, never execute, a raw request or a small explicit subset of cURL."""
    import shlex
    from urllib.parse import urlunsplit
    if not isinstance(text,str) or len(text)>65536: raise ValueError('Requisição: máximo 64 KiB')
    if scheme not in ('http','https'):raise ValueError('Protocolo inválido')
    headers_={}; method='GET';url=None
    def header(line):
        if ':' not in line: raise ValueError('Cabeçalho inválido')
        k,v=line.split(':',1);k=k.strip().lower();v=v.strip()
        if k in ('authorization','cookie','host') and k in headers_:raise ValueError('Cabeçalho duplicado: '+k)
        headers_[k]=v
    text=text.strip()
    if not text:raise ValueError('Cole uma requisição GET ou cURL')
    if text.startswith('curl '):
        words=shlex.split(text.replace('\\\n',''))
        i=1
        while i<len(words):
            word=words[i]
            if word in ('-H','--header','-b','--cookie','-X','--request','--url'):
                i+=1
                if i>=len(words):raise ValueError('Opção cURL sem valor')
                value=words[i]
                if word in ('-H','--header'):header(value)
                elif word in ('-b','--cookie'):
                    if '=' not in value or value.startswith('@'):raise ValueError('Use Cookie literal; arquivos não são lidos')
                    header('Cookie: '+value)
                elif word in ('-X','--request'):method=value.upper()
                else:url=value
            elif word in ('--compressed','--http2','--http1.1','-s','--silent'):pass
            elif word.startswith(('http://','https://')):
                if url:raise ValueError('Importe uma URL por vez')
                url=word
            else:raise ValueError('Opção cURL não suportada. Importe somente URL e cabeçalhos, sem corpo ou comandos adicionais.')
            i+=1
    else:
        normalized=text.replace('\r\n','\n')
        if '\n\n' in normalized and normalized.split('\n\n',1)[1].strip():
            raise ValueError('Importe somente cabeçalhos, sem corpo de requisição')
        lines=normalized.splitlines();parts=lines[0].split()
        if len(parts)!=3 or not parts[2].startswith('HTTP/'):raise ValueError('Use uma requisição HTTP completa ou Copy as cURL')
        method,path,_=parts
        for line in lines[1:]:
            if not line.strip():break
            header(line)
        if path.startswith(('http://','https://')):url=path
        else:
            if not path.startswith('/') or path.startswith('//') or not headers_.get('host'):raise ValueError('Informe Host e caminho absoluto')
            url=scheme+'://'+headers_['host']+path
    if method!='GET':raise ValueError('Importe uma requisição GET; ações de escrita não são reproduzidas')
    url=canonical_url(url or '')
    p=urlsplit(url);auth={'origin':urlunsplit((p.scheme,p.netloc,'','',''))}
    authorization=headers_.get('authorization','')
    if authorization:
        if not authorization.lower().startswith('bearer '):raise ValueError('Authorization: somente Bearer é suportado')
        auth['token']=authorization[7:].strip()
    if headers_.get('cookie'):auth['cookie']=headers_['cookie']
    credentials=validate({'http':auth}) if len(auth)>1 else {}
    return dict(url=url,session=credentials.get('http'),message='URL e sessão extraídas. Outros cabeçalhos foram ignorados. Nada foi executado.')
