"""External tool integration with reviewable plans, bounded scoped proxy and provenance."""
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import tempfile
import time
import uuid
from urllib.parse import parse_qsl, urlsplit
from .engine import Engine
from .models import canonical_url, origin
from .intel import IntelStore, safe_url, sanitize
from .storage import atomic_json, now


def dependency(name):
    path=shutil.which(name)
    if not path:raise ValueError(f'{name} não encontrado. Instale a ferramenta para executar; o plano continua disponível.')
    return path


def endpoint_scope(engine,url):
    url=canonical_url(url)
    if not engine.scope.permits_url(url):raise ValueError('URL fora do escopo permitido')
    return url


@asynccontextmanager
async def proxy(engine,origins,output,methods=None,max_requests=100,rate=2,port=0):
    dependency('mitmdump')
    if not 1<=max_requests<=10000 or not 0.1<=rate<=20:raise ValueError('Limites: 1–10000 requisições, 0.1–20 req/s')
    origins=[endpoint_scope(engine,u) for u in origins]
    if not origins:raise ValueError('Informe ao menos uma origem')
    for value in origins:
        p=urlsplit(value)
        if p.path!='/' or p.query:raise ValueError('Origens do proxy: protocolo, host e porta, sem caminho')
    with tempfile.TemporaryDirectory(prefix='penpilot-proxy-') as directory:
        folder=Path(directory);ready=folder/'ready';config=folder/'config.json'
        if not port:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        config.write_text(json.dumps(dict(run=str(engine.root),scope=engine.scope.json(),origins=origins,output=str(output),id=uuid.uuid4().hex,ready=str(ready),meter=str(folder/'meter.json'),methods=methods or ['GET','HEAD','OPTIONS'],max_requests=max_requests,rate=rate,credentials=engine.credentials)))
        config.chmod(0o600)
        output=Path(output);output.parent.mkdir(parents=True,exist_ok=True);output.touch(mode=0o600,exist_ok=True)
        project=Path(__file__).resolve().parent.parent
        argv=['mitmdump','--listen-host','127.0.0.1','--listen-port',str(port),'-q','-s',str(Path(__file__).with_name('proxy_addon.py')),'--set',f'penpilot_config={config}','--set','connection_strategy=lazy','--set','upstream_cert=false','--set',f'confdir={folder / "ca"}','--set','body_size_limit=2m','--set','websocket=false']
        with (folder/'stderr').open('w') as log:
            proc=await asyncio.create_subprocess_exec(*argv,stdout=log,stderr=log,start_new_session=True,env={**os.environ,'PYTHONPATH':str(project)})
            try:
                for _ in range(100):
                    if ready.exists():break
                    if proc.returncode is not None:raise ValueError('mitmdump não iniciou; verifique a instalação e a porta')
                    await asyncio.sleep(.1)
                else:raise ValueError('Timeout ao iniciar mitmdump')
                yield dict(url=f'http://127.0.0.1:{port}',ca=str(folder/'ca/mitmproxy-ca-cert.pem'),meter=str(folder/'meter.json'),process=proc)
            finally:
                if proc.returncode is None:
                    try:os.killpg(proc.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:await asyncio.wait_for(proc.wait(),5)
                    except asyncio.TimeoutError:
                        os.killpg(proc.pid,signal.SIGKILL);await proc.wait()


def validate_template(path):
    import yaml
    path=Path(path).expanduser().resolve()
    if not path.is_file() or path.stat().st_size>512000:raise ValueError('Template local YAML: máximo 500 KiB')
    raw=path.read_bytes();doc=yaml.safe_load(raw)
    if not isinstance(doc,dict) or not isinstance(doc.get('http'),list):raise ValueError('Somente templates HTTP estruturados são suportados')
    if set(doc)-{'id','info','http'}:raise ValueError('Template contém protocolo ou recurso não permitido')
    requests=doc['http']
    if not requests or len(requests)>10:raise ValueError('Template deve conter 1–10 blocos HTTP')
    for req in requests:
        if not isinstance(req,dict) or set(req)-{'method','path','matchers','matchers-condition','extractors','redirects','max-redirects'}:raise ValueError('Use template HTTP simples, sem raw, payloads, código ou workflow')
        if req.get('method','GET') not in ('GET','HEAD'):raise ValueError('Template: somente GET ou HEAD')
        if req.get('redirects'):raise ValueError('Redirecionamentos de template não são permitidos')
        paths=req.get('path',[])
        if not isinstance(paths,list) or not paths or len(paths)>10:raise ValueError('Template: 1–10 caminhos')
        for target in paths:
            if not isinstance(target,str) or not target.startswith('{{BaseURL}}') or '{{' in target.replace('{{BaseURL}}','') or (target[len('{{BaseURL}}'):] and not target[len('{{BaseURL}}'):].startswith(('/', '?'))):
                raise ValueError('Caminhos devem usar {{BaseURL}}, sem variáveis dinâmicas')
    return path,hashlib.sha256(raw).hexdigest()


def plan(engine,tool,url,template=None,parameter=None,max_requests=100,rate=2,timeout=180):
    url=endpoint_scope(engine,url)
    if tool not in ('nuclei','sqlmap'):raise ValueError('Ferramenta inválida')
    if not 1<=max_requests<=10000 or not 0.1<=rate<=20 or not 1<=timeout<=3600:raise ValueError('Limites inválidos')
    result=dict(schema=1,tool=tool,url=safe_url(url),scope=engine.scope.json(),created=now(),max_requests=max_requests,rate=rate,timeout=timeout,network='Proxy local obrigatório: origem exata, DNS fixado, TLS validado e orçamento. Não é sandbox de processo.',status='planned')
    if tool=='nuclei':
        if not template:raise ValueError('--template local explícito é obrigatório')
        path,digest=validate_template(template);result.update(template=str(path),template_sha256=digest)
        argv=['nuclei','-u',url,'-t',str(path),'-pt','http','-dr','-ni','-duc','-jsonl','-omit-raw','-omit-template','-silent','-rl',str(max(1,int(rate))),'-c','1','-bs','1','-timeout','15','-retries','0','-proxy','{proxy}','-proxy-internal']
    else:
        names=[k for k,v in parse_qsl(urlsplit(url).query,keep_blank_values=True)]
        if not parameter or parameter not in names or not re.fullmatch(r'[A-Za-z0-9_.-]+',parameter):raise ValueError('sqlmap requer --parameter presente na query da URL')
        argv=['sqlmap','-u',url,'-p',parameter,'--batch','--level=1','--risk=1','--technique=BE','--threads=1','--timeout=15','--retries=0',f'--delay={1/rate:g}','--ignore-redirects','--disable-precon','--proxy={proxy}','--output-dir={output}','--answers=follow=N','-v','1']
        result['parameter']=parameter
    result['argv']=[safe_url(v) if v==url else v for v in argv]
    result['limitations']='Sem OAST, exploração de escrita, dump de dados, shell ou submissão automática de bounty. Matchers e mensagens exigem reprodução.'
    return result,argv


async def execute_tool(engine,tool,url,**options):
    spec,argv=plan(engine,tool,url,**options);dependency(tool)
    identity=uuid.uuid4().hex[:12];directory=engine.root/'intel'/'jobs'/identity;directory.mkdir(parents=True,mode=0o700)
    atomic_json(directory/'job.json',dict(spec,id=identity,status='running'))
    p=urlsplit(url);base=f'{p.scheme}://{p.netloc}'
    status='completed';returncode=None
    try:
        with tempfile.TemporaryDirectory(prefix='penpilot-scanner-') as temp:
            async with proxy(engine,[base],directory/'traffic.jsonl',max_requests=spec['max_requests'],rate=spec['rate']) as capture:
                args=[a.replace('{proxy}',capture['url']).replace('{output}',temp) for a in argv]
                # Copy the exact reviewed template to prevent changes between plan and process start.
                if tool=='nuclei':
                    template_path=Path(spec['template']);raw=template_path.read_bytes()
                    if hashlib.sha256(raw).hexdigest()!=spec['template_sha256']:raise ValueError('Template mudou durante a preparação')
                    copy=Path(temp)/'template.yaml';copy.write_bytes(raw);args[args.index('-t')+1]=str(copy)
                proc=await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True,env={**os.environ,'NO_PROXY':'','no_proxy':'','SSL_CERT_FILE':capture['ca'],'REQUESTS_CA_BUNDLE':capture['ca'],'NO_COLOR':'1'})
                async def read(stream):
                    lines=[];size=0
                    while True:
                        chunk=await stream.read(4096)
                        if not chunk:break
                        size+=len(chunk)
                        if size>4*1024*1024:raise ValueError('Saída do scanner excedeu 4 MiB')
                        lines.append(chunk)
                    return b''.join(lines).decode(errors='replace')
                tasks=[asyncio.create_task(read(proc.stdout)),asyncio.create_task(read(proc.stderr))]
                try:
                    out,err=await asyncio.wait_for(asyncio.gather(*tasks),spec['timeout']);returncode=await proc.wait()
                    if returncode:status='failed'
                except (TimeoutError,ValueError):
                    status='limited';out=err='Saída interrompida por limite de execução.'
                finally:
                    if proc.returncode is None:
                        try:os.killpg(proc.pid,signal.SIGTERM)
                        except ProcessLookupError:pass
                        try:await asyncio.wait_for(proc.wait(),3)
                        except asyncio.TimeoutError:os.killpg(proc.pid,signal.SIGKILL);await proc.wait()
                    for task in tasks:task.cancel()
                    await asyncio.gather(*tasks,return_exceptions=True)
                meter=json.loads(Path(capture['meter']).read_text())
                if meter['budget_exhausted']:status='limited'
                elif meter['upstream_errors'] and not meter['sent']-meter['upstream_errors']:status='failed'
            store=IntelStore(engine.root);records=[]
            if tool=='nuclei':
                for line in out.splitlines():
                    try:row=json.loads(line)
                    except ValueError:continue
                    if 'template-id' in row and origin(row.get('matched-at',url))==origin(url):
                        records.append(dict(kind='scanner-match',tool=tool,url=safe_url(row.get('matched-at',url)),source='job:'+identity,template=row['template-id'],severity=row.get('info',{}).get('severity','unknown'),confidence='unverified',in_scope=True,evidence=[f'intel/jobs/{identity}/job.json']))
            else:
                # Do not infer confirmation from exit code or text mentioning 'injectable'.
                indicators=[line for line in out.splitlines() if re.search(r'Parameter:|Type:|Title:',line)][:30]
                if indicators:records.append(dict(kind='scanner-match',tool=tool,url=safe_url(url),source='job:'+identity,confidence='unverified',in_scope=True,indicators=sanitize(indicators),evidence=[f'intel/jobs/{identity}/job.json']))
            store.put(records)
            record=dict(spec,id=identity,status=status,returncode=returncode,finished=now(),matches=len(records),raw_output_retained=False,proxy=meter)
            # Only operational error classification, never arbitrary scanner output in agent context.
            if err:record['diagnostic']='Scanner produziu stderr; verifique versão, template e dependências.'
            atomic_json(directory/'job.json',record)
            return record
    except BaseException as ex:
        atomic_json(directory/'job.json',dict(spec,id=identity,status='cancelled' if isinstance(ex,(KeyboardInterrupt,asyncio.CancelledError)) else 'failed',finished=now(),error=type(ex).__name__))
        raise



async def capture(engine,origins,port=8081,max_requests=500,rate=5,allow_writes=False):
    identity=uuid.uuid4().hex[:12];output=engine.root/'intel'/f'capture-{identity}.jsonl'
    methods=['GET','HEAD','OPTIONS']+(['POST','PUT','PATCH','DELETE'] if allow_writes else [])
    async with proxy(engine,origins,output,methods,max_requests,rate,port) as running:
        print(json.dumps(dict(proxy=running['url'],ca=running['ca'],output=str(output),methods=methods,note='Configure apenas o navegador de teste. CA temporária; nenhuma configuração do sistema foi alterada. Ctrl+C encerra.'),ensure_ascii=False),flush=True)
        await running['process'].wait()
