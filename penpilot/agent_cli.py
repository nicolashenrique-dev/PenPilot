"""CLI surfaces for agent context, capture, replay and explicit scanner execution."""
import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit
from .engine import Engine
from .intel import IntelStore


def register(sub,default_output):
    agent=sub.add_parser('agent',help='Contexto compacto e triagem para agentes de IA')
    action=agent.add_subparsers(dest='agent_action',required=True)
    init=action.add_parser('init',help='Criar caso sem iniciar rede ou Nmap')
    init.add_argument('--scope',nargs='+',required=True);init.add_argument('-o','--output',default=str(default_output))
    for name in ('sync','handoff','context','show','mark','import','report'):
        command=action.add_parser(name);command.add_argument('directory')
        if name in ('context','handoff'):command.add_argument('--budget',type=int,default=12000,help='Caracteres, não tokens exatos')
        if name=='context':
            command.add_argument('--cursor',type=int,default=0);command.add_argument('--revision',type=int);command.add_argument('--query',default='')
        if name in ('show','mark'):command.add_argument('identity')
        if name=='mark':
            command.add_argument('--status',choices=['todo','investigating','discarded','validated'],required=True);command.add_argument('--note',default='')
        if name=='import':
            command.add_argument('file');command.add_argument('--format',choices=['har','traffic','mitm','js','openapi','nuclei'],required=True);command.add_argument('--base')
    repeater=sub.add_parser('repeater',help='Repetir uma requisição em escopo e comparar respostas')
    repeater.add_argument('directory');repeater.add_argument('--url');repeater.add_argument('--request',help='Arquivo HTTP GET ou cURL; nunca executado como shell')
    repeater.add_argument('--scheme',choices=['http','https'],default='https');repeater.add_argument('--method',default='GET')
    repeater.add_argument('--set-query',action='append',default=[]);repeater.add_argument('--header',action='append',default=[])
    repeater.add_argument('--body-file');repeater.add_argument('--allow-writes',action='store_true');repeater.add_argument('--compare')
    repeater.add_argument('--execute',action='store_true',help='Enviar a requisição; sem esta opção, mostrar plano')
    tools=sub.add_parser('tools',help='Planos e execução controlada de Nuclei/sqlmap')
    tools.add_argument('directory');tools.add_argument('tool',choices=['nuclei','sqlmap']);tools.add_argument('--url',required=True)
    tools.add_argument('--template');tools.add_argument('--parameter');tools.add_argument('--max-requests',type=int,default=100)
    tools.add_argument('--rate',type=float,default=2);tools.add_argument('--timeout',type=int,default=180);tools.add_argument('--execute',action='store_true')
    capture=sub.add_parser('capture',help='Proxy mitmproxy local com captura estruturada e escopo')
    capture.add_argument('directory');capture.add_argument('--origins',nargs='+',required=True);capture.add_argument('--port',type=int,default=8081)
    capture.add_argument('--max-requests',type=int,default=500);capture.add_argument('--rate',type=float,default=5);capture.add_argument('--allow-writes',action='store_true')
    return repeater,tools,capture


def dispatch(args,credentials):
    if args.command=='agent':
        if args.agent_action=='init':
            # Offline case: no DNS or discovery. Scope is explicitly provided by operator.
            import uuid
            from .models import Scope,Profile
            from .storage import atomic_json,now
            scope=Scope(args.scope);root=Path(args.output).expanduser().resolve()/('case-'+uuid.uuid4().hex[:12]);root.mkdir(parents=True,mode=0o700)
            profile=Profile.build('quick');(root/'wordlist.txt').write_bytes(Path(profile.wordlist).read_bytes());profile.wordlist=str(root/'wordlist.txt')
            for child in ('logs','commands','hosts'):(root/child).mkdir()
            state=dict(schema=1,id=root.name,created=now(),updated=now(),status='completed',targets=scope.allowed,input_urls=[],profile=profile.json(),scope=scope.json(),nodes=[],tasks=[],findings=[],events=[],limits=[],requests={},auth_required=[])
            atomic_json(root/'state.json',state);atomic_json(root/'manifest.json',dict(kind='offline-case',tools={}))
            return dict(directory=str(root),network_started=False)
        store=IntelStore(args.directory)
        if args.agent_action=='import':return store.ingest(args.file,args.format,args.base)
        if args.agent_action=='sync':return store.sync()
        if args.agent_action=='report':return store.report()
        if args.agent_action=='context':return store.context(args.budget,args.cursor,args.query,args.revision)
        if args.agent_action=='handoff':return store.handoff(args.budget)
        if args.agent_action=='show':return store.detail(args.identity)
        if args.agent_action=='mark':return store.decision(args.identity,args.status,args.note)
    engine=Engine.load(args.directory,credentials(args))
    if args.command=='repeater':
        from .auth import import_request
        from .repeater import prepare,repeat
        from .intel import safe_url
        url=args.url
        if args.request:
            file=Path(args.request).expanduser()
            if file.stat().st_size>65536:raise ValueError('Requisição excede 64 KiB')
            imported=import_request(file.read_text(),args.scheme);url=url or imported['url']
            if imported['session']:
                engine.credentials['http']=imported['session']
                from .storage import Redactor
                engine.redactor=Redactor(engine.credentials)
        if not url:raise ValueError('Informe --url ou --request')
        if args.body_file and Path(args.body_file).stat().st_size>1024*1024:raise ValueError('Corpo excede 1 MiB')
        body=Path(args.body_file).read_bytes() if args.body_file else None
        options=dict(method=args.method,query=args.set_query,headers=args.header,body=body,allow_writes=args.allow_writes)
        if not args.execute:
            effective,method,headers=prepare(engine,url,**options)
            return dict(status='planned',url=safe_url(effective),method=method,headers=list(headers),body_bytes=len(body or b''),network_sent=False)
        return asyncio.run(repeat(engine,url,compare=args.compare,**options))
    if args.command=='tools':
        from .tooling import plan,execute_tool
        options=dict(template=args.template,parameter=args.parameter,max_requests=args.max_requests,rate=args.rate,timeout=args.timeout)
        return asyncio.run(execute_tool(engine,args.tool,args.url,**options)) if args.execute else plan(engine,args.tool,args.url,**options)[0]
    if args.command=='capture':
        from .tooling import capture
        try:asyncio.run(capture(engine,args.origins,args.port,args.max_requests,args.rate,args.allow_writes))
        except KeyboardInterrupt:pass
        return dict(status='stopped')
