from __future__ import annotations
import asyncio
import json
import secrets
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .engine import Engine, doctor
from .models import Profile
from .plugins import REGISTRY
from .storage import archive
from .paths import default_output
from .summary import summarize, readable_report, write_readable

STATIC = Path(__file__).parent / 'static'


def create_app(output=None, initial=None, port=8765):
    root = Path(output or default_output()).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    engines, jobs = {}, {}
    from .monitor import MonitorStore
    monitors = MonitorStore(root)
    from .workspace import Workspace
    workspace = Workspace(root)
    token = secrets.token_urlsafe(32)
    if initial:
        engine = Engine.load(initial)
        from .storage import reports
        reports(engine.root, engine.redactor.obj(engine.state))
        engines[engine.state['id']] = engine

    @asynccontextmanager
    async def lifespan(app):
        # One scheduler owns each output directory, including across panel ports.
        import fcntl
        lock_file=(root/'.panel.lock').open('a')
        try:
            fcntl.flock(lock_file,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            lock_file.close()
            raise ValueError('Já existe um painel usando esta pasta de histórico. Abra o painel existente ou use outra pasta.')
        monitor_job = asyncio.create_task(monitors.serve())
        try:
            yield
        finally:
            monitors.stopped.set()
            if monitors.active_engine:
                monitors.active_engine.stop_requested = True
            for engine in engines.values():
                engine.stop_requested = True
            try:
                await monitor_job
                if jobs:
                    await asyncio.gather(*jobs.values(), return_exceptions=True)
            finally:
                fcntl.flock(lock_file,fcntl.LOCK_UN)
                lock_file.close()

    app = FastAPI(title='PenPilot', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.engines, app.state.jobs = engines, jobs
    app.state.monitors = monitors

    @app.middleware('http')
    async def boundary(request, call_next):
        host = request.headers.get('host', '')
        allowed_hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
        if host not in allowed_hosts:
            return JSONResponse({'detail': 'Host inválido'}, status_code=403)
        if request.method not in ('GET', 'HEAD'):
            if request.headers.get('x-penpilot-token') != token:
                return JSONResponse({'detail': 'Token local inválido'}, status_code=403)
            origin = request.headers.get('origin')
            if origin and origin not in {f'http://127.0.0.1:{port}', f'http://localhost:{port}'}:
                return JSONResponse({'detail': 'Origem inválida'}, status_code=403)
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({'detail': str(exc)}, status_code=400)

    def get(run):
        if run in engines:
            return engines[run]
        if '/' in run or '\\' in run or run.startswith('.'):
            raise HTTPException(404, 'Execução não encontrada')
        path = (root / run).resolve()
        if not path.is_relative_to(root) or not (path / 'state.json').exists():
            raise HTTPException(404, 'Execução não encontrada')
        engines[run] = Engine.load(path)
        from .storage import reports
        reports(engines[run].root, engines[run].redactor.obj(engines[run].state))
        return engines[run]

    def start(engine, resume=False):
        key = engine.state['id']
        if key in jobs and not jobs[key].done():
            return
        async def runner():
            try:
                await engine.run(resume=resume)
            except Exception as ex:
                engine.event('failed', str(ex))
        jobs[key] = asyncio.create_task(runner())

    @app.get('/', response_class=HTMLResponse)
    async def index():
        return (STATIC / 'index.html').read_text().replace('__TOKEN__', token)

    @app.get('/api/config')
    async def config():
        return dict(output_directory=str(root), profiles={name: Profile.build(name).json() for name in ('quick', 'standard', 'full', 'custom')}, plugins=[{k: v for k, v in asdict(p).items() if k != 'run'} for p in REGISTRY.values()], initial=next(iter(engines), None))

    @app.get('/api/doctor')
    async def diagnostics():
        return await asyncio.to_thread(doctor)

    @app.get('/api/runs')
    async def runs():
        result = {}
        for p in root.glob('*/state.json'):
            if p.is_symlink():
                continue
            try:
                s = json.loads(p.read_text())
                result[s['id']] = {k: s[k] for k in ('id', 'targets', 'created', 'status')}
            except (ValueError, KeyError, OSError):
                continue
        for e in engines.values():
            result[e.state['id']] = {k: e.state[k] for k in ('id', 'targets', 'created', 'status')}
        return sorted([dict(r, **workspace.data['runs'].get(r['id'], {})) for r in result.values()], key=lambda r: r['created'], reverse=True)

    def parse(data):
        values = dict(data.get('profile') or {})
        profile = Profile.build(**values)
        targets = data.get('targets', [])
        if not isinstance(targets, list) or not targets or not all(isinstance(t, str) for t in targets):
            raise ValueError('Informe ao menos um alvo')
        return profile, targets

    @app.post('/api/preflight')
    async def preflight(request: Request):
        from .preflight import inspect
        data=await request.json();p,targets=parse(data)
        return await asyncio.to_thread(inspect,targets,p,data.get('allowed'),data.get('excluded',[]),data.get('credentials'))

    @app.post('/api/session/import')
    async def session_import(request: Request):
        from .auth import import_request
        data=await request.json()
        return import_request(data.get('text',''),data.get('scheme','https'))

    @app.get('/api/projects')
    async def projects():
        return workspace.data['projects']

    @app.post('/api/projects')
    async def save_project(request: Request):
        return workspace.project(await request.json())

    @app.post('/api/runs/{run}/metadata')
    async def metadata(run: str, request: Request):
        e=get(run);data=await request.json()
        if data.get('archived') and (e.running or e.state['status']=='running'):
            raise ValueError('Encerre a execução antes de arquivar')
        return workspace.metadata(run,data)

    @app.post('/api/preview')
    async def preview(request: Request):
        data = await request.json()
        p, targets = parse(data)
        return dict(profile=p.json(), targets=targets, allowed=data.get('allowed') or targets, excluded=data.get('excluded', []), phases=['Descoberta Nmap', 'Confirmação de protocolos inconclusivos', 'Enumeração condicional: '+', '.join(p.modules)], expansion=f'Cascata: níveis 0–{p.directory_depth}; crawler: 0–{p.crawl_depth}; até {p.max_tasks} tarefas e {p.max_requests} requisições HTTP/host', note='Prévia não confirma serviços nem acessibilidade. Um processo por host; orçamento de pacotes Nmap não equivale a requisições HTTP.')

    @app.post('/api/runs')
    async def create(request: Request):
        data = await request.json()
        p, targets = parse(data)
        # DNS and doctor are blocking; do them outside the server's event loop.
        engine = await asyncio.to_thread(Engine.create, root, targets, p, data.get('allowed') or targets, data.get('excluded', []), data.get('credentials'))
        engines[engine.state['id']] = engine
        start(engine)
        return {'id': engine.state['id']}

    @app.get('/api/runs/{run}')
    async def state(run: str):
        e = get(run)
        from .analysis import next_steps
        from .preflight import session_hint
        return e.redactor.obj(dict(e.state, session_status=session_hint(e.credentials), output_directory=str(e.root), summary=summarize(e.state), auth_ready=list(e.credentials), metadata=workspace.data['runs'].get(run, {}), next_steps=next_steps(e.state)))

    @app.get('/api/runs/{run}/report', response_class=HTMLResponse)
    async def report(run: str):
        e = get(run)
        # Render from structured state, never serve collected HTML as active content.
        return readable_report(e.redactor.obj(e.state)).replace('href="hosts/', f'href="/api/runs/{run}/files/hosts/')

    @app.post('/api/runs/{run}/cancel')
    async def cancel(run: str, request: Request):
        data = await request.json()
        get(run).cancel(data.get('node'))
        return {'ok': True}

    @app.post('/api/runs/{run}/resume')
    async def resume(run: str, request: Request):
        e = get(run)
        data = await request.json()
        if data.get('credentials'):
            from .storage import Redactor
            from .auth import validate
            from .models import origin as url_origin
            proposed = validate(data['credentials'])
            if proposed.get('http'):
                e.scope.resolve(url_origin(proposed['http']['origin'])[1])
                if proposed['http'].get('storage_origin'):
                    e.scope.resolve(url_origin(proposed['http']['storage_origin'])[1])
            e.credentials = {**e.credentials, **proposed}
            e.baselines = {}
            e.state['auth_required'] = sorted(set(e.state.get('auth_required', [])) | set(proposed))
            e.redactor = Redactor(e.credentials)
        start(e, resume=True)
        return {'ok': True}

    @app.post('/api/runs/{run}/repeat')
    async def repeat(run: str, request: Request):
        data = await request.json()
        e = get(run)
        try:
            task = e.repeat(data['node'], data.get('deepen', False))
        except (KeyError, StopIteration):
            raise HTTPException(404, 'Nó não encontrado')
        start(e)
        return {'task': task}

    @app.post('/api/runs/{run}/finding/{finding}')
    async def annotate(run: str, finding: str, request: Request):
        e = get(run)
        f = next((f for f in e.state['findings'] if f['id'] == finding), None)
        if not f:
            raise HTTPException(404, 'Achado não encontrado')
        data = await request.json()
        if 'note' in data:
            f['note'] = e.redactor.text(str(data['note'])[:10000])
        if 'selected' in data:
            f['selected'] = bool(data['selected'])
        if data.get('marker') in ('investigate', 'relevant', 'discarded'):
            f['marker'] = data['marker']
        e.checkpoint()
        return f

    @app.post('/api/runs/{run}/export')
    async def export(run: str, request: Request):
        data = await request.json()
        e = get(run)
        e.checkpoint()
        # Snapshot writes run synchronously, so a task cannot mutate halfway through ZIP creation.
        path = archive(e.root, bool(data.get('publication')), data.get('redact', []))
        return {'url': f'/api/runs/{run}/files/{path.name}'}


    @app.get('/api/runs/{run}/analysis')
    async def analysis(run: str):
        from .analysis import application_map, review
        e=get(run)
        return e.redactor.obj(dict(map=application_map(e.state),review=review(e.state)))

    @app.get('/api/runs/{run}/compare/{previous}')
    async def comparison(run: str,previous: str):
        from .analysis import compare
        from .analysis import visual_comparison
        before,after=get(previous),get(run)
        return after.redactor.obj(dict(compare(before.state,after.state),captures=visual_comparison(before.state,after.state)))

    @app.post('/api/runs/{run}/burp')
    async def burp(run: str):
        from .analysis import burp_archive
        e=get(run);path=burp_archive(e.root,e.redactor.obj(e.state))
        return dict(url=f'/api/runs/{run}/files/{path.name}')

    @app.get('/api/runs/{run}/agent')
    async def agent_context(run: str,budget: int=12000,cursor: int=0,query: str='',revision: int | None=None):
        from .intel import IntelStore
        return IntelStore(get(run).root).context(budget,cursor,query,revision)

    @app.post('/api/runs/{run}/agent/sync')
    async def agent_sync(run: str):
        from .intel import IntelStore
        return await asyncio.to_thread(IntelStore(get(run).root).sync)

    @app.get('/api/runs/{run}/agent/record/{identity}')
    async def agent_detail(run: str,identity: str):
        from .intel import IntelStore
        return IntelStore(get(run).root).detail(identity)

    @app.post('/api/runs/{run}/agent/record/{identity}')
    async def agent_mark(run: str,identity: str,request: Request):
        from .intel import IntelStore
        data=await request.json()
        return IntelStore(get(run).root).decision(identity,data.get('status'),data.get('note',''))

    @app.post('/api/runs/{run}/agent/handoff')
    async def agent_handoff(run: str):
        from .intel import IntelStore
        result=await asyncio.to_thread(IntelStore(get(run).root).handoff)
        return dict(result,url=f'/api/runs/{run}/files/intel/agent-context.json',guide_url=f'/api/runs/{run}/files/intel/HANDOFF.md')

    @app.post('/api/runs/{run}/agent/import')
    async def agent_import(run: str,request: Request):
        import tempfile
        from .intel import IntelStore
        data=await request.json();text=data.get('text','')
        if not isinstance(text,str) or len(text.encode())>2*1024*1024:raise ValueError('Importação web: máximo 2 MiB; use CLI para arquivos maiores')
        with tempfile.TemporaryDirectory(prefix='penpilot-import-') as directory:
            path=Path(directory)/'input';path.write_text(text)
            return await asyncio.to_thread(IntelStore(get(run).root).ingest,path,data.get('format'),data.get('base'))

    @app.get('/api/monitors')
    async def monitor_list():
        return monitors.items

    @app.post('/api/monitors')
    async def monitor_create(request: Request):
        data=await request.json()
        return monitors.create(get(str(data.get('template',''))),data.get('interval',3600))

    @app.post('/api/monitors/{identity}')
    async def monitor_toggle(identity: str,request: Request):
        data=await request.json()
        return monitors.toggle(identity,data.get('active'))

    @app.get('/api/runs/{run}/files/{path:path}')
    async def files(run: str, path: str):
        e = get(run)
        full = (e.root / path).resolve()
        if not full.is_relative_to(e.root) or not full.is_file() or any(p.startswith('.') for p in Path(path).parts):
            raise HTTPException(404, 'Arquivo indisponível')
        if full.suffix == '.png':
            return FileResponse(full, media_type='image/png')
        if full.suffix == '.zip':
            return FileResponse(full, filename=full.name, media_type='application/zip')
        # Evidence never renders as active HTML, even if it comes from a hostile server.
        return FileResponse(full, media_type='text/plain; charset=utf-8')

    app.mount('/static', StaticFiles(directory=STATIC), name='static')
    return app
