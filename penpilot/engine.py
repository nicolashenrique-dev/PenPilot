from __future__ import annotations
import asyncio
import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
import uuid
from pathlib import Path

from .models import Profile, Scope, uid, canonical_url, origin
from .storage import Redactor, atomic_json, now, reports


class TaskError(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status


TOOLS = {'mitmdump': ['--version'], 'nuclei': ['-version'], 'sqlmap': ['--version'], 'nmap': ['--version'], 'ffuf': ['-V'], 'gobuster': ['--version'], 'smbclient': ['--version'], 'gowitness': ['version'], 'enum4linux-ng': ['--help']}


def doctor():
    result = {}
    for tool, args in TOOLS.items():
        path = shutil.which(tool)
        version = None
        if path:
            try:
                p = subprocess.run([path, *args], capture_output=True, text=True, timeout=5)
                version = (p.stdout or p.stderr).strip().split('\n')[0][:200]
            except (OSError, subprocess.TimeoutExpired):
                version = 'Não foi possível consultar versão'
        result[tool] = dict(available=bool(path), path=path, version=version, install=f'sudo apt install {tool}' if tool in ('nmap', 'ffuf', 'gobuster', 'smbclient') else 'Consulte a documentação oficial (opcional, sem adaptador ativo no MVP)')
    try:
        import importlib.metadata
        from playwright._impl._driver import compute_driver_executable
        node, cli = compute_driver_executable()
        available = Path(node).is_file() and Path(cli).is_file()
        browser = shutil.which('chromium') or shutil.which('google-chrome')
        result['playwright'] = dict(available=available, path=str(cli), version=importlib.metadata.version('playwright'), browser=browser or 'Chromium gerenciado será verificado ao executar', install='pip install "penpilot[screenshots]" && python -m playwright install chromium')
    except (ImportError, OSError):
        result['playwright'] = dict(available=False, path=None, version=None, install='pip install "penpilot[screenshots]" && python -m playwright install chromium')
    return result


class Engine:
    def __init__(self, root, state, credentials=None):
        self.root = Path(root).resolve()
        self.state = state
        self.profile = Profile.build(**state['profile'])
        self.scope = Scope(**state['scope'])
        from .auth import validate
        self.credentials = validate(credentials)
        self.baselines = {}
        if self.credentials.get('http'):
            self.scope.resolve(origin(self.credentials['http']['origin'])[1])
            if self.credentials['http'].get('storage_origin'):
                self.scope.resolve(origin(self.credentials['http']['storage_origin'])[1])
        self.redactor = Redactor(self.credentials)
        self.running = False
        self.stop_requested = False
        self.active = {}
        self.host_locks = {}
        self.last_request = {}
        self.rate_locks = {}
        self.deadline = float('inf')
        self._lockfile = None

    @classmethod
    def create(cls, output, targets, profile=None, allowed=None, excluded=(), credentials=None):
        from .auth import validate
        credentials = validate(credentials)
        profile = profile or Profile.build()
        urls = list(dict.fromkeys(canonical_url(t.strip()) for t in targets if "://" in t))
        scope = Scope(allowed or targets, excluded)
        targets = scope.targets(targets)
        urls = [url for url in urls if origin(url)[1] in targets]
        if urls:
            ports = profile.ports.split(',')
            for url in urls:
                port = origin(url)[2]
                if not any(int(part.split('-')[0]) <= port <= int(part.split('-')[-1]) for part in ports):
                    ports.append(str(port))
            profile = Profile.build(**{**profile.json(), 'ports': ','.join(ports)})
        run_id = time.strftime('%Y-%m-%d_%H%M%S') + '_' + uuid.uuid4().hex[:8]
        root = Path(output).resolve() / run_id
        root.mkdir(parents=True, mode=0o700)
        for d in ('commands', 'logs', 'hosts'):
            (root / d).mkdir()
        state = dict(schema=1, id=run_id, created=now(), updated=now(), status='pending', targets=targets, input_urls=urls, profile=profile.json(), scope=scope.json(), nodes=[], tasks=[], findings=[], requests={}, events=[], limits=[], auth_required=list((credentials or {}).keys()))
        e = cls(root, state, credentials)
        for target in targets:
            node = e.node('host', target, None, host=target, source='scope')
            e.enqueue('discovery', node['id'])
        wordlist = Path(profile.wordlist).read_bytes()
        # Copy the effective list to make later resumes independent of its original location.
        (root / 'wordlist.txt').write_bytes(wordlist)
        e.profile.wordlist = str(root / 'wordlist.txt')
        state['profile'] = e.profile.json()
        atomic_json(root / 'manifest.json', dict(id=run_id, created=state['created'], profile=e.profile.json(), scope=scope.json(), tools=doctor(), wordlist_sha256=hashlib.sha256(wordlist).hexdigest(), original_wordlist=str(profile.wordlist), auth_contexts=state['auth_required']))
        e.event('created', 'Execução criada; módulos aguardam confirmação de protocolo')
        e.checkpoint()
        return e

    @classmethod
    def load(cls, root, credentials=None):
        root = Path(root).resolve()
        state = json.loads((root / 'state.json').read_text())
        if state.get('schema') != 1:
            raise ValueError('Versão de estado não suportada')
        from .web_summary import hydrate_fingerprints
        hydrate_fingerprints(root, state)
        state['profile']['wordlist'] = str(root / 'wordlist.txt')
        return cls(root, state, credentials)

    def event(self, kind, message, **data):
        event = self.redactor.obj(dict(time=now(), kind=kind, message=message, **data))
        self.state['events'].append(event)
        self.state['events'] = self.state['events'][-300:]
        with (self.root / 'events.jsonl').open('a') as f:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')
        with (self.root / 'session.log').open('a') as f:
            f.write(f"{event['time']} [{kind}] {event['message']}\n")

    def checkpoint(self):
        self.state['updated'] = now()
        self.state['scope'] = self.scope.json()
        safe = self.redactor.obj(self.state)
        atomic_json(self.root / 'scope.json', safe['scope'])
        atomic_json(self.root / 'results.json', dict(nodes=safe['nodes'], findings=safe['findings']))
        checklist, coverage = reports(self.root, safe)
        self.state['checklist'], self.state['coverage'] = checklist, coverage
        atomic_json(self.root / 'state.json', self.redactor.obj(self.state))

    def node(self, kind, label, parent, **data):
        if kind == 'url' and parent and 'ip' not in data:
            data['ip'] = self.get_node(parent).get('ip')
        identity = uid(kind, data.get('host', ''), data.get('url', data.get('port', label)), data.get('ip') or '')
        existing = next((n for n in self.state['nodes'] if n['id'] == identity), None)
        if existing:
            if parent and parent not in existing['parents']:
                existing['parents'].append(parent)
            return existing
        n = dict(id=identity, kind=kind, label=label, parent=parent, parents=[parent] if parent else [], status='discovered', **data)
        self.state['nodes'].append(n)
        return n

    def get_node(self, identity):
        return next(n for n in self.state['nodes'] if n['id'] == identity)

    def service(self, node):
        while node['kind'] != 'service':
            if not node.get('parent'):
                return None
            node = self.get_node(node['parent'])
        return node

    def enqueue(self, plugin, node_id, attempt=1, priority=10, **params):
        if len(self.state['tasks']) >= self.profile.max_tasks:
            reason = 'max_tasks: novas tarefas não foram criadas'
            if reason not in self.state['limits']:
                self.state['limits'].append(reason)
                self.event('limit', reason)
            return None
        task_id = uid(plugin, node_id, attempt)
        if any(t['id'] == task_id for t in self.state['tasks']):
            return None
        node = self.get_node(node_id)
        if node.get('cancelled'):
            return None
        task = dict(id=task_id, plugin=plugin, node=node_id, host=node['host'], status='pending', reason='', attempt=attempt, priority=priority, created=now(), params=params, auth='provided' if plugin in self.credentials or (plugin in ('http','content','screenshot') and 'http' in self.credentials) else 'anonymous', commands=[])
        self.state['tasks'].append(task)
        for suffix in ('stdout', 'stderr'):
            (self.root / 'logs' / f'{task_id}.{suffix}.log').touch()
        atomic_json(self.root / 'commands' / f'{task_id}.json', {'plugin': plugin, 'commands': [], 'note': 'Plugin interno; chamadas de rede nos resultados'})
        self.event('queued', f'{plugin}: aguardando execução', task=task_id, node=node_id)
        return task

    def finding(self, task, title, data, kind='observation', evidence=(), source=None, confidence='observed'):
        f = dict(id=uid(task['id'], title, source or task['node']), node=task['node'], task=task['id'], title=title, data=self.redactor.obj(data), kind=kind, evidence=list(evidence), source=source or task['node'], confidence=confidence, auth=task['auth'], selected=True, note='', marker='investigate', created=now())
        if not any(x['id'] == f['id'] for x in self.state['findings']):
            self.state['findings'].append(f)
            self.event('finding', title, node=task['node'])
        return f

    def evidence(self, task, name, value):
        path = Path('hosts') / uid(task['host']) / task['plugin'] / task['id'] / name
        full = self.root / path
        full.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            full.write_bytes(value)
        else:
            full.write_text(self.redactor.text(value if isinstance(value, str) else json.dumps(self.redactor.obj(value), ensure_ascii=False, indent=2)))
        return path.as_posix()

    async def request_slot(self, host):
        lock = self.rate_locks.setdefault(host, asyncio.Lock())
        async with lock:
            await self._request_slot(host)

    async def _request_slot(self, host):
        self.check_stop()
        count = self.state['requests'].get(host, 0)
        if count >= self.profile.max_requests:
            raise TaskError('limited', 'Orçamento de requisições HTTP por host atingido')
        delay = 1 / self.profile.rate - (time.monotonic() - self.last_request.get(host, 0))
        if delay > 0:
            await asyncio.sleep(delay)
        self.check_stop()
        self.last_request[host] = time.monotonic()
        self.state['requests'][host] = count + 1

    def check_stop(self):
        if self.stop_requested:
            raise TaskError('interrupted', 'Backend encerrado; retome para continuar')
        if time.monotonic() >= self.deadline:
            raise TaskError('limited', 'Orçamento de duração atingido')

    async def command(self, task, argv, timeout=None):
        self.check_stop()
        if not shutil.which(argv[0]):
            raise TaskError('unavailable', f'Dependência ausente: {argv[0]}')
        manifest = json.loads((self.root / 'manifest.json').read_text())
        tool_info = manifest.get('tools', {}).get(argv[0], {})
        record = dict(argv=self.redactor.obj(argv), started=now(), tool=argv[0], version=tool_info.get('version', 'internal/unknown'))
        task['commands'].append(record)
        atomic_json(self.root / 'commands' / f"{task['id']}.json", task['commands'])
        proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True, env={**os.environ, 'LC_ALL': 'C', 'NO_COLOR': '1'})
        async def read(stream, suffix):
            chunks = []
            total = 0
            # Redact complete lines to avoid exposing secrets split across pipe reads.
            while True:
                try:
                    line = await stream.readline()
                except ValueError:
                    raise TaskError('failed', 'Saída contém linha acima do limite de coleta')
                if not line:
                    break
                total += len(line)
                if total > 16 * 1024 * 1024:
                    raise TaskError('limited', 'Limite de saída por processo (16 MiB)')
                text = self.redactor.text(line.decode(errors='replace'))
                chunks.append(text)
                with (self.root / 'logs' / f"{task['id']}.{suffix}.log").open('a') as f:
                    f.write(text)
            return ''.join(chunks)
        readers = [asyncio.create_task(read(proc.stdout, 'stdout')), asyncio.create_task(read(proc.stderr, 'stderr'))]
        try:
            async with asyncio.timeout(min(timeout or self.profile.task_timeout, max(.01, self.deadline-time.monotonic()))):
                out, err = await asyncio.gather(*readers)
                code = await proc.wait()
        finally:
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    await asyncio.wait_for(proc.wait(), 2)
                except (ProcessLookupError, asyncio.TimeoutError):
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await proc.wait()
            for reader in readers:
                reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            record['finished'] = now()
            record['returncode'] = proc.returncode
            atomic_json(self.root / 'commands' / f"{task['id']}.json", task['commands'])
        if code:
            reason = (err or out)[-1800:]
            status = 'denied' if any(s in reason.upper() for s in ('ACCESS_DENIED', 'LOGON_FAILURE', 'AUTHENTICATION', 'NT_STATUS_ACCOUNT')) else 'failed'
            raise TaskError(status, f'{argv[0]} terminou com {code}: {reason}')
        return out, err

    async def execute(self, task):
        from .plugins import REGISTRY
        task.update(status='running', started=now())
        self.event('started', f"{task['plugin']} iniciado", task=task['id'])
        self.checkpoint()
        try:
            if task['plugin'] in self.state.get('auth_required', []) and task['plugin'] not in self.credentials:
                raise TaskError('unavailable', 'Credenciais desta sessão precisam ser fornecidas novamente')
            async with asyncio.timeout(min(self.profile.task_timeout, max(.01, self.deadline-time.monotonic()))):
                await REGISTRY[task['plugin']].run(self, task)
            task['status'] = 'completed'
        except TaskError as e:
            task.update(status=e.status, reason=str(e))
        except TimeoutError:
            task.update(status='timeout' if time.monotonic() < self.deadline else 'limited', reason='Tempo limite da tarefa/duração atingido')
        except asyncio.CancelledError:
            task.update(status=task.get('cancel_status', 'interrupted'), reason=task.get('cancel_reason', 'Execução interrompida'))
        except Exception as e:
            task.update(status='failed', reason=self.redactor.text(f'{type(e).__name__}: {e}'))
        finally:
            task['finished'] = now()
            self.get_node(task['node'])['status'] = task['status']
            self.event(task['status'], f"{task['plugin']}: {task['reason'] or task['status']}", task=task['id'])
            self.checkpoint()

    def seed_urls(self):
        # Explicit user URLs are enough to attempt HTTP; they do not prove a service exists.
        for url in self.state.get('input_urls',[]):
            scheme,host,port=origin(url)
            parent=next((n for n in self.state['nodes'] if n['kind']=='host' and n['host']==host),None)
            if not parent or parent.get('cancelled'):continue
            service=self.node('service',f'{port}/tcp · URL informada',parent['id'],host=host,port=port,protocol=None,input_url=True)
            node=self.node('url',url,service['id'],host=host,url=url,source='user-url')
            for priority,module in enumerate(('http','screenshot','content')):
                if module in self.profile.modules:self.enqueue(module,node['id'],priority=priority,depth=0)

    async def run(self, resume=False):
        import fcntl
        if self.running:
            return
        lock = (self.root / '.run.lock').open('a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock.close()
            raise ValueError('Esta execução já está ativa em outro processo')
        self._lockfile = lock
        self.running = True
        self.stop_requested = False
        self.deadline = time.monotonic() + self.profile.max_duration
        if resume:
            self.state['resume_count'] = self.state.get('resume_count', 0) + 1
            # A new duration window, but request counters remain global to the run.
            for t in self.state['tasks']:
                if t['status'] in ('running', 'interrupted', 'limited', 'unavailable') and not self.get_node(t['node']).get('cancelled'):
                    t.update(status='pending', reason='Retomada')
        self.seed_urls()
        self.state['status'] = 'running'
        try:
            while True:
                if self.stop_requested or time.monotonic() >= self.deadline:
                    for task, future in list(self.active.values()):
                        task['cancel_status'] = 'interrupted' if self.stop_requested else 'limited'
                        future.cancel()
                    await asyncio.gather(*(v[1] for v in self.active.values()), return_exceptions=True)
                    for t in self.state['tasks']:
                        if t['status'] == 'pending':
                            t.update(status='interrupted' if self.stop_requested else 'limited', reason='Backend encerrado' if self.stop_requested else 'Orçamento de duração atingido')
                    break
                busy_hosts = {t['host'] for t, future in self.active.values() if not future.done()}
                pending = sorted((t for t in self.state['tasks'] if t['status'] == 'pending'), key=lambda t: t['priority'])
                for task in pending:
                    if len(self.active) >= self.profile.concurrency:
                        break
                    if task['host'] in busy_hosts:
                        continue
                    future = asyncio.create_task(self.execute(task))
                    self.active[task['id']] = (task, future)
                    busy_hosts.add(task['host'])
                    # Reserve before yielding to prevent duplicate scheduling.
                    task['status'] = 'running'
                if not self.active:
                    break
                done, _ = await asyncio.wait([f for _, f in self.active.values()], timeout=.2, return_when=asyncio.FIRST_COMPLETED)
                for key, (_, future) in list(self.active.items()):
                    if future in done:
                        await future
                        del self.active[key]
            statuses = {t['status'] for t in self.state['tasks']}
            self.state['status'] = 'partial' if statuses & {'failed', 'timeout', 'denied', 'limited', 'unavailable', 'interrupted', 'unsupported'} or self.state['limits'] else 'cancelled' if 'cancelled' in statuses else 'completed'
        finally:
            self.running = False
            self.state['finished'] = now()
            self.event('finished', f"Execução {self.state['status']}")
            self.checkpoint()
            try:
                from .intel import IntelStore
                IntelStore(self.root).handoff()
            except (ValueError,OSError,TypeError) as ex:
                self.event('warning','Contexto do agente não foi atualizado: '+type(ex).__name__)
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
            self._lockfile = None

    def descendants(self, node_id):
        ids = {node_id}
        changed = True
        while changed:
            old = len(ids)
            ids.update(n['id'] for n in self.state['nodes'] if n.get('parent') in ids)
            changed = len(ids) > old
        return ids

    def cancel(self, node_id=None):
        ids = self.descendants(node_id) if node_id else {n['id'] for n in self.state['nodes']}
        for n in self.state['nodes']:
            if n['id'] in ids:
                n.update(cancelled=True, status='cancelled')
        for t in self.state['tasks']:
            if t['node'] in ids:
                if t['id'] in self.active:
                    t.update(status='cancelled', cancel_status='cancelled', cancel_reason='Cancelado pelo usuário')
                    self.active[t['id']][1].cancel()
                elif t['status'] in ('pending', 'limited', 'interrupted'):
                    t.update(status='cancelled', reason='Ramo cancelado')
        self.event('cancel', 'Ramo cancelado' if node_id else 'Execução cancelada', node=node_id)
        self.checkpoint()

    def repeat(self, node_id, deepen=False):
        n = self.get_node(node_id)
        for child in self.state['nodes']:
            if child['id'] in self.descendants(node_id):
                child.pop('cancelled', None)
        attempt = max([t['attempt'] for t in self.state['tasks']] or [0]) + 1
        if n['kind'] == 'host':
            plugin = 'discovery'
        else:
            plugin = 'confirm'
        task = self.enqueue(plugin, node_id, attempt=attempt, priority=0, deepen=deepen)
        self.checkpoint()
        return task
