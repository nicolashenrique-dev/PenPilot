"""Persistent schedules serviced while the local panel or watch command runs."""
import asyncio
import json
import time
import uuid
from pathlib import Path
from .analysis import compare
from .engine import Engine
from .models import Profile
from .storage import atomic_json, now


def clone_targets(state):
    from .models import origin
    urls=state.get('input_urls',[])
    hosts={origin(u)[1] for u in urls}
    return urls+[h for h in state['targets'] if h not in hosts]


class MonitorStore:
    def __init__(self,root):
        self.root=Path(root).resolve();self.path=self.root/'.monitors.json'
        self.items=json.loads(self.path.read_text()) if self.path.exists() else []
        self.active_engine=None
        self.lock=asyncio.Lock()
        self.stopped=asyncio.Event()

    def save(self):
        atomic_json(self.path,self.items)

    def create(self,template,interval):
        if not isinstance(interval,int) or not 60<=interval<=2592000:
            raise ValueError('Intervalo: 60 segundos a 30 dias')
        if template.state.get('auth_required'):
            raise ValueError('Monitor persistente requer modelo anônimo. Para sessão em memória, use watch com credenciais.')
        if template.running or template.state['status'] in ('pending','running'):
            raise ValueError('Aguarde a conclusão da execução modelo')
        if template.root.parent!=self.root:
            raise ValueError('O modelo precisa estar na pasta de histórico deste painel')
        item=dict(id=uuid.uuid4().hex[:12],template=template.state['id'],interval=interval,active=True,next_at=time.time()+interval,last_run=template.state['id'],events=[],last_error=None)
        self.items.append(item);self.save();return item

    def toggle(self,identity,active):
        item=next((m for m in self.items if m['id']==identity),None)
        if item is None:raise ValueError('Monitor não encontrado')
        if not isinstance(active,bool):raise ValueError('active deve ser booleano')
        item['active']=active
        if active:item['next_at']=time.time()+item['interval']
        if not active and self.active_engine and getattr(self.active_engine,'monitor_id',None)==identity:
            self.active_engine.stop_requested=True
        self.save();return item

    def load(self,identity):
        path=(self.root/identity).resolve()
        if path.parent!=self.root:raise ValueError('Modelo inválido')
        return Engine.load(path)

    async def tick(self):
        if self.lock.locked():return
        async with self.lock:
            for item in self.items:
                if not item['active'] or item['next_at']>time.time():continue
                try:
                    template=self.load(item['template'])
                    previous=self.load(item['last_run'])
                    engine=Engine.create(self.root,clone_targets(template.state),Profile.build(**template.profile.json()),template.scope.allowed,template.scope.excluded)
                    engine.monitor_id=item['id'];self.active_engine=engine
                    await engine.run()
                    diff=compare(previous.state,engine.state)
                    failed=engine.state['status'] not in ('completed','cancelled')
                    changed_status=engine.state['status']!=previous.state['status']
                    if diff['has_changes'] or changed_status or item['last_error']:
                        item['events'].append(dict(time=now(),kind='failure' if failed else 'change',run=engine.state['id'],message='Coleta parcial; revise as tarefas.' if failed else 'Mudança detectada na coleta.',comparison=diff))
                    item['last_run']=engine.state['id'];item['last_error']=None
                except asyncio.CancelledError:
                    raise
                except Exception as ex:
                    message=str(ex)[:500]
                    if message!=item['last_error']:
                        item['events'].append(dict(time=now(),kind='failure',message=message))
                    item['last_error']=message
                finally:
                    self.active_engine=None
                    item['events']=item['events'][-30:]
                    item['next_at']=time.time()+item['interval'];self.save()

    async def serve(self):
        try:
            while not self.stopped.is_set():
                await self.tick()
                try:await asyncio.wait_for(self.stopped.wait(),1)
                except asyncio.TimeoutError:pass
        finally:
            if self.active_engine:self.active_engine.stop_requested=True


async def watch(directory,interval,count,credentials=None):
    import signal
    if interval<60 or count<0:raise ValueError('Intervalo mínimo de 60 segundos; count >= 0')
    template=Engine.load(directory,credentials)
    if template.state.get('auth_required') and not credentials:
        raise ValueError('Forneça novamente a sessão para monitorar uma execução autenticada')
    stop=asyncio.Event();active=[None]
    def halt():
        stop.set()
        if active[0]:active[0].stop_requested=True
    loop=asyncio.get_running_loop()
    for sig in (signal.SIGINT,signal.SIGTERM):loop.add_signal_handler(sig,halt)
    previous=template;iteration=0
    print('Monitor ativo; Ctrl+C encerra. Somente mudanças ou falhas serão exibidas.',flush=True)
    while not stop.is_set() and (count==0 or iteration<count):
        engine=Engine.create(template.root.parent,clone_targets(template.state),Profile.build(**template.profile.json()),template.scope.allowed,template.scope.excluded,credentials)
        active[0]=engine
        await engine.run()
        delta=compare(previous.state,engine.state)
        if delta['has_changes'] or engine.state['status']!=previous.state['status']:
            print(json.dumps(dict(run=engine.state['id'],status=engine.state['status'],comparison=delta),ensure_ascii=False),flush=True)
        previous=engine;iteration+=1
        if count and iteration>=count:break
        try:await asyncio.wait_for(stop.wait(),interval)
        except asyncio.TimeoutError:pass
    return 0
