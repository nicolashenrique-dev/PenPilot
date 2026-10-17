"""mitmdump addon: scoped forwarding via pinned HTTPX, no automatic upstream socket."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit, urlunsplit
import httpx
from mitmproxy import ctx, http
from penpilot.intel import IntelStore, safe_url, SAFE_HEADERS
from penpilot.models import Scope, canonical_url, origin


class ScopedCapture:
    def __init__(self):
        self.lock=asyncio.Lock();self.count=0;self.last=0;self.config=None

    def load(self,loader):
        loader.add_option('penpilot_config',str,'','Local PenPilot proxy configuration')

    def running(self):
        self.config=json.loads(Path(ctx.options.penpilot_config).read_text())
        self.scope=Scope(**self.config['scope'])
        self.origins={origin(u) for u in self.config['origins']}
        self.store=IntelStore(self.config['run'])
        self.meter={'sent':0,'blocked':0,'budget_exhausted':False,'upstream_errors':0}
        self.save_meter()
        Path(self.config['ready']).write_text('ready')

    def save_meter(self):
        from penpilot.storage import atomic_json
        atomic_json(Path(self.config['meter']),self.meter)

    def server_connect(self,data):
        # All upstream traffic goes through request() and pinned HTTPX instead.
        data.server.error='Automatic upstream connections disabled by PenPilot'

    async def request(self,flow):
        if not self.config:
            flow.response=http.Response.make(503,b'PenPilot not ready');return
        try:
            url=canonical_url(flow.request.pretty_url)
            if origin(url) not in self.origins or not self.scope.permits_url(url):
                self.meter['blocked']+=1;self.save_meter()
                flow.response=http.Response.make(403,b'PenPilot: out of scope');return
            method=flow.request.method.upper()
            if method not in self.config['methods']:
                self.meter['blocked']+=1;self.save_meter()
                flow.response=http.Response.make(405,b'PenPilot: method disabled');return
            async with self.lock:
                if self.count>=self.config['max_requests']:
                    self.meter['budget_exhausted']=True;self.save_meter()
                    flow.response=http.Response.make(429,b'PenPilot: request budget exhausted');return
                await asyncio.sleep(max(0,1/self.config['rate']-(time.monotonic()-self.last)))
                self.count+=1;self.last=time.monotonic();self.meter['sent']=self.count;self.save_meter()
            p=urlsplit(url);ip=self.scope.resolve(p.hostname)[0]
            authority=f'[{ip}]' if ':' in ip else ip
            target=urlunsplit((p.scheme,f'{authority}:{origin(url)[2]}',p.path,p.query,''))
            excluded={'host','proxy-authorization','proxy-connection','connection','transfer-encoding','content-length','accept-encoding'}
            headers={k:v for k,v in flow.request.headers.items() if k.lower() not in excluded}
            headers['Host']=p.netloc
            from penpilot.auth import headers as auth_headers
            headers.update(auth_headers(self.config.get('credentials',{}),url))
            body=flow.request.raw_content or b''
            if len(body)>1024*1024:
                flow.response=http.Response.make(413,b'PenPilot: body too large');return
            async with httpx.AsyncClient(timeout=15,trust_env=False,follow_redirects=False,verify=True) as client:
                async with client.stream(method,target,headers=headers,content=body,extensions={'sni_hostname':p.hostname.encode()}) as response:
                    chunks=[];size=0
                    async for chunk in response.aiter_bytes():
                        size+=len(chunk)
                        if size>2*1024*1024:raise ValueError('Response exceeds 2 MiB')
                        chunks.append(chunk)
                    raw=b''.join(chunks)
                    out=[(k.encode(),v.encode()) for k,v in response.headers.multi_items() if k.lower() not in ('content-encoding','content-length','transfer-encoding','connection')]
                    flow.response=http.Response.make(response.status_code,raw,out)
                    # No body or credential values in the capture file.
                    record={'request':{'url':safe_url(url),'method':method,'headers':[{'name':k,'value':'REDACTED'} for k in headers if k.lower() in ('authorization','cookie')]},'response':{'status':response.status_code,'headers':{k:v for k,v in response.headers.items() if k.lower() in SAFE_HEADERS},'content':{'size':len(raw),'mimeType':response.headers.get('content-type','')},'body_sha256':hashlib.sha256(raw).hexdigest()}}
                    with open(self.config['output'],'a') as file:file.write(json.dumps(record,ensure_ascii=False)+'\n')
                    records=self.store.traffic([record],'capture:'+self.config['id'])
                    mime=response.headers.get('content-type','')
                    if 'javascript' in mime or p.path.endswith(('.js','.mjs')):
                        records+=self.store.javascript(raw.decode(errors='replace'),url,'capture:'+self.config['id'])
                    self.store.put(records)
        except Exception:
            if self.config:
                self.meter['upstream_errors']+=1;self.save_meter()
            # Avoid echoing upstream exception messages that can contain credentials.
            flow.response=http.Response.make(502,b'PenPilot: upstream request failed; check TLS, scope or limits')


addons=[ScopedCapture()]
