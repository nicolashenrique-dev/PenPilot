"""JavaScript rendering with intercepted, pinned, budgeted GET-only networking."""
import asyncio
import json
import shutil
from urllib.parse import urljoin, urlsplit
from .models import canonical_url, origin
from .engine import TaskError


async def mask_secrets(page, secrets):
    if secrets:
        await page.evaluate('''(secrets)=>{const clean=s=>secrets.reduce((v,k)=>v.split(k).join('[REDACTED]'),s);const w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);while(w.nextNode()){const n=w.currentNode;if(!['SCRIPT','STYLE'].includes(n.parentElement?.tagName))n.textContent=clean(n.textContent);}document.querySelectorAll('input,textarea').forEach(n=>n.value=clean(n.value));}''',secrets)


async def capture(e,t,page_url):
    from playwright.async_api import async_playwright
    from .plugins import fetch
    permitted = {origin(page_url)} | {origin(u) for u in e.profile.browser_origins}
    requests = []; failures=[]
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True,executable_path=shutil.which('chromium') or shutil.which('google-chrome'),args=['--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
        try:
            context=await browser.new_context(viewport={'width':1440,'height':960},java_script_enabled=True,service_workers='block',accept_downloads=False)
            auth=e.credentials.get('http',{})
            if auth.get('storage'):
                script='(()=>{const cfg='+json.dumps(dict(origin=canonical_url(auth.get('storage_origin',auth['origin'])).rstrip('/'),values=auth['storage']))+'; if(location.origin===cfg.origin){for(const [k,v] of Object.entries(cfg.values))localStorage.setItem(k,v);}})();'
                await context.add_init_script(script=script)
            # Browser-side credentials, websockets and unsolicited writes are never forwarded.
            async def deny_socket(ws):
                await ws.close()
            await context.route_web_socket('**/*',deny_socket)
            async def route_request(route):
                raw=route.request;url=raw.url
                row=dict(url=url,method=raw.method,resource=raw.resource_type,status=None)
                if len(requests)<2000:requests.append(row)
                try:
                    request_headers=await raw.all_headers()
                    read_method=raw.method=='GET' or (raw.method=='OPTIONS' and request_headers.get('access-control-request-method')=='GET')
                    if not read_method or origin(url) not in permitted or not e.scope.permits_url(url):
                        row['blocked']='Método ou origem fora da coleta permitida'
                        await route.abort();return
                    info,body=await fetch(e,t,url,binary=True,request_headers=request_headers,method=raw.method)
                    row['status']=info['status']
                    headers={k:v for k,v in info['headers'].items() if k.lower() in ('content-type','location','access-control-allow-origin','access-control-allow-credentials','access-control-expose-headers','access-control-allow-methods','access-control-allow-headers','access-control-max-age')}
                    await route.fulfill(status=info['status'],headers=headers,body=body)
                except (TaskError,ValueError) as ex:
                    row['blocked']=str(ex)
                    if isinstance(ex,TaskError) and ex.status in ('limited','timeout','unavailable'):failures.append(str(ex))
                    await route.abort()
            await context.route('**/*',route_request)
            page=await context.new_page()
            navigation_error=None
            try:
                await page.goto(page_url,wait_until='domcontentloaded',timeout=e.profile.timeout*1000)
                await page.wait_for_timeout(e.profile.browser_wait_ms)
            except Exception as ex:
                navigation_error=e.redactor.text(str(ex))[:400]
            text=await page.locator('body').inner_text(timeout=e.profile.timeout*1000)
            links=await page.locator('a[href]').evaluate_all('(nodes)=>nodes.slice(0,200).map(n=>n.href)')
            data=dict(url=page_url,title=await page.title(),visible_text_chars=len(text.strip()),rendered=True,requests=requests,links=links,navigation_error=navigation_error,limitations=['GET e preflight OPTIONS; POST, WebSocket, downloads e origens não autorizadas bloqueados.','A captura não interage com botões nem valida todos os estados da aplicação.'])
            proof=e.evidence(t,'browser.json',data)
            await mask_secrets(page,e.redactor.secrets)
            screenshot=e.evidence(t,'rendered.png',await page.screenshot(full_page=False))
            e.evidence(t,'rendered.txt',text[:100000])
            e.finding(t,'Navegação com JavaScript · '+data['title'],data,kind='browser',evidence=[proof,screenshot],source=page_url)
            depth=t['params'].get('depth',0)
            if depth<e.profile.crawl_depth:
                parent=e.get_node(t['node'])
                for value in links[:100]:
                    try:
                        url=canonical_url(value)
                        if origin(url)==origin(page_url) and e.scope.permits_url(url):
                            child=e.node('url',url,parent['id'],host=parent['host'],url=url,source=t['id'])
                            e.enqueue('http',child['id'],attempt=t['attempt'],depth=depth+1)
                    except ValueError:pass
            if navigation_error or failures or not text.strip():
                raise TaskError('limited','Renderização parcial: '+(navigation_error or (failures[0] if failures else 'sem texto visível')))
        finally:
            await browser.close()
