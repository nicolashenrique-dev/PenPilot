from __future__ import annotations
import asyncio
import ftplib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import httpx
from .engine import TaskError
from .models import canonical_url, origin, uid


@dataclass(frozen=True)
class Plugin:
    id: str
    protocols: tuple
    dependencies: tuple
    cost: str
    authentication: str
    queries: tuple
    run: object


def classify(service):
    name = service.get('name', '')
    if service.get('method') != 'probed' or int(service.get('conf', 0)) < 7:
        return None
    if name in ('http', 'https', 'http-alt', 'ssl/http'):
        return 'https' if service.get('tunnel') == 'ssl' or name in ('https', 'ssl/http') else 'http'
    if name in ('microsoft-ds', 'netbios-ssn'):
        return 'smb'
    if name in ('ftp', 'ftps'):
        return 'ftps' if service.get('tunnel') == 'ssl' or name == 'ftps' else 'ftp'
    return name if name not in ('unknown', 'tcpwrapped') else None


def register_services(e, t, xml):
    document = ET.fromstring(xml)
    found = []
    parent = e.get_node(t['node'])
    for host in document.findall('host'):
        for port in host.findall('./ports/port'):
            if port.find('state') is None or port.find('state').get('state') != 'open':
                continue
            service = port.find('service')
            attrs = dict(service.attrib) if service is not None else {}
            number = int(port.get('portid'))
            protocol = classify(attrs)
            n = e.node('service', f"{number}/tcp · {protocol or 'não confirmado'} {attrs.get('product', '')} {attrs.get('version', '')}".strip(), parent['id'], host=t['host'], port=number, protocol=protocol, method=attrs.get('method', 'unknown'), confidence=attrs.get('conf', '0'), product=attrs.get('product', ''), version=attrs.get('version', ''), cpes=[x.text for x in service.findall('cpe')] if service is not None else [], source=t['id'], ip=host.find('address').get('addr'))
            # A fresh discovery updates identity evidence without removing old task evidence.
            n.update(protocol=protocol, method=attrs.get('method', 'unknown'), confidence=attrs.get('conf', '0'))
            found.append(n)
            if protocol:
                schedule(e, t, n)
            else:
                e.enqueue('confirm', n['id'], attempt=t['attempt'], priority=t['priority'])
    return found


def schedule(e, task, service, node=None):
    node = node or service
    protocol = service['protocol']
    modules = e.profile.modules
    params = dict(attempt=task['attempt'], priority=task['priority'])
    if protocol in ('http', 'https'):
        if not node.get('url'):
            seeds = [url for url in e.state.get('input_urls', []) if origin(url) == (protocol, service['host'], service['port'])]
            if seeds:
                for url in seeds:
                    child = e.node('url', url, service['id'], host=service['host'], url=url, source=task['id'])
                    schedule(e, task, service, child)
                return
            host = service['host']
            authority = f'[{host}]' if ':' in host else host
            url = canonical_url(f'{protocol}://{authority}:{service["port"]}/')
            node = e.node('url', url, service['id'], host=service['host'], url=url, source=task['id'])
        if 'http' in modules:
            e.enqueue('http', node['id'], **params, depth=0)
        if 'content' in modules:
            e.enqueue('content', node['id'], **params, depth=0)
        if 'screenshot' in modules:
            e.enqueue('screenshot', node['id'], **params)
    if protocol == 'smb' and 'smb' in modules:
        e.enqueue('smb', service['id'], **params)
    if protocol in ('ftp', 'ftps') and 'ftp' in modules:
        e.enqueue('ftp', service['id'], **params)


async def discovery(e, t):
    ips = e.scope.resolve(t['host'])
    all_services = []
    for ip in ips:
        argv = ['nmap', '-sT', '-sV', '--version-light', '-Pn', '-n', '--max-retries', '1', '--max-rate', str(max(1, int(e.profile.rate * 10))), '--host-timeout', f'{e.profile.task_timeout}s', '-p', e.profile.ports, '-oX', '-']
        if ':' in ip:
            argv.append('-6')
        argv.append(ip)
        out, _ = await e.command(t, argv)
        evidence = e.evidence(t, f'nmap-{uid(ip)}.xml', out)
        nodes = register_services(e, t, out)
        all_services.extend(nodes)
        e.finding(t, f'Descoberta TCP · {ip}', dict(services=len(nodes), ip=ip, note='Somente identificação probed com confiança >=7 libera plugins; portas por tabela precisam de confirmação.'), evidence=[evidence])
    present = {n['protocol'] for n in all_services}
    for module, protocols in [('http', {'http', 'https'}), ('content', {'http', 'https'}), ('screenshot', {'http', 'https'}), ('smb', {'smb'}), ('ftp', {'ftp', 'ftps'})]:
        if module in e.profile.modules and not present.intersection(protocols):
            skipped = e.enqueue(module, t['node'], attempt=t['attempt'])
            if skipped:
                skipped.update(status='skipped', reason='Nenhum serviço compatível confirmado na descoberta; portas inconclusivas têm sondagem própria')


async def confirm(e, t):
    n = e.get_node(t['node'])
    service = e.service(n)
    if not service:
        raise TaskError('skipped', 'Nó sem serviço associado')
    ip = service.get('ip') or e.scope.resolve(t['host'])[0]
    argv = ['nmap', '-sT', '-sV', '--version-intensity', '5', '-Pn', '-n', '--max-retries', '0', '-p', str(service['port']), '-oX', '-']
    if ':' in ip:
        argv.append('-6')
    out, _ = await e.command(t, argv + [ip], timeout=min(45, e.profile.task_timeout))
    evidence = e.evidence(t, 'confirmation.xml', out)
    port = ET.fromstring(out).find('./host/ports/port')
    attrs = port.find('service').attrib if port is not None and port.find('service') is not None else {}
    proto = classify(attrs)
    if port is None or port.find('state').get('state') != 'open' or not proto:
        raise TaskError('skipped', 'Protocolo/acessibilidade não confirmados pela sondagem')
    service.update(protocol=proto, method=attrs.get('method'), confidence=attrs.get('conf'))
    e.finding(t, 'Disponibilidade confirmada', dict(protocol=proto, port=service['port']), evidence=[evidence])
    schedule(e, t, service, n if n['kind'] == 'url' else None)


async def fetch(e, t, url, binary=False, request_headers=None, method='GET'):
    url = canonical_url(url)
    if 'http' in e.state.get('auth_required', []) and 'http' not in e.credentials:
        raise TaskError('unavailable', 'Sessão web necessária: forneça novamente as credenciais para retomar')
    if not e.scope.permits_url(url):
        raise TaskError('skipped', f'URL fora do escopo: {url}')
    p = urlsplit(url)
    approved_ips = e.scope.resolve(p.hostname)
    node = e.get_node(t['node'])
    service = e.service(node)
    candidate_ip = service.get('ip') if service and service['host'] == p.hostname else None
    ip = candidate_ip if candidate_ip in approved_ips else approved_ips[0]
    await e.request_slot(t['host'])
    authority = f'[{ip}]' if ':' in ip else ip
    target = urlunsplit((p.scheme, f'{authority}:{p.port or (443 if p.scheme == "https" else 80)}', p.path, p.query, ''))
    headers = {'Host': p.netloc, 'User-Agent': 'PenPilot/0.1 authorized-lab-recon'}
    from .auth import headers as auth_headers
    if method not in ('GET', 'OPTIONS'):
        raise TaskError('skipped', 'Método não permitido')
    if request_headers:
        incoming_origin=request_headers.get('origin')
        if incoming_origin and e.scope.permits_url(incoming_origin):
            headers['Origin']=incoming_origin
        if method=='OPTIONS':
            headers['Access-Control-Request-Method']='GET'
            if request_headers.get('access-control-request-headers'):
                headers['Access-Control-Request-Headers']=request_headers['access-control-request-headers']
    auth=e.credentials.get('http',{})
    if method=='GET' and request_headers and auth and origin(auth['origin'])==origin(url):
        for key in ('authorization','cookie'):
            value=request_headers.get(key)
            if (key=='authorization' and auth.get('token')) or (key=='cookie' and auth.get('cookie')):
                continue
            if value and '\r' not in value and '\n' not in value:
                headers[key]=value
                e.redactor.secrets.extend([value,value.removeprefix('Bearer ')])
    if method=='GET':
        headers.update(auth_headers(e.credentials, url))
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(verify=not e.profile.insecure_tls, timeout=e.profile.timeout, follow_redirects=False, trust_env=False) as client:
            async with client.stream(method, target, headers=headers, extensions={'sni_hostname': p.hostname.encode()}) as response:
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > 2 * 1024 * 1024:
                        raise TaskError('limited', 'Resposta HTTP excede 2 MiB')
                    chunks.append(chunk)
                body = b''.join(chunks)
                tls = None
                stream = response.extensions.get('network_stream')
                sslobj = stream.get_extra_info('ssl_object') if stream else None
                if sslobj:
                    cert = sslobj.getpeercert(binary_form=True)
                    tls = dict(version=sslobj.version(), cipher=sslobj.cipher(), cert_sha256=hashlib.sha256(cert).hexdigest(), certificate=sslobj.getpeercert(), verified=not e.profile.insecure_tls)
                from .analysis import cookie_metadata
                info = dict(cookies=cookie_metadata(response.headers.get_list('set-cookie')), url=url, status=response.status_code, headers=dict(response.headers), bytes=len(body), elapsed_ms=round((time.monotonic()-started)*1000), tls=tls)
                if response.status_code == 429:
                    e.last_request[t['host']] = time.monotonic() + min(30, int(response.headers.get('retry-after', '2')) if response.headers.get('retry-after', '').isdigit() else 2)
                    e.event('backoff', 'HTTP 429: pausa conservadora aplicada', node=t['node'])
                return info, body if binary else body.decode('utf-8', errors='replace')
    except httpx.TimeoutException as ex:
        raise TaskError('timeout', f'Timeout HTTP em {url}') from ex
    except httpx.HTTPError as ex:
        raise TaskError('failed', f'HTTP: {ex}') from ex


class Extractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts, self.forms, self.comments, self.title = [], [], [], [], []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'title':
            self.in_title = True
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])
        if tag == 'script' and attrs.get('src'):
            self.scripts.append(attrs['src'])
        if tag == 'form':
            self.forms.append({k: attrs[k] for k in ('action', 'method') if k in attrs})

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data)

    def handle_comment(self, data):
        self.comments.append(data[:1000])


async def fetch_page(e, t, url):
    """Follow bounded same-origin redirects and the standard HTTPS upgrade."""
    chain = []
    seen = set()
    for _ in range(6):
        if url in seen:
            raise TaskError('limited', 'Redirecionamento circular; navegação interrompida')
        seen.add(url)
        info, body = await fetch(e, t, url)
        if info['status'] not in (301, 302, 303, 307, 308) or not info['headers'].get('location'):
            return info, body, chain
        destination = canonical_url(urljoin(url, info['headers']['location']))
        source_origin, target_origin = origin(url), origin(destination)
        upgrade = source_origin == ('http', target_origin[1], 80) and target_origin == ('https', source_origin[1], 443)
        if not (source_origin == target_origin or upgrade) or not e.scope.permits_url(destination):
            info['redirect_blocked'] = destination
            return info, body, chain
        chain.append(dict(url=url, status=info['status'], destination=destination))
        e.evidence(t, f'redirect-{len(chain)}.json', info)
        url = destination
    raise TaskError('limited', 'Limite de 5 redirecionamentos atingido')


async def generic_response(e, t, url, info, body):
    key = origin(url)
    if key not in e.baselines:
        control = urljoin(url, '/.penpilot-missing-' + uid(e.state['id'], key))
        baseline, baseline_body = await fetch(e, t, control)
        e.baselines[key] = dict(url=control, status=baseline['status'], content_type=baseline['headers'].get('content-type', '').split(';')[0], body_sha256=hashlib.sha256(e.redactor.text(baseline_body).encode()).hexdigest())
        e.evidence(t, 'generic-baseline.json', e.baselines[key])
    baseline = e.baselines[key]
    same = (info['status'], info['headers'].get('content-type', '').split(';')[0], hashlib.sha256(e.redactor.text(body).encode()).hexdigest()) == (baseline['status'], baseline['content_type'], baseline['body_sha256'])
    return dict(generic_response=same, generic_check='completed', generic_baseline=baseline)


def document_links(body, content_type, base):
    """Extract literal candidates only; never execute downloaded code."""
    candidates = []
    if 'xml' in content_type or urlsplit(base).path.endswith('.xml'):
        if '<!DOCTYPE' not in body.upper() and '<!ENTITY' not in body.upper():
            try:
                doc = ET.fromstring(body)
                candidates += [n.text.strip() for n in doc.iter() if n.tag.split('}')[-1] == 'loc' and n.text][:200]
            except ET.ParseError:
                pass
    if urlsplit(base).path.endswith('/robots.txt'):
        candidates += re.findall(r'(?im)^(?:Allow|Disallow|Sitemap):\s*(\S+)', body)[:200]
    if 'javascript' in content_type or urlsplit(base).path.endswith(('.js', '.mjs')):
        # Static quoted paths, including Vite chunks. Dynamic expressions remain unvisited.
        literals = re.findall(r"[\"']([^\"'\n]{1,500})[\"']", body)
        candidates += [v for v in literals if v.startswith(('/', './', '../', 'https://', 'http://', 'assets/')) and not any(c in v for c in ('{', '}', '*', ' ', '<', '>'))][:200]
    result = []
    for value in candidates:
        try:
            # Vite asset references are relative to the site root, not /assets/ itself.
            url = canonical_url(urljoin(urljoin(base, '/') if value.startswith('assets/') else base, value))
            if url not in result:
                result.append(url)
        except ValueError:
            pass
    return result


async def http(e, t):
    n = e.get_node(t['node'])
    if not n.get('url'):
        raise TaskError('skipped', 'Pré-requisito HTTP não confirmado')
    info, body, redirects = await fetch_page(e, t, n['url'])
    n['final_url'] = info['url']
    seed_service=e.service(n)
    if seed_service and seed_service.get('input_url') and origin(info['url'])==origin(n['url']):
        seed_service.update(protocol=origin(info['url'])[0],method='http-response',confidence='10',label=f"{seed_service['port']}/tcp · {origin(info['url'])[0]}")
    if origin(info['url']) != origin(n['url']):
        previous = e.service(n)
        scheme, host, port = origin(info['url'])
        service = e.node('service', f'{port}/tcp · {scheme}', previous['parent'], host=host, port=port, ip=previous.get('ip'), source=t['id'])
        service.update(protocol=scheme, method='http-response', confidence='10')
        n = e.node('url', info['url'], service['id'], host=host, url=info['url'], source=t['id'])
    parser = Extractor()
    if 'html' in info['headers'].get('content-type', '') or '<html' in body[:500].lower():
        parser.feed(body)
    links = []
    for value in parser.links + parser.scripts:
        try:
            url = canonical_url(urljoin(info['url'], value))
            if url not in links:
                links.append(url)
        except ValueError:
            pass
    links = list(dict.fromkeys(links + document_links(body, info['headers'].get('content-type', ''), info['url'])))
    if info['headers'].get('location'):
        try:
            links.append(canonical_url(urljoin(info['url'], info['headers']['location'])))
        except ValueError:
            pass
    data = dict(**info, body_sha256=hashlib.sha256(e.redactor.text(body).encode()).hexdigest(), redirects=redirects, title=' '.join(parser.title).strip()[:500], technologies={k: v for k, v in info['headers'].items() if k in ('server', 'x-powered-by', 'x-generator')}, comments=parser.comments[:100], emails=sorted(set(re.findall(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', body)))[:100], links=links[:200], scripts=parser.scripts[:100], forms=parser.forms[:100], hostnames=sorted({urlsplit(u).hostname for u in links}), snippet=body[:1000])
    if e.profile.generic_check and info['status'] == 200 and 'html' in info['headers'].get('content-type', ''):
        try:
            generic = await generic_response(e, t, info['url'], info, body)
            data.update(generic)
        except TaskError as ex:
            data['generic_check'] = 'incomplete'
            e.event('limit', 'Comparação com URL inexistente não concluída: ' + str(ex), node=t['node'])
    evidence = [e.evidence(t, 'response.json', data), e.evidence(t, 'body.txt', body)]
    n['title'], n['technologies'] = data['title'], data['technologies']
    e.finding(t, f"HTTP {info['status']} · {data['title'] or n['url']}", data, kind='web', evidence=evidence, source=info['url'])
    if info['status'] in (401, 403):
        raise TaskError('denied', f"HTTP {info['status']}: acesso negado; resposta preservada")
    depth = t['params'].get('depth', 0)
    for url in links[:100]:
        # Same-origin crawling also avoids enumerating an unconfirmed service on another port.
        permitted = origin(url) == origin(info['url']) and e.scope.permits_url(url)
        if not permitted:
            e.event('scope', f'Link observado sem seguir: {url}', node=n['id'])
            continue
        if depth < e.profile.crawl_depth:
            child = e.node('url', url, n['id'], host=t['host'], url=url, source=t['id'])
            e.enqueue('http', child['id'], attempt=t['attempt'], priority=t['priority'], depth=depth+1)
    if links and depth >= e.profile.crawl_depth:
        e.event('depth', f'Crawler interrompido no nível {depth}', node=n['id'])


def words(e):
    result = []
    for word in Path(e.profile.wordlist).read_text().splitlines():
        word = word.strip()
        if not word or word.startswith('#'):
            continue
        # Wordlists are URL path segments, never additional targets or traversal.
        if word.startswith(('/', '\\')) or any(x in word for x in ('..', '://', '?', '#', '%', '\\')):
            raise TaskError('failed', f'Entrada de wordlist inválida: {word[:80]}')
        if not re.fullmatch(r'[A-Za-z0-9_./~-]+', word):
            raise TaskError('failed', 'Wordlist aceita somente caminhos ASCII simples')
        result.append(word)
        if not word.endswith('/'):
            result.extend(word + (ext if ext.startswith('.') else '.'+ext) for ext in e.profile.extensions)
    return list(dict.fromkeys(result))


async def content(e, t):
    n = e.get_node(t['node'])
    if not n.get('url'):
        raise TaskError('skipped', 'Pré-requisito HTTP não confirmado')
    base = n.get('final_url', n['url']).split('?')[0].rstrip('/') + '/'
    candidates = words(e)
    depth = t['params'].get('depth', 0)
    matches = []
    if e.profile.content_engine == 'ffuf' and e.credentials.get('http'):
        raise TaskError('unsupported', 'Sessão web requer motor integrado; ffuf não recebe credenciais')
    if e.profile.content_engine == 'ffuf':
        # ffuf has its own networking: only IP URLs, redirects off, one task per host.
        try:
            ipaddress.ip_address(urlsplit(base).hostname)
        except ValueError:
            raise TaskError('unavailable', 'ffuf no MVP exige URL com IP fixo; use builtin para hostnames com DNS fixado')
        if urlsplit(base).scheme == 'https' and not e.profile.insecure_tls:
            raise TaskError('unavailable', 'Para HTTPS com verificação de certificado, use builtin; o adaptador ffuf requer insecure_tls explícito')
        remaining = e.profile.max_requests - e.state['requests'].get(t['host'], 0) - 1
        # Reserve candidate upper bound plus baseline; auto-calibration would add extra requests.
        if len(candidates) > remaining:
            raise TaskError('limited', 'Wordlist excede orçamento restante; reduza a lista ou use builtin')
        e.state['requests'][t['host']] = e.state['requests'].get(t['host'], 0) + len(candidates)
        wl = e.root / e.evidence(t, 'effective-wordlist.txt', '\n'.join(candidates)+'\n')
        output = e.root / 'logs' / f"{t['id']}.ffuf.json"
        # Explicit baseline filter; keep raw ffuf JSON as evidence.
        baseline, baseline_body = await fetch(e, t, base + 'penpilot-missing-' + uid(t['id']))
        argv = ['ffuf', '-u', base+'FUZZ', '-w', str(wl), '-t', '1', '-rate', str(max(1, int(e.profile.rate))), '-p', str(1 / e.profile.rate), '-timeout', str(e.profile.timeout), '-maxtime', str(e.profile.task_timeout), '-noninteractive', '-s', '-mc', 'all', '-fc', '404', '-of', 'json', '-o', str(output)]
        if baseline['status'] != 404:
            argv += ['-fs', str(len(baseline_body.encode()))]
        await e.command(t, argv)
        if output.exists():
            raw = json.loads(output.read_text())
            evidence = e.evidence(t, 'ffuf.json', raw)
            output.unlink()
            matches = [dict(url=r['url'], status=r['status'], bytes=r['length']) for r in raw.get('results', [])]
        else:
            raise TaskError('failed', 'ffuf não produziu JSON')
    else:
        baseline, baseline_body = await fetch(e, t, base + 'penpilot-missing-' + uid(t['id']))
        signature = (baseline['status'], len(baseline_body), hashlib.sha256(baseline_body.encode()).hexdigest())
        for word in candidates:
            info, body = await fetch(e, t, urljoin(base, word))
            current = (info['status'], len(body), hashlib.sha256(body.encode()).hexdigest())
            wildcard = current == signature
            if info['status'] != 404 and not wildcard:
                match = dict(url=info['url'], status=info['status'], bytes=info['bytes'], location=info['headers'].get('location'))
                matches.append(match)
                # Persist immediately so cancellation keeps discoveries already observed.
                e.finding(t, f"Caminho HTTP {info['status']} · {info['url']}", match, kind='path', source=info['url'])
        evidence = e.evidence(t, 'content.json', dict(base=base, depth=depth, baseline={k: baseline[k] for k in ('status', 'bytes')}, filter='exact status and body; equal length alone is not a match', matches=matches))
    e.finding(t, f'Conteúdo · nível {depth} · {base}', dict(matches=matches, depth=depth, max_depth=e.profile.directory_depth, engine=e.profile.content_engine, wildcard_filter='heurístico; revise evidências'), kind='content', evidence=[evidence], source=base)
    for match in matches:
        url = canonical_url(match['url'])
        child = e.node('url', url, n['id'], host=t['host'], url=url, source=t['id'])
        if 'http' in e.profile.modules:
            e.enqueue('http', child['id'], attempt=t['attempt'], priority=t['priority'], depth=0)
        directory = url if urlsplit(url).path.endswith('/') else None
        if match.get('location'):
            destination = canonical_url(urljoin(url, match['location']))
            if destination.rstrip('/') == url.rstrip('/') and destination.endswith('/'):
                directory = destination
        if directory and depth < e.profile.directory_depth:
            dnode = e.node('url', directory, n['id'], host=t['host'], url=directory, source=t['id'])
            e.enqueue('content', dnode['id'], attempt=t['attempt'], priority=t['priority'], depth=depth+1)
    if depth >= e.profile.directory_depth:
        e.event('depth', f'Cascata interrompida no nível {depth} (base = 0)', node=n['id'])


async def screenshot(e, t):
    n = e.get_node(t['node'])
    if not n.get('url'):
        raise TaskError('skipped', 'Pré-requisito HTTP não confirmado')
    info, _, _ = await fetch_page(e, t, n.get('final_url', n['url']))
    if info.get('redirect_blocked'):
        raise TaskError('skipped', 'Captura não realizada: redirecionamento fora da origem permitida')
    if info['status'] >= 400:
        raise TaskError('denied' if info['status'] in (401, 403) else 'failed', f"Captura não realizada: página respondeu HTTP {info['status']}")
    page_url = info['url']
    if e.profile.render_js:
        try:
            from .browser_capture import capture
            return await capture(e, t, page_url)
        except ImportError as ex:
            raise TaskError('unavailable', 'Instale Playwright e Chromium para renderizar JavaScript') from ex
        except TaskError:
            raise
        except Exception as ex:
            raise TaskError('unavailable' if 'Executable' in str(ex) else 'failed', e.redactor.text(f'Navegador: {ex}')) from ex
    try:
        from playwright.async_api import async_playwright
    except ImportError as ex:
        raise TaskError('unavailable', 'Instale penpilot[screenshots] e o Chromium do Playwright') from ex
    try:
        async with async_playwright() as p:
            executable = shutil.which('chromium') or shutil.which('google-chrome')
            browser = await p.chromium.launch(headless=True, executable_path=executable)
            try:
                context = await browser.new_context(viewport={'width': 1440, 'height': 960}, java_script_enabled=False, service_workers='block')
                async def route_request(route):
                    url = route.request.url
                    try:
                        if origin(url) != origin(page_url) or route.request.method != 'GET':
                            await route.abort(); return
                        info, body = await fetch(e, t, url, binary=True)
                        headers = {k: v for k, v in info['headers'].items() if k.lower() in ('content-type', 'location')}
                        await route.fulfill(status=info['status'], headers=headers, body=body)
                    except (ValueError, TaskError):
                        await route.abort()
                await context.route('**/*', route_request)
                page = await context.new_page()
                await page.goto(page_url, wait_until='networkidle', timeout=e.profile.timeout*1000)
                visible_text = (await page.locator('body').inner_text()).strip()
                from .browser_capture import mask_secrets
                await mask_secrets(page, e.redactor.secrets)
                data = await page.screenshot(full_page=False)
                evidence = e.evidence(t, 'screenshot.png', data)
                e.finding(t, f"Screenshot · {n.get('title') or n['url']}", dict(url=page_url, visible_text_chars=len(visible_text), static_only=True, note='JavaScript desativado; recursos fora da origem bloqueados; viewport 1440×960'), kind='screenshot', evidence=[evidence], source=n['url'])
                if not visible_text:
                    raise TaskError('limited', 'Captura salva, mas sem texto visível. A página pode depender de JavaScript; a interface dinâmica não foi validada.')
            finally:
                await browser.close()
    except TaskError:
        raise
    except Exception as ex:
        raise TaskError('unavailable' if 'Executable' in str(ex) else 'failed', f'Screenshot: {ex}') from ex


async def smb(e, t):
    s = e.service(e.get_node(t['node']))
    if not s or s['protocol'] != 'smb':
        raise TaskError('skipped', 'SMB não confirmado')
    ip = s.get('ip') or e.scope.resolve(t['host'])[0]
    argv = ['smbclient', '-L', ip, '-I', ip, '-p', str(s['port']), '-g', '-t', str(e.profile.timeout)]
    credential = e.credentials.get('smb')
    authpath = None
    try:
        if credential:
            fd, authpath = tempfile.mkstemp(prefix='penpilot-auth-')
            with os.fdopen(fd, 'w') as f:
                for key in ('username', 'password', 'domain'):
                    value = credential.get(key, '')
                    if '\n' in value or '\r' in value:
                        raise TaskError('failed', 'Credencial não pode conter quebra de linha')
                    f.write(f'{key} = {value}\n')
            argv += ['-A', authpath]
        else:
            argv += ['-N']
        out, err = await e.command(t, argv)
        shares = []
        for line in out.splitlines():
            parts = line.split('|', 2)
            if len(parts) == 3 and parts[0] in ('Disk', 'IPC', 'Printer'):
                shares.append(dict(type=parts[0], name=parts[1], comment=parts[2], access='not tested'))
        evidence = [e.evidence(t, 'shares.json', shares)]
        e.finding(t, 'SMB · shares anunciados', dict(shares=shares, note='Listar share não comprova acesso aos arquivos; nenhum SO/AD inferido'), kind='smb', evidence=evidence)
        for share in shares[:20]:
            if share['type'] != 'Disk' or any(c in share['name'] for c in ('/', '\\', '\n', '\r')):
                continue
            cmd = ['smbclient', f'//{ip}/{share["name"]}', '-I', ip, '-p', str(s['port']), '-t', str(e.profile.timeout), '-c', 'ls'] + (['-A', authpath] if authpath else ['-N'])
            try:
                listing, _ = await e.command(t, cmd)
                share['access'] = 'read listing allowed'
                path = e.evidence(t, f'share-{uid(share["name"])}.txt', listing)
                e.finding(t, f'SMB · {share["name"]}', dict(share=share['name'], access='listing allowed'), kind='smb', evidence=[path])
            except TaskError as ex:
                share['access'] = ex.status
                e.finding(t, f'SMB · {share["name"]}', dict(access=ex.status, reason=str(ex)), kind='smb')
        e.evidence(t, 'shares.json', shares)
    finally:
        if authpath:
            os.unlink(authpath)


async def ftp(e, t):
    s = e.service(e.get_node(t['node']))
    if not s or s['protocol'] not in ('ftp', 'ftps'):
        raise TaskError('skipped', 'FTP não confirmado')
    # Async FTP control channel and pinned passive connection, no worker thread left after cancellation.
    ip = s.get('ip') or e.scope.resolve(t['host'])[0]
    tls_context = ssl._create_unverified_context() if e.profile.insecure_tls else ssl.create_default_context()
    implicit_tls = s['protocol'] == 'ftps'
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, s['port'], ssl=tls_context if implicit_tls else None, server_hostname=t['host'] if implicit_tls else None), e.profile.timeout)
    transcript = []
    async def reply():
        lines = []
        for _ in range(100):
            raw = await asyncio.wait_for(reader.readline(), e.profile.timeout)
            if not raw:
                raise TaskError('failed', 'FTP fechou a conexão')
            line = raw.decode(errors='replace').rstrip()
            lines.append(line)
            if len(line) >= 4 and line[:3].isdigit() and line[3] == ' ':
                result = '\n'.join(lines)
                transcript.append(e.redactor.text(result))
                return int(line[:3]), result
        raise TaskError('limited', 'Resposta FTP longa demais')
    async def command(value):
        transcript.append('> ' + ('PASS [REDACTED]' if value.startswith('PASS ') else e.redactor.text(value)))
        writer.write((value+'\r\n').encode()); await writer.drain()
        return await reply()
    try:
        code, banner = await reply()
        if code != 220:
            raise TaskError('failed', f'Banner FTP inesperado: {banner}')
        feature_code, features = await command('FEAT')
        tls = 'AUTH TLS' in features.upper()
        tls_active = implicit_tls
        if tls and not implicit_tls:
            code, text = await command('AUTH TLS')
            if code == 234:
                await writer.start_tls(tls_context, server_hostname=t['host'], ssl_handshake_timeout=e.profile.timeout)
                tls_active = True
            else:
                raise TaskError('failed', f'FTP anunciou TLS mas recusou negociação: {text}')
        if tls_active:
            await command('PBSZ 0')
            code, text = await command('PROT P')
            if code != 200:
                raise TaskError('unsupported', f'Canal de dados protegido não disponível: {text}')
        cred = e.credentials.get('ftp', {'username': 'anonymous', 'password': 'penpilot@example.invalid'})
        for value in cred.values():
            if '\r' in value or '\n' in value:
                raise TaskError('failed', 'Credencial FTP contém quebra de linha')
        code, response = await command('USER ' + cred.get('username', 'anonymous'))
        if code == 331:
            code, response = await command('PASS ' + cred.get('password', ''))
        if code != 230:
            raise TaskError('denied', f'FTP autenticação negada: {response}')
        _, system = await command('SYST')
        _, pwd = await command('PWD')
        # EPSV avoids a server-chosen address; fallback PASV ignores the supplied IP.
        code, text = await command('EPSV')
        match = re.search(r'\(\|\|\|(\d+)\|\)', text)
        if code == 229 and match:
            port = int(match[1])
        else:
            code, text = await command('PASV')
            match = re.search(r'\((\d+,\d+,\d+,\d+),(\d+),(\d+)\)', text)
            if code != 227 or not match:
                raise TaskError('unsupported', 'FTP não suporta modo passivo disponível')
            port = int(match[2])*256+int(match[3])
        data_reader, data_writer = await asyncio.wait_for(asyncio.open_connection(ip, port), e.profile.timeout)
        try:
            code, text = await command('LIST')
            if code not in (125, 150):
                raise TaskError('denied', f'Listagem FTP não autorizada: {text}')
            if tls_active:
                await data_writer.start_tls(tls_context, server_hostname=t['host'], ssl_handshake_timeout=e.profile.timeout)
            data = bytearray()
            while chunk := await asyncio.wait_for(data_reader.read(65536), e.profile.timeout):
                data.extend(chunk)
                if len(data) > 2*1024*1024:
                    raise TaskError('limited', 'Listagem FTP excede 2 MiB')
            code, text = await reply()
            if code != 226:
                raise TaskError('failed', f'Listagem incompleta: {text}')
        finally:
            data_writer.close(); await data_writer.wait_closed()
        evidence = [e.evidence(t, 'listing.txt', data.decode(errors='replace'))]
        e.finding(t, 'FTP · acesso e listagem', dict(banner=banner, system=system, pwd=pwd, tls_advertised=tls, tls_active=tls_active, authenticated=True, listing=data.decode(errors='replace'), note='Somente diretório inicial; sem download/upload de arquivos'), kind='ftp', evidence=evidence)
    finally:
        e.evidence(t, 'transcript.txt', '\n'.join(transcript))
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


REGISTRY = {p.id: p for p in [
    Plugin('discovery', (), ('nmap',), 'TCP connect + version probes', 'none', ('ports', 'service versions'), discovery),
    Plugin('confirm', (), ('nmap',), 'one TCP port', 'none', ('protocol and availability',), confirm),
    Plugin('http', ('http', 'https'), (), 'one GET per node', 'none', ('headers', 'TLS', 'HTML clues', 'links'), http),
    Plugin('content', ('http', 'https'), ('ffuf (optional)',), 'wordlist + one baseline / directory', 'none', ('paths',), content),
    Plugin('screenshot', ('http', 'https'), ('playwright', 'chromium'), 'page resources, bounded by HTTP budget', 'none', ('screenshot with JS off',), screenshot),
    Plugin('smb', ('smb',), ('smbclient',), 'list shares + at most 20 directory listings', 'anonymous or supplied', ('shares', 'read access'), smb),
    Plugin('ftp', ('ftp', 'ftps'), (), 'control negotiation + one LIST', 'anonymous or supplied', ('banner', 'FEAT', 'TLS', 'directory listing'), ftp),
]}
