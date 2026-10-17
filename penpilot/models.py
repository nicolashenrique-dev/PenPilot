from __future__ import annotations
import hashlib
import ipaddress
import json
import re
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

MODULES = ['http', 'content', 'screenshot', 'smb', 'ftp']
DEFAULT_WORDLIST = str(Path(__file__).parent / 'data/common.txt')


def uid(*parts):
    return hashlib.sha256('|'.join(map(str, parts)).encode()).hexdigest()[:16]


def canonical_url(url):
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('URL HTTP(S) sem credenciais é necessária')
    port = p.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Porta da URL deve estar entre 1 e 65535")
    host = p.hostname.lower().rstrip('.')
    authority = f'[{host}]' if ':' in host else host
    if port and port != (443 if p.scheme == 'https' else 80):
        authority += f':{port}'
    return urlunsplit((p.scheme, authority, p.path or '/', p.query, ''))


def origin(url):
    p = urlsplit(canonical_url(url))
    return p.scheme, p.hostname, p.port or (443 if p.scheme == 'https' else 80)


def duration(value):
    m = re.fullmatch(r'(\d+)([smh]?)', str(value))
    if not m:
        raise ValueError('Duração: 30s, 15m ou 1h')
    return int(m[1]) * {'': 1, 's': 1, 'm': 60, 'h': 3600}[m[2]]


@dataclass
class Profile:
    name: str = 'standard'
    focus: str = 'general'
    modules: list[str] = field(default_factory=lambda: MODULES.copy())
    ports: str = '21,22,53,80,139,443,445,3389,8000,8080,8443'
    timeout: int = 10
    task_timeout: int = 120
    max_duration: int = 900
    concurrency: int = 3
    rate: float = 5
    max_tasks: int = 100
    max_requests: int = 300
    crawl_depth: int = 1
    directory_depth: int = 1
    wordlist: str = DEFAULT_WORDLIST
    content_engine: str = 'builtin'
    extensions: list[str] = field(default_factory=list)
    insecure_tls: bool = False
    render_js: bool = False
    generic_check: bool = True
    browser_origins: list[str] = field(default_factory=list)
    browser_wait_ms: int = 1500

    @classmethod
    def build(cls, name='standard', **overrides):
        presets = {
            'quick': dict(generic_check=False, max_duration=300, max_requests=80, crawl_depth=0, directory_depth=0, modules=['http', 'smb', 'ftp']),
            'standard': {},
            'full': dict(ports='1-65535', max_duration=3600, max_requests=1000, crawl_depth=2, directory_depth=2, max_tasks=300),
            'custom': {},
        }
        if name not in presets:
            raise ValueError('Perfil inválido')
        values = dict(presets[name]); values.update(overrides)
        unknown = set(values) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError('Opções desconhecidas: ' + ', '.join(sorted(unknown)))
        p = cls(name=name, **values)
        if p.focus not in ('general', 'web', 'windows'):
            raise ValueError('Foco inválido')
        if p.focus == 'web':
            p.modules = [m for m in p.modules if m in ['http', 'content', 'screenshot']]
        if p.focus == 'windows':
            p.modules = [m for m in p.modules if m != 'ftp']
        if not set(p.modules) <= set(MODULES):
            raise ValueError('Módulo desconhecido')
        for part in p.ports.split(','):
            if not re.fullmatch(r'\d+(?:-\d+)?', part):
                raise ValueError('Portas TCP: use 80,443,8000-8100')
            nums = list(map(int, part.split('-')))
            if any(n < 1 or n > 65535 for n in nums) or nums[0] > nums[-1]:
                raise ValueError('Porta fora do intervalo')
        for k, lo, hi in [('timeout', 1, 60), ('task_timeout', 1, 3600), ('max_duration', 1, 86400), ('concurrency', 1, 16), ('max_tasks', 1, 10000), ('max_requests', 1, 100000), ('crawl_depth', 0, 5), ('directory_depth', 0, 5)]:
            if not isinstance(getattr(p, k), int) or not lo <= getattr(p, k) <= hi:
                raise ValueError(f'{k}: intervalo {lo}–{hi}')
        if not 0.1 <= float(p.rate) <= 100:
            raise ValueError('Taxa: 0.1–100')
        for flag in ('render_js', 'generic_check', 'insecure_tls'):
            if not isinstance(getattr(p, flag), bool):
                raise ValueError(f'{flag}: use verdadeiro ou falso')
        if not isinstance(p.browser_wait_ms, int) or not 0 <= p.browser_wait_ms <= 10000:
            raise ValueError('Espera do navegador: 0–10000 ms')
        if not isinstance(p.browser_origins, list) or len(p.browser_origins) > 20:
            raise ValueError('Informe até 20 origens para o navegador')
        for value in p.browser_origins:
            parsed = urlsplit(canonical_url(value))
            if parsed.path != '/' or parsed.query:
                raise ValueError('Origem deve conter apenas protocolo, host e porta')
        if p.render_js and 'screenshot' not in p.modules:
            p.modules.append('screenshot')
        if p.content_engine not in ('builtin', 'ffuf'):
            raise ValueError('Motor de conteúdo inválido')
        if any(not re.fullmatch(r'\.?[a-zA-Z0-9]+', e) for e in p.extensions):
            raise ValueError('Extensão inválida')
        if not Path(p.wordlist).is_file():
            raise ValueError('Wordlist não encontrada')
        return p

    def json(self):
        return asdict(self)


class Scope:
    """Exact names and IP networks. Resolve once, pin connections to approved IPs."""
    def __init__(self, allowed, excluded=(), pins=None):
        self.allowed = [self.normalize(x) for x in allowed]
        self.excluded = [self.normalize(x) for x in excluded]
        self.pins = pins or {}
        if not self.allowed:
            raise ValueError('Escopo vazio')

    @staticmethod
    def normalize(value):
        value = value.strip()
        if '://' in value:
            value = urlsplit(canonical_url(value)).hostname
        value = value.lower().rstrip('.')
        if not value or value.startswith('-') or any(c in value for c in '\n\r\t @\\'):
            raise ValueError('Alvo/escopo inválido')
        try:
            return str(ipaddress.ip_network(value, strict=False)) if '/' in value else str(ipaddress.ip_address(value))
        except ValueError:
            if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value):
                raise ValueError('Use IP, CIDR ou hostname exato (sem URL)')
            return value

    @staticmethod
    def match(host, rules):
        for rule in rules:
            if host == rule:
                return True
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False):
                    return True
            except ValueError:
                pass
        return False

    def resolve(self, host):
        host = self.normalize(host)
        if self.match(host, self.excluded) or not self.match(host, self.allowed):
            raise ValueError(f'Fora do escopo: {host}')
        if host not in self.pins:
            ips = sorted({r[4][0] for r in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
            if not ips or any(self.match(ip, self.excluded) for ip in ips):
                raise ValueError(f'Resolução excluída: {host}')
            self.pins[host] = ips
        return self.pins[host]

    def permits_url(self, url):
        try:
            host = urlsplit(canonical_url(url)).hostname
            self.resolve(host)
            return True
        except (ValueError, OSError):
            return False

    def json(self):
        return dict(allowed=self.allowed, excluded=self.excluded, pins=self.pins)

    def targets(self, targets):
        result = []
        for value in targets:
            value = self.normalize(value)
            if '/' in value:
                network = ipaddress.ip_network(value)
                if network.num_addresses > 256:
                    raise ValueError('MVP aceita no máximo 256 endereços por CIDR')
                candidates = list(map(str, network.hosts()))
            else:
                candidates = [value]
            for host in candidates:
                if self.match(host, self.excluded):
                    continue
                self.resolve(host)
                if host not in result:
                    result.append(host)
        if not result or len(result) > 256:
            raise ValueError('Selecione 1–256 alvos permitidos')
        return result
