import argparse
import errno
import socket
import asyncio
import getpass
import json
import signal
import sys
import webbrowser
from pathlib import Path

from .models import Profile, duration
from .paths import default_output


def credentials(args):
    result = {}
    for service in ('smb', 'ftp'):
        user = getattr(args, service+'_user', None)
        if user:
            result[service] = {'username': user, 'password': getpass.getpass(f'Senha {service} (somente memória): ')}
    if getattr(args, 'session_file', None):
        result['http'] = json.loads(Path(args.session_file).expanduser().read_text())
    if getattr(args, 'http_token', False) or getattr(args, 'http_cookie', False):
        result['http'] = dict(origin=args.http_origin or '')
        if args.http_token:
            result['http']['token'] = getpass.getpass('Token Bearer (somente memória): ')
        if args.http_cookie:
            result['http']['cookie'] = getpass.getpass('Cookie (somente memória): ')
    from .auth import validate
    return validate(result)


async def execute(engine, resume=False):
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: setattr(engine, 'stop_requested', True))
    job = asyncio.create_task(engine.run(resume=resume))
    seen = set()
    while not job.done():
        for event in engine.state['events']:
            key = json.dumps(event, sort_keys=True)
            if key not in seen:
                print(f"{event['time']} [{event['kind']}] {event['message']}", flush=True)
                seen.add(key)
        await asyncio.sleep(.25)
    await job
    print(f"Estado: {engine.state['status']}\nEvidências: {engine.root}\nResumo: {engine.root / 'resumo.txt'}\nRelatório: {engine.root / 'report.html'}\nWriteup: {engine.root / 'writeup.md'}")
    return 0 if engine.state['status'] == 'completed' else 2


def main(argv=None):
    from . import __version__
    parser = argparse.ArgumentParser(
        prog='penpilot', description='PenPilot — reconhecimento local para labs autorizados.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Exemplos:
  penpilot web -o ~/Labs
  penpilot scan 10.10.10.5 --profile quick -o ~/Labs
  penpilot scan -h
  penpilot resume ~/Labs/ID

Os caminhos relativos usam a pasta atual do terminal, não a instalação.
Use COMANDO -h para ver todas as opções desse comando.''')
    parser.add_argument('-v', '--version', action='version', version=f'PenPilot {__version__}', help='Mostrar versão e sair')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('doctor', help='Diagnóstico das dependências')
    service=sub.add_parser('service',help='Serviço local opcional de usuário (systemd)')
    service.add_argument('action',choices=['install','start','stop','status'])
    service.add_argument('-o','--output',default=str(default_output()),help='Pasta de histórico do painel')
    service.add_argument('--port',type=int,default=8765,help='Porta ao instalar (padrão: 8765)')
    scan = sub.add_parser('scan', help='Iniciar execução')
    scan.add_argument('targets', nargs='+', metavar='ALVO', help='URLs HTTP(S), IPs, hostnames ou CIDRs autorizados')
    scan.add_argument('-o', '--output', default=str(default_output()), metavar='PASTA', help='Pasta de resultados (padrão: ~/PenPilot/execucoes)')
    scan.add_argument('--profile', choices=['quick', 'standard', 'full', 'custom'], default=None, help='Intensidade de coleta (padrão: standard)')
    scan.add_argument('--profile-file', metavar='JSON', help='Carregar perfil JSON; opções explícitas da CLI têm prioridade')
    scan.add_argument('--scope', nargs='+', metavar='ALVO', help='IPs, nomes exatos ou CIDRs permitidos (padrão: alvos informados)')
    scan.add_argument('--exclude', nargs='*', default=[], metavar='ALVO', help='Excluir IPs, hostnames ou CIDRs do escopo')
    scan.add_argument('-p', '--ports', metavar='PORTAS', help='Portas TCP: 21,80,445 ou 8000-8100; padrão definido pelo perfil')
    scan.add_argument('--max-duration', type=duration, metavar='TEMPO', help='Orçamento de duração: 30s, 15m ou 1h')
    scan.add_argument('--focus', choices=['general', 'web', 'windows'], help='Foco de coleta; windows habilita SMB, sem enumeração AD')
    scan.add_argument('-w', '--wordlist', metavar='ARQUIVO', help='Wordlist de caminhos; relativo à pasta atual do terminal')
    scan.add_argument('--crawl-depth', type=int, metavar='N', help='Profundidade do crawler de links, de 0 a 5')
    scan.add_argument('--directory-depth', type=int, metavar='N', help='Cascata de diretórios: 0 só a base; 1 mais uma geração; máximo 5')
    scan.add_argument('--rate', type=float, metavar='N', help='Limite HTTP por alvo, em requisições/segundo (0.1–100)')
    scan.add_argument('--max-requests', type=int, metavar='N', help='Orçamento de requisições HTTP por alvo')
    scan.add_argument('--content-engine', choices=['builtin', 'ffuf'], help='Motor de descoberta de caminhos; builtin é o padrão')
    scan.add_argument('--insecure-tls', action='store_true', default=None, help='Aceitar certificados TLS não confiáveis neste lab')
    scan.add_argument('--modules', help='http,content,screenshot,smb,ftp')
    scan.add_argument('--render-js', action=argparse.BooleanOptionalAction, default=None, help='Renderizar JavaScript e observar chamadas GET no navegador')
    scan.add_argument('--generic-check', action=argparse.BooleanOptionalAction, default=None, help='Comparar HTML com URL inexistente')
    scan.add_argument('--browser-origins', nargs='+', help='Origens adicionais autorizadas para recursos/API no navegador; inclua os hosts no --scope')
    resume = sub.add_parser('resume', help='Retomar diretório preservando tarefas concluídas')
    resume.add_argument('directory', metavar='PASTA', help='Pasta da execução contendo state.json')
    watch_parser = sub.add_parser('watch', help='Repetir um modelo e exibir apenas mudanças; requer terminal aberto')
    watch_parser.add_argument('directory', help='Execução modelo')
    watch_parser.add_argument('--interval', type=duration, default=3600, help='Intervalo entre coletas; mínimo 60s, padrão 1h')
    watch_parser.add_argument('--count', type=int, default=0, help='Número de coletas; 0 até Ctrl+C')
    from .agent_cli import register
    agent_commands=register(sub,default_output())
    for cmd in (scan, resume, watch_parser, *agent_commands):
        cmd.add_argument('--http-origin', help='Origem exata da sessão, ex.: https://lab.exemplo')
        cmd.add_argument('--http-token', action='store_true', help='Solicitar Bearer sem eco, somente em memória')
        cmd.add_argument('--http-cookie', action='store_true', help='Solicitar Cookie sem eco, somente em memória')
        cmd.add_argument('--session-file', help='JSON local com origin, token/cookie e storage opcional; não copiado para evidências')
        cmd.add_argument('--smb-user', metavar='USUARIO', help='Usuário SMB; senha solicitada sem eco, mantida em memória')
        cmd.add_argument('--ftp-user', metavar='USUARIO', help='Usuário FTP; senha solicitada sem eco, mantida em memória')
    web = sub.add_parser('web', help='Painel em localhost')
    web.add_argument('-o', '--output', default=str(default_output()), metavar='PASTA', help='Pasta de histórico e novas execuções (padrão: ~/PenPilot/execucoes)')
    web.add_argument('--open', dest='directory', metavar='PASTA', help='Abrir uma execução existente; não inicia um scan')
    web.add_argument('--port', type=int, default=8765, help='Porta local do painel (padrão: 8765)')
    web.add_argument('--browser', action='store_true', help='Solicitar abertura do painel no navegador padrão')
    profile = sub.add_parser('profile', help='Exportar um perfil JSON')
    profile.add_argument('name', choices=['quick', 'standard', 'full', 'custom'], help='Perfil-base a exportar')
    profile.add_argument('-o', '--output', metavar='JSON', help='Salvar arquivo JSON (padrão: imprimir no terminal)')
    export = sub.add_parser('export', help='Empacotar evidências ou cópia textual para revisão')
    export.add_argument('directory', metavar='PASTA', help='Pasta da execução a exportar')
    export.add_argument('--publication', action='store_true', help='Gerar cópia textual para revisão, sem logs ou screenshots')
    export.add_argument('--redact', action='append', default=[], metavar='TEXTO', help='Ocultar texto na cópia de publicação; pode repetir esta opção')
    compare_parser=sub.add_parser('compare', help='Comparar duas execuções salvas')
    compare_parser.add_argument('before');compare_parser.add_argument('after')
    map_parser=sub.add_parser('map', help='Mapa de páginas, recursos e APIs observadas')
    map_parser.add_argument('directory')
    review_parser=sub.add_parser('review', help='Revisões contextuais com evidências e próximo passo')
    review_parser.add_argument('directory')
    export.add_argument('--burp', action='store_true', help='Exportar requisições para revisão no Burp, sem credenciais')
    for command_parser in (parser, *sub.choices.values()):
        for action in command_parser._actions:
            if isinstance(action, argparse._HelpAction):
                action.help = 'Mostrar esta ajuda e sair'
    args = parser.parse_args(argv if argv is not None else (sys.argv[1:] or ['--help']))
    from .engine import Engine, doctor
    from .storage import archive
    try:
        if args.command in ('agent','repeater','tools','capture'):
            from .agent_cli import dispatch
            print(json.dumps(dispatch(args,credentials),ensure_ascii=False,indent=None if args.command=='agent' and args.agent_action=='context' else 2))
            return 0
        if args.command == 'service':
            from .service import manage
            return manage(args.action,args.output,args.port)
        if args.command == 'watch':
            from .monitor import watch
            return asyncio.run(watch(args.directory,args.interval,args.count,credentials(args)))
        if args.command in ('compare','map','review'):
            from .analysis import compare, application_map, review
            if args.command=='compare':
                data=compare(Engine.load(args.before).state,Engine.load(args.after).state)
            else:
                data=(application_map if args.command=='map' else review)(Engine.load(args.directory).state)
            print(json.dumps(data,ensure_ascii=False,indent=2))
            return 0
        if args.command == 'doctor':
            print(json.dumps(doctor(), ensure_ascii=False, indent=2))
            return 0
        if args.command == 'profile':
            values = Profile.build(args.name).json()
            values.pop('wordlist')  # Use the installed bundled list when importing elsewhere.
            data = json.dumps(values, ensure_ascii=False, indent=2)
            if args.output:
                Path(args.output).write_text(data+'\n')
            else:
                print(data)
            return 0
        if args.command == 'scan':
            values = {'name': args.profile or 'standard'}
            if args.profile_file:
                profile_path = Path(args.profile_file).expanduser().resolve()
                values = json.loads(profile_path.read_text())
                if not isinstance(values, dict):
                    raise ValueError('O perfil JSON deve conter um objeto de configuração')
                if values.get('wordlist'):
                    wordlist = Path(values['wordlist']).expanduser()
                    values['wordlist'] = str(wordlist if wordlist.is_absolute() else profile_path.parent / wordlist)
            if args.profile is not None:
                values['name'] = args.profile
            for key in ('ports', 'max_duration', 'focus', 'wordlist', 'crawl_depth', 'directory_depth', 'rate', 'max_requests', 'content_engine', 'insecure_tls', 'render_js', 'generic_check', 'browser_origins'):
                if getattr(args, key) is not None:
                    values[key] = getattr(args, key)
            if args.modules is not None:
                values['modules'] = args.modules.split(',') if args.modules else []
            p = Profile.build(**values)
            engine = Engine.create(args.output, args.targets, p, args.scope, args.exclude, credentials(args))
            return asyncio.run(execute(engine))
        if args.command == 'resume':
            return asyncio.run(execute(Engine.load(args.directory, credentials(args)), resume=True))
        if args.command == 'export':
            engine = Engine.load(args.directory)
            engine.checkpoint()
            if args.burp:
                from .analysis import burp_archive
                print(burp_archive(engine.root, engine.state))
            else:
                print(archive(engine.root, args.publication, args.redact))
            return 0
        if args.command == 'web':
            import uvicorn
            from .web import create_app
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    listener.bind(('127.0.0.1', args.port))
                except OSError as ex:
                    if ex.errno != errno.EADDRINUSE:
                        raise
                    print(f'A porta {args.port} já está em uso. Se o PenPilot já estiver aberto, acesse http://127.0.0.1:{args.port}.\nPara iniciar outro painel, use: penpilot web --port {args.port + 1 if args.port < 65535 else 8765}', file=sys.stderr)
                    return 1
                app = create_app(args.output, args.directory, args.port)
                listener.listen(2048)
                if args.browser:
                    webbrowser.open(f'http://127.0.0.1:{args.port}')
                print(f'Painel: http://127.0.0.1:{args.port}\nSaídas: {Path(args.output).expanduser().resolve()}\nUse Ctrl+C para encerrar.', flush=True)
                uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=args.port, log_level='warning')).run(sockets=[listener])
            return 0
    except (ValueError, OSError, TypeError, ImportError) as ex:
        print(f'Erro: {ex}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
