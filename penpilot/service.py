"""Optional per-user systemd service. Installation never starts or enables it."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys


def unit_name(output):
    return 'penpilot-'+hashlib.sha256(str(Path(output).expanduser().resolve()).encode()).hexdigest()[:10]+'.service'


def quote(value):
    return '"'+str(value).replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('$','$$')+'"'


def unit_text(output,port):
    output=Path(output).expanduser().resolve()
    if not 1<=port<=65535:raise ValueError('Porta: 1–65535')
    if any(c in str(output) for c in '\n\r\x00'):raise ValueError('Caminho inválido')
    project=Path(__file__).resolve().parent.parent
    return ('[Unit]\nDescription=PenPilot local web and monitoring\nAfter=network.target\n\n[Service]\nType=simple\n'
            +'WorkingDirectory='+str(project).replace('%','%%')+'\n'
            +'ExecStart='+ ' '.join(quote(v) for v in [sys.executable,'-m','penpilot','web','-o',output,'--port',port])+'\n'
            +'Restart=on-failure\nRestartSec=10\nTimeoutStopSec=120\nUMask=0077\n\n[Install]\nWantedBy=default.target\n')


def manage(action,output,port=8765):
    if not shutil.which('systemctl'):raise ValueError('Este recurso requer systemd com serviços de usuário')
    name=unit_name(output)
    directory=Path(os.environ.get('XDG_CONFIG_HOME',str(Path.home()/'.config')))/'systemd/user'
    if action=='install':
        directory.mkdir(parents=True,exist_ok=True)
        path=directory/name
        path.write_text(unit_text(output,port));path.chmod(0o600)
        result=subprocess.run(['systemctl','--user','daemon-reload'],check=False)
        print(f'Arquivo: {path}\nServiço não iniciado. Use penpilot service start -o {Path(output).expanduser().resolve()}')
        return result.returncode
    if action not in ('start','stop','status'):raise ValueError('Ação inválida')
    if not (directory/name).exists():raise ValueError('Instale primeiro: penpilot service install')
    return subprocess.run(['systemctl','--user',action,name,'--no-pager'],check=False).returncode
