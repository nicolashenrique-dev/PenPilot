import asyncio
import contextlib
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from penpilot.engine import Engine
from penpilot.models import Profile


def ready_service(tmp_path, port, protocol, credentials=None):
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick',modules=[protocol],ports=str(port),task_timeout=25,timeout=3),credentials=credentials)
    host=e.state['nodes'][0]
    service=e.node('service',protocol,host['id'],host='127.0.0.1',port=port,protocol=protocol,ip='127.0.0.1')
    e.state['tasks'][0]['status']='completed'
    t=e.enqueue(protocol,service['id'])
    return e,t


@pytest.fixture
def ftp_server(tmp_path):
    pytest.importorskip('pyftpdlib')
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    root=tmp_path/'ftp-root';root.mkdir();(root/'evidence.txt').write_text('public fixture')
    auth=DummyAuthorizer();auth.add_anonymous(str(root),perm='elr');auth.add_user('lab-user','lab-password',str(root),perm='elr')
    class Handler(FTPHandler): pass
    Handler.authorizer=auth
    Handler.auth_failed_timeout=.1
    server=FTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,kwargs={'timeout':.1},daemon=True);thread.start()
    yield server.socket.getsockname()[1]
    server.close_all();thread.join(timeout=2)


def test_ftp_real_anonymous_listing(tmp_path,ftp_server):
    e,t=ready_service(tmp_path/'runs',ftp_server,'ftp')
    asyncio.run(e.run())
    assert t['status']=='completed',t
    finding=e.state['findings'][0]
    assert finding['data']['authenticated'] and 'evidence.txt' in finding['data']['listing']
    assert list(e.root.rglob('transcript.txt'))


def test_ftp_denied_and_credential_redaction(tmp_path,ftp_server):
    e,t=ready_service(tmp_path/'runs',ftp_server,'ftp',{'ftp':{'username':'lab-user','password':'wrong-secret'}})
    asyncio.run(e.run())
    assert t['status']=='denied',t
    for file in e.root.rglob('*'):
        if file.is_file():
            assert b'wrong-secret' not in file.read_bytes() and b'lab-user' not in file.read_bytes()


def test_smb_real_share_listing(tmp_path):
    pytest.importorskip('impacket')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    share=tmp_path/'share';share.mkdir();(share/'public.txt').write_text('controlled SMB fixture')
    script="from impacket.smbserver import SimpleSMBServer; import sys; s=SimpleSMBServer(listenAddress='127.0.0.1',listenPort=int(sys.argv[1])); s.setSMB2Support(True); s.addShare('LAB',sys.argv[2],'controlled fixture'); s.start()"
    proc=subprocess.Popen([sys.executable,'-c',script,str(port),str(share)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1): break
            except OSError: time.sleep(.05)
        e,t=ready_service(tmp_path/'runs',port,'smb')
        asyncio.run(e.run())
        assert t['status']=='completed',t
        assert any(f['data'].get('share')=='LAB' and f['data']['access']=='listing allowed' for f in e.state['findings'])
    finally:
        proc.terminate()
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()


def test_closed_service_does_not_launch_enumeration(tmp_path):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    e=Engine.create(tmp_path,['127.0.0.1'],Profile.build('quick',ports=str(port)))
    asyncio.run(e.run())
    assert not [n for n in e.state['nodes'] if n['kind']=='service']
    assert all(t['status']=='skipped' and not t['commands'] for t in e.state['tasks'] if t['plugin']!='discovery')
