import json
import os
import subprocess
from pathlib import Path

import pytest
from penpilot import cli
from penpilot.engine import Engine

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('args', [[], ['-h'], ['--help'], ['--version'], *[[command, '-h'] for command in ('scan', 'web', 'resume', 'profile', 'export', 'doctor')]])
def test_launcher_help_from_other_directory(tmp_path, args):
    result = subprocess.run([str(ROOT / 'penpilot.sh'), *args], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'penpilot' in result.stdout.lower()
    assert not list(tmp_path.iterdir())


def test_symlink_launcher_preserves_cwd_and_portable_profile(tmp_path):
    launcher = tmp_path / 'meu comando'
    launcher.symlink_to(ROOT / 'penpilot.sh')
    result = subprocess.run([str(launcher), 'profile', 'quick', '-o', 'perfil.json'], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    data = json.loads((tmp_path / 'perfil.json').read_text())
    assert data['name'] == 'quick'
    assert 'wordlist' not in data


def test_profile_wordlist_relative_to_file_and_cli_override(tmp_path, monkeypatch):
    profiles = tmp_path / 'meus perfis'
    profiles.mkdir()
    (profiles / 'words.txt').write_text('admin/\n')
    config = profiles / 'lab.json'
    config.write_text(json.dumps({'name': 'quick', 'wordlist': 'words.txt'}))
    caller = tmp_path / 'trabalho'
    caller.mkdir()
    monkeypatch.chdir(caller)
    captured = []
    def create(output, targets, profile, *args):
        captured.append((output, profile))
        return object()
    async def execute(engine, resume=False):
        return 0
    monkeypatch.setattr(Engine, 'create', create)
    monkeypatch.setattr(cli, 'execute', execute)
    assert cli.main(['scan', '127.0.0.1', '--profile-file', str(config), '-o', 'evidencias']) == 0
    assert captured[-1][0] == 'evidencias'
    assert Path(captured[-1][1].wordlist) == profiles / 'words.txt'
    (caller / 'override.txt').write_text('docs/\n')
    assert cli.main(['scan', '127.0.0.1', '--profile-file', str(config), '-w', 'override.txt', '-p', '8080', '--profile', 'custom']) == 0
    assert captured[-1][1].wordlist == 'override.txt'
    assert captured[-1][1].ports == '8080'
    assert captured[-1][1].name == 'custom'


def test_invalid_profile_object_has_actionable_error(tmp_path, capsys):
    config = tmp_path / 'list.json'
    config.write_text('[]')
    assert cli.main(['scan', '127.0.0.1', '--profile-file', str(config)]) == 1
    assert 'objeto de configuração' in capsys.readouterr().err


def test_web_busy_port_is_actionable(tmp_path, capsys):
    import socket
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]
        output = tmp_path / 'unused'
        assert cli.main(['web', '--port', str(port), '-o', str(output)]) == 1
    captured = capsys.readouterr()
    assert 'já está em uso' in captured.err
    assert 'penpilot web --port' in captured.err
    assert 'Painel:' not in captured.out
    assert not output.exists()


@pytest.mark.parametrize('command',['map','review','compare','watch'])
def test_automation_commands_have_help(command,tmp_path):
    result=subprocess.run([str(ROOT/'penpilot.sh'),command,'-h'],cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode==0
    assert command in result.stdout
