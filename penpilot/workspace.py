"""Local projects and reversible history metadata; never store credentials."""
import json
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from .models import Profile, Scope
from .storage import atomic_json


class Workspace:
    def __init__(self, root):
        self.path = Path(root) / '.workspace.json'
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {'projects': [], 'runs': {}}

    def save(self):
        atomic_json(self.path, self.data)

    def project(self, data):
        name = str(data.get('name', '')).strip()
        if not name or len(name)>100: raise ValueError('Nome do projeto: 1–100 caracteres')
        targets = data.get('targets', [])
        allowed = data.get('allowed') or targets
        excluded = data.get('excluded', [])
        if not isinstance(targets,list) or not targets: raise ValueError('Informe os alvos do projeto')
        if not all(isinstance(values,list) and all(isinstance(v,str) for v in values) for values in (targets,allowed,excluded)):
            raise ValueError('Alvos, escopo e exclusões devem ser listas de texto')
        # Persist only explicit configuration; URLs with query values may carry sessions.
        for value in targets+allowed+excluded:
            Scope.normalize(value)
            if '://' in value and urlsplit(value).query:
                raise ValueError('Remova parâmetros de query antes de salvar o projeto; podem conter sessões')
        profile = Profile.build(**data.get('profile', {})).json()
        identity = data.get('id')
        if identity:
            item = next((p for p in self.data['projects'] if p['id']==identity), None)
            if item is None: raise ValueError('Projeto não encontrado')
        else:
            item = {'id': uuid.uuid4().hex[:12]}
            self.data['projects'].append(item)
        item.update(name=name,targets=targets,allowed=allowed,excluded=excluded,profile=profile)
        self.save()
        return item

    def metadata(self, run, data):
        item = self.data['runs'].setdefault(run, {})
        if 'name' in data:
            name=str(data['name']).strip()
            if len(name)>100: raise ValueError('Nome: até 100 caracteres')
            item['name']=name
        if 'archived' in data:
            if not isinstance(data['archived'],bool): raise ValueError('archived deve ser booleano')
            item['archived']=data['archived']
        self.save()
        return item
