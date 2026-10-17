# Arquitetura e plugins

```text
CLI / FastAPI + JS local
        ↓
Engine: Scope → Profile → fila → tarefas por host → checkpoint
        ↓                           ↓
Nmap XML → serviços confirmados → plugins compatíveis
                                    ↓
                          entidades / findings / evidências
                                    ↓
                   results.json + HTML + Markdown + ZIP
```

## Componentes

- `models.py`: perfis, canonicalização de URL, allowlist/exclusões, DNS fixado.
- `engine.py`: criação, fila, prioridade, executor de processos, cancelamento, tentativas, eventos e retomada. Subprocessos recebem lista de argumentos, sem shell.
- `plugins.py`: contrato `Plugin` e adaptadores; usa `TaskError(status, reason)` para resultados não bem-sucedidos.
- `storage.py`: escrita atômica, sanitização, relatórios e ZIP.
- `web.py`: API local, jobs independentes da aba, validação de Host/Origin/token, servir evidência inerte.
- `static/`: frontend sem bibliotecas externas nem requests a CDNs.

## Contrato

Cada `Plugin` declara `id`, `protocols`, `dependencies`, `cost`, `authentication`, `queries` e `async run(engine, task)`. `REGISTRY` é o catálogo. Plugins não inventam estados de sucesso: falha deve subir como `TaskError` ou exceção capturada.

- `task`: ID, plugin, node, host, status, motivo, tentativa, prioridade, timestamps, parâmetros, contexto de autenticação e comandos.
- `node`: ID determinístico, tipo, pai primário, todos os pais de origem, label, host, serviço/protocolo/URL e evidência de identificação.
- `finding`: ID, nó, tarefa, título, dados estruturados, origem, contexto de autenticação, confiança, evidências relativas, seleção, anotação e marcador.
- `engine.enqueue`: deduplica por plugin/nó/tentativa, aplica máximo de tarefas e evita ramo cancelado.
- `engine.command`: captura stdout/stderr sanitizados por tarefa, impõe timeout, termina grupo de processos em cancelamento e registra versão/comando/retorno.
- `engine.evidence`: cria arquivo isolado por tarefa, sanitiza texto e retorna link relativo.
- `engine.finding`: inclui resultado estruturado, com origem e sem conclusão de exploração.

Para novo protocolo: implemente a classificação por evidência em `classify`, declare o plugin, adicione a liberação a `schedule`, exponha opção de módulo no perfil e acrescente testes de presença/ausência/negação/timeout. Não agende pelo número da porta sozinho. IDs de entidades não são índices de UI.

## Estado

Tarefas passam de `pending` para `running`, depois `completed`, `failed`, `denied`, `timeout`, `unavailable`, `unsupported`, `skipped`, `cancelled`, `limited` ou `interrupted`. Antes da descoberta, módulos são permissões do perfil; não há tarefas de enumeração executáveis. Os eventos registram a liberação posterior. Falha de um plugin não termina os outros.

Trabalho manual tem prioridade 0; automático, 10. Não preempta tarefas em andamento. Cancelar ramo afeta o nó e descendentes do pai primário da árvore, preservando ramos independentes. As relações adicionais permanecem registradas. Repetir usa novo número de tentativa global, impedindo colisão com tentativas anteriores de subnós.

Um worker por nome de alvo, até `concurrency` alvos simultâneos. A captura do browser usa bloqueio de taxa HTTP por host mesmo quando vários subrecursos chegam simultaneamente. Cada processo externo tem seu grupo POSIX para encerramento de filhos. Lock `flock` impede dois motores executando a mesma pasta. A API não é um coordenador de múltiplos processos.

Checkpoints JSON usam arquivo temporário no mesmo filesystem, `fsync` e `os.replace`. A wordlist é copiada e hasheada. Fechamento abrupto pode perder observações desde o último checkpoint; não corrompe a última versão completa. `events.jsonl` preserva eventos incrementais; a UI recebe os 300 mais recentes.

## Fronteiras de rede

HTTP usa conexão para IP fixado com Host/SNI do nome original, sem proxy do ambiente nem redirects automáticos. Crawler visita só a mesma origem (esquema, host e porta); outras origens ficam como pistas. Assim um link não confirma protocolo de outra porta. Screenshots têm JS/service workers bloqueados, interceptam todas as requisições e passam pelo mesmo fetch. Cabeçalhos de cookies não são reaplicados, e não há sessão HTTP autenticada nesta versão.

FTP passivo conecta ao IP do canal de controle. AUTH TLS é negociado antes de credenciais quando anunciado; FTPS implícito começa em TLS. Diretório inicial é somente listado. SMB autenticação fica em arquivo temporário 0600 fora da pasta de evidência e é removida em `finally`.

A sanitização oculta credenciais fornecidas e headers/keys sensíveis em texto/JSON. Não equivale à remoção de todos os dados sensíveis obtidos no alvo, principalmente imagens. Artefatos originais pertencem ao usuário e ficam no diretório 0700 da execução.

## Fontes de integração consultadas

- [Nmap XML e identificação de serviços](https://nmap.org/book/output-formats-xml-output.html)
- [ffuf: opções e saída estruturada](https://github.com/ffuf/ffuf)
- [Gowitness](https://github.com/sensepost/gowitness)
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

Flags ativas de Nmap, ffuf e smbclient também foram verificadas nas versões locais. O manifesto registra essas versões para cada execução; ferramentas diferentes podem exigir revisão do adaptador.
