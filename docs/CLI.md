# Terminal: comandos e parâmetros

[Início](../README.md) · [Guia completo](USER_GUIDE.md)

Nos exemplos, `penpilot` pode ser substituído por `"/caminho/PenPilot/penpilot.sh"`. Não é necessário estar no diretório do código.

## Descobrir os comandos

```bash
penpilot                  # ajuda geral
penpilot -h               # o mesmo que --help
penpilot --version        # ou -v
penpilot scan -h
penpilot web -h
penpilot resume -h
penpilot profile -h
penpilot export -h
penpilot doctor -h
```

A ajuda de cada subcomando é gerada pelo mesmo parser que processa as opções e contém a referência atualizada.

## Scan

```bash
penpilot scan ALVO [ALVO...] [OPÇÕES]
```

| Opção | Efeito |
| --- | --- |
| `-o`, `--output PASTA` | Diretório de evidências; padrão `~/PenPilot/execucoes` |
| `--profile quick\|standard\|full\|custom` | Intensidade; padrão `standard` |
| `--profile-file JSON` | Carrega configuração de um arquivo; flags explícitas substituem valores |
| `-p`, `--ports PORTAS` | Portas TCP: `80,443,8000-8100` |
| `--scope ALVO...` | IPs, nomes exatos e CIDRs permitidos |
| `--exclude ALVO...` | Remove alvos do escopo |
| `--max-duration TEMPO` | Orçamento, por exemplo `30s`, `15m` ou `1h` |
| `--focus general\|web\|windows` | Foco; Windows/SMB não implica enumeração AD |
| `--modules LISTA` | Lista separada por vírgulas: `http,content,screenshot,smb,ftp` |
| `-w`, `--wordlist ARQUIVO` | Wordlist local, substituindo a do perfil |
| `--crawl-depth N` | Profundidade de links, entre 0 e 5 |
| `--directory-depth N` | Cascata de diretórios: 0 somente base; 1 mais uma geração |
| `--rate N` | Taxa HTTP por alvo, entre 0.1 e 100 req/s |
| `--max-requests N` | Orçamento total HTTP por alvo |
| `--content-engine builtin\|ffuf` | Motor integrado ou ffuf |
| `--insecure-tls` | Aceita certificados não confiáveis neste lab |
| `--smb-user USUARIO` | Pede senha SMB sem eco |
| `--ftp-user USUARIO` | Pede senha FTP sem eco |

Alvos são IPs, hostnames ou CIDRs, sem `http://`. Perfis marcam módulos permitidos: só executam quando o serviço é identificado. Os limites completos, incluindo `concurrency`, `timeout`, `task_timeout`, `max_tasks` e `extensions`, também podem ser definidos no JSON do perfil.

## Trabalhar com um arquivo de perfil

```bash
penpilot profile standard -o "$HOME/perfis/lab.json"
# Edite o JSON no editor de sua preferência.
penpilot scan 10.10.10.5 --profile-file "$HOME/perfis/lab.json" -o "$HOME/Labs"
```

A pasta de destino do perfil precisa existir. O perfil exportado usa a wordlist que acompanha a instalação quando não há campo `wordlist`. Para usar uma lista própria, adicione `"wordlist": "listas/web.txt"`; nesse exemplo, a lista é procurada em `~/perfis/listas/web.txt`, mesmo que o terminal esteja em outra pasta. `--wordlist ./outra.txt` usa a pasta do terminal e tem prioridade.

O perfil contém configurações, não credenciais. Senhas são solicitadas apenas quando você fornece o usuário correspondente.

## Painel, retomada e exportação

```bash
penpilot web -o "$HOME/Labs" --port 8765
penpilot web --open "$HOME/Labs/ID" -o "$HOME/Labs"
penpilot resume "$HOME/Labs/ID"
penpilot resume "$HOME/Labs/ID" --smb-user usuario
penpilot export "$HOME/Labs/ID"
penpilot export "$HOME/Labs/ID" --publication --redact 10.10.10.5
```

`--browser` solicita abertura no navegador padrão. Fechar a aba não interrompe o processo do backend. Use `Ctrl+C` no terminal para encerrar, preservando o checkpoint.

`resume` recebe a pasta da execução e não repete tarefas concluídas. A nova janela de duração mantém o orçamento de requisições já consumido. `export` grava o ZIP dentro da pasta da execução. `--publication` cria uma cópia textual separada para revisão; não publica nada.

## Erros comuns

- **`penpilot: comando não encontrado`**: use o launcher pelo caminho completo ou configure `~/.local/bin` no PATH após instalar.
- **`No module named penpilot`**: use `penpilot.sh` ou o comando instalado; o Python do sistema pode não ser o da instalação.
- **Dependência Python ausente**: execute `bash /caminho/PenPilot/install.sh`.
- **Dependência Nmap/SMB ausente**: consulte `penpilot doctor`; instalar o pacote Python não instala ferramentas do sistema.
- **Pasta ou wordlist não encontrada**: confira a regra dos caminhos relativos acima. Use aspas em caminhos que tenham espaços.
- **Porta 8765 ocupada**: escolha outra com `penpilot web --port 8766`.

Saídas: `0` conclusão; `2` scan parcial/cancelado ou erro de sintaxe de argumentos; `1` erro de entrada em runtime. `-h` e `--version` não iniciam reconhecimento.

## Usar uma URL como alvo

```bash
penpilot scan 'https://lab.exemplo:8443/app/?page=1' --focus web
penpilot scan 'http://lab.exemplo/docs/' 'http://lab.exemplo/admin/'
```

URLs HTTP e HTTPS são aceitas também no campo Alvos do painel. No painel, separe URLs por espaço; no terminal, use aspas para preservar parâmetros. O hostname define o escopo, a porta da URL é acrescentada às portas do perfil e o caminho e a query são usados como ponto inicial quando o protocolo correspondente é confirmado. Fragmentos (`#secao`) são removidos, pois não são enviados ao servidor. URLs com usuário/senha embutidos e outros protocolos são rejeitados.

O reconhecimento continua consultando as demais portas do perfil. Para restringir a descoberta, informe `-p 8443`, por exemplo. O caminho inicial não é uma restrição de escopo: links da mesma origem podem ser seguidos conforme a profundidade configurada. Exclusões e limites continuam sendo aplicados.

## Agente, captura e scanners

Consulte [fluxo completo e exemplos](AGENT_WORKFLOW.md). Ajuda: `penpilot agent -h`, `penpilot repeater -h`, `penpilot capture -h` e `penpilot tools -h`.
