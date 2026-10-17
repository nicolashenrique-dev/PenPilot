# PenPilot

Ferramenta local de reconhecimento para labs autorizados. Funciona pelo terminal ou pelo painel em **http://127.0.0.1:8765**. Resultados ficam em arquivos na pasta escolhida por você.

## Investigação assistida por agente

Captura mitmproxy, Repeater CLI, Nuclei/sqlmap com limites, análise de JS/OpenAPI e contexto paginado: veja o [guia do agente](docs/AGENT_WORKFLOW.md). No painel, abra uma execução e selecione **Agente**.

## Usar nesta máquina, de qualquer pasta

O arquivo de entrada é **`penpilot.sh`**. Ele encontra o código e o ambiente virtual pela localização da instalação, sem mudar a pasta atual do seu terminal.

```bash
# Ajuda geral
"/home/nicolas/Área de trabalho/PenPilot/penpilot.sh" -h

# Ajuda de um comando
"/home/nicolas/Área de trabalho/PenPilot/penpilot.sh" scan -h

# Abrir o painel, guardando resultados na sua pasta Labs
"/home/nicolas/Área de trabalho/PenPilot/penpilot.sh" web -o "$HOME/Labs"
```

Não é preciso executar `cd` para o projeto nem ativar `.venv`. O launcher usa a `.venv` que já existe nesta máquina. Mantenha `penpilot.sh` junto do pacote `penpilot/`; ele é um arquivo de entrada, **não um executável independente que pode ser copiado sozinho**. Pode criar um link simbólico para ele.

## Instalar o comando `penpilot`

Execute uma vez, de qualquer diretório:

```bash
bash "/home/nicolas/Área de trabalho/PenPilot/install.sh"
```

O instalador usa `.venv` no projeto e cria `~/.local/bin/penpilot`. Não exige sudo e configura o PATH em `~/.bashrc` e em `~/.zshrc`, se presente. Abra um novo terminal após instalar. Depois:

```bash
penpilot -h
penpilot --version
penpilot doctor
penpilot web -o "$HOME/Labs"
```

Se o terminal disser `comando não encontrado`, use o caminho `"$HOME/.local/bin/penpilot"` ou ative o PATH nesta sessão:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

O instalador já configura o PATH para os próximos terminais; a linha acima atualiza uma janela que já estava aberta. Se mover a instalação, execute `install.sh` novamente para atualizar o link; um comando existente que pertença a outra instalação não será sobrescrito automaticamente.

## Instalar em outra máquina

Requisitos: Linux/Kali e Python 3.11+ com suporte a `venv`. Copie o projeto, **sem copiar a `.venv`**, para a pasta desejada e execute o instalador pelo caminho correspondente:

```bash
bash /caminho/PenPilot/install.sh --screenshots
# Ferramentas do sistema, se ausentes:
sudo apt install nmap smbclient ffuf
# Se não houver Chromium instalado:
/caminho/PenPilot/.venv/bin/python -m playwright install chromium
```

A instalação pode baixar dependências Python. Nmap é necessário para descoberta; SMB usa smbclient, ffuf é opcional e capturas usam Playwright/Chromium. `penpilot doctor` mostra o diagnóstico. Gobuster, Gowitness e enum4linux-ng são diagnosticados, mas ainda não possuem adaptadores ativos.

## URLs como alvo

Cole `https://lab.exemplo:8443/app/` no campo **Alvos** do painel ou use:

```bash
penpilot scan 'https://lab.exemplo:8443/app/' --focus web
```

A porta é incluída na descoberta e o caminho é preservado para a análise web após confirmar o protocolo. Para várias URLs no painel, separe por espaço. O perfil continua controlando as outras portas e a profundidade da análise.

## Tiro e queda

```bash
penpilot web
```

Abra **http://127.0.0.1:8765**, clique em **Nova execução**, informe o alvo e inicie. As opções avançadas são opcionais.

Sem `-o`, os resultados ficam em **`~/PenPilot/execucoes/ID-DA-EXECUCAO/`**. No painel, veja a tabela de serviços ou clique em **Ver relatório**. Na pasta, abra **`resumo.txt`** ou **`report.html`**. XML/JSON são evidências técnicas preservadas, não o formato principal de leitura.

## Comandos principais

| Quero… | Comando |
| --- | --- |
| Ver ajuda geral | `penpilot -h` |
| Entender opções de scan | `penpilot scan -h` |
| Abrir o painel | `penpilot web -o ~/Labs` |
| Reconhecer um alvo | `penpilot scan 10.10.10.5 --profile quick -o ~/Labs` |
| Escolher portas | `penpilot scan 10.10.10.5 -p 21,80,445,8080 -o ~/Labs` |
| Salvar um perfil | `penpilot profile standard -o ~/perfil.json` |
| Usar um perfil salvo | `penpilot scan 10.10.10.5 --profile-file ~/perfil.json` |
| Retomar trabalho | `penpilot resume ~/Labs/ID-DA-EXECUCAO` |
| Abrir resultados existentes | `penpilot web --open ~/Labs/ID-DA-EXECUCAO -o ~/Labs` |
| Exportar evidências | `penpilot export ~/Labs/ID-DA-EXECUCAO` |

Todos os subcomandos aceitam `-h` e `--help`. Sem argumentos, o programa mostra a ajuda. Use apenas alvos autorizados.

## Onde os arquivos são salvos?

- `-o ~/Labs`: salva na sua pasta Labs, independentemente da instalação.
- `-o ./resultados`: salva em `resultados` dentro da pasta atual do terminal.
- Sem `-o`, scan e web usam **`~/PenPilot/execucoes`**, independentemente da pasta do terminal. O painel e o terminal mostram o caminho exato. Saídas antigas permanecem na pasta original; abra-as com `web --open /caminho/da/execucao`.
- `--profile-file`: caminho para um **arquivo JSON de configuração**. Uma wordlist relativa dentro dele é resolvida em relação à pasta desse JSON.
- `--wordlist`: caminho para um **arquivo de palavras**, relativo à pasta atual do terminal. Essa opção substitui a wordlist do perfil.
- `resume` e `web --open`: recebem a **pasta da execução**, onde está `state.json`; não o arquivo `state.json` sozinho.
- O arquivo `PenPilot-prompt-completo.md` é a especificação do projeto, não um arquivo executável nem um perfil de scan.

Exemplo: se o terminal está em `~/Documentos`, chamar o launcher pelo caminho completo com `-o ./resultados` grava em `~/Documentos/resultados`. O programa não grava automaticamente na pasta do código.

## Documentação

No painel, abra o card **Como usar o PenPilot**: ajuda pesquisável, exemplos copiáveis e explicações sobre saídas, sessões, comparação, Burp e monitoramento. Em telas pequenas, use **Como usar** no topo.

- [Referência CLI e parâmetros](docs/CLI.md)
- [Guia de uso, perfis, evidências e limitações](docs/USER_GUIDE.md)
- [Arquitetura e contrato dos plugins](docs/ARCHITECTURE.md)
- [Validações realizadas](docs/VALIDATION.md)
- [Checklist de implementação](docs/IMPLEMENTATION.md)

## Estado do projeto

MVP funcional: Nmap, HTTP, SMB, FTP, capturas, árvore, cancelamento, retomada e writeups. A interface apresenta busca, detalhes sob demanda e seleção de tentativas anteriores. AD, DNS/subdomínios ativos, UDP e correlação de CVEs continuam pendentes. Veja o guia para as limitações específicas de cada integração.

## Cobertura e relatórios

O painel e o relatório HTML usam tema escuro. `writeup.md` contém o resumo legível; `technical.md` preserva os dados e comandos detalhados. A conclusão indica encerramento das tarefas, não cobertura completa do site.

A coleta extrai URLs de sitemaps, regras do robots.txt e caminhos literais em JavaScript (incluindo chunks em `assets/`). São candidatos, não vulnerabilidades. A navegação continua limitada à origem, escopo, profundidade e orçamento configurados; por padrão faz análise estática. Ative a renderização JavaScript para observar a página e suas requisições GET. Sessões Bearer, Cookie e localStorage podem ser fornecidas em memória. Capturas sem texto visível ficam marcadas como limitadas.

O resumo agrupa respostas com o mesmo corpo salvo, status, origem e tipo de conteúdo. URLs e evidências individuais ficam disponíveis nos detalhes. Respostas HTML iguais em várias rotas são descritas como possível página-base compartilhada, sem concluir acesso à funcionalidade. A cobertura separa URLs com resposta coletada das apenas mencionadas. Relatórios antigos também usam esse agrupamento quando o corpo da resposta está disponível; título semelhante sozinho nunca basta.


## Análise web, sessão e automação

No painel, abra **Nova execução → Navegador e sessão web** para habilitar JavaScript, comparar respostas genéricas e fornecer sessão. As abas **Mapa**, **Revisões**, **Comparar** e **Monitorar** trabalham com as evidências coletadas. **Enviar para Burp** baixa requisições GET reconstruídas e um HAR, sem credenciais e sem valores de query.

```bash
# Renderização real e análise de resposta genérica
penpilot scan 'https://lab.exemplo/' --focus web --render-js
# Solicitar token sem deixá-lo no histórico do terminal
penpilot scan 'https://lab.exemplo/' --http-origin 'https://lab.exemplo' --http-token
# Comparar ou revisar resultados já salvos (sem scan)
penpilot compare /pasta/execucao-anterior /pasta/execucao-atual
penpilot review /pasta/execucao-atual
penpilot map /pasta/execucao-atual
penpilot export /pasta/execucao-atual --burp
# Repetir o modelo a cada hora; Ctrl+C encerra
penpilot watch /pasta/execucao-modelo --interval 1h
```

O monitor do painel funciona enquanto `penpilot web` estiver aberto. Configurações e pausas são preservadas; mudanças e falhas aparecem no histórico e em avisos do painel. Não instala serviço no sistema e não executa coletas quando o processo estiver fechado. Modelos com credenciais usam `watch` com sessão em memória, pois monitores persistentes não salvam segredos. Nenhum monitor é criado automaticamente.

Veja [o guia de análise web](docs/WEB_AUTOMATION.md) para sessões, origens de API, limites e exportação.


## Projetos, sessões e histórico

O painel oferece diagnóstico prévio, importação GET do Burp/cURL, projetos sem credenciais, histórico pesquisável com arquivamento reversível e próximos passos por observação. Compare capturas da mesma URL lado a lado na aba Comparar. O card Como usar explica cada fluxo.

Para manter o painel sem terminal aberto, há `penpilot service install/start/stop/status` (use uma ação por comando). O serviço de usuário systemd é opcional; instalar não inicia nem habilita automaticamente. Consulte [o guia](docs/WEB_AUTOMATION.md) para comandos, limites de sessão e execução em segundo plano.
