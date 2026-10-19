# Validação da versão 0.1.0

## Reconferência — 19/10/2026

- Revisão do código no commit `7e0a001`; ambiente local existente.
- `.venv/bin/python -m pytest -q`: **112 testes passaram em 126,58 s**.
- `node --check penpilot/static/app.js`, `bash -n install.sh penpilot.sh` e `git diff --check`: passaram.
- Painel iniciado com histórico vazio em diretório temporário e porta local separada. Abertura do formulário e prévia de limites verificadas, sem iniciar coleta pela interface; console sem avisos ou erros nesse fluxo.
- README atualizado com captura dessa instância vazia em `assets/painel-inicial.png`, fluxo Mermaid e instruções de clone. Links locais do README e da arquitetura verificados.
- O resultado da suíte não constitui auditoria completa nem garante ausência de falhas. Não houve teste de alvos externos ou ativação de serviço systemd nesta reconferência.

As seções abaixo registram validações históricas; versões, contagens e imagens citadas nelas correspondem às respectivas rodadas.

## Ambiente utilizado

Linux/Kali, Python 3.14.7; Nmap 7.99, ffuf 2.1.0-dev, smbclient 4.24.6, Playwright 1.63.0 com Chromium local. Versões de cada execução estão no manifesto. Foram consultadas as opções efetivamente instaladas antes de construir os comandos.

## Exercícios reais

- Nmap identificou HTTP em porta alta de servidor HTTP de fixture em 127.0.0.1; HTTP foi liberado, SMB/FTP foram ignorados sem iniciar ferramentas.
- ffuf consultou wordlist curta na mesma fixture; saída JSON foi parseada e evidência preservada.
- Servidor SMB Impacket em porta alta, loopback: smbclient anunciou share LAB e confirmou permissão de listagem, coletando `public.txt` como metadado.
- Servidor FTP pyftpdlib em loopback: login anônimo e LIST bem-sucedidos; senha incorreta retornou acesso negado e ficou oculta nas evidências.
- Playwright produziu PNG real da página local com requisições interceptadas pelo coletor. O primeiro ambiente Playwright do sistema tinha driver ausente; o pacote foi instalado dentro de `.venv` e a captura foi repetida com sucesso. A execução parcial inicial foi preservada, sem trocar erro por sucesso artificial.
- CLI executou descoberta, HTTP e screenshot até conclusão; painel reabriu essa pasta, salvou anotação/legenda, criou tentativa 2 por Aprofundar e manteve os arquivos da tentativa 1.
- Painel foi inspecionado no navegador local; prévia, árvore, logs, anotação, retomada visual de pasta e exportação ZIP conferidos. Captura do painel: `painel.jpg`.

## Testes automatizados

A suíte cobre validação de perfis, fixação de DNS/exclusões, decisão por protocolo, redaction, escrita atômica, relatório escapado, ZIP, retomada sem repetir concluídos, isolamento de cancelamento pendente/ativo, encerramento de subprocesso, duração parcial, limite HTTP concorrente, profundidades 0/1/2, respostas negadas, descoberta real em porta não padrão, ffuf real, SMB/FTP reais, ausência de serviço, screenshot real, entidades de diferentes IPs e fronteira Host/Origin/token da API.

Resultado final: **25 testes passaram em 18,19 segundos**. Comando: `.venv/bin/python -m pytest -q`. As fixtures de rede só escutam loopback. Não foram escaneados alvos externos para validar o produto.

Validação sintática do frontend: `node --check penpilot/static/app.js`.

## O que não foi validado

Não há benchmark de desempenho ffuf/Gobuster, interoperabilidade com Windows AD, todas as implementações SMB, autenticação Kerberos, TLS FTP com PKI real ou galerias de SPAs autenticadas. Essas limitações permanecem visíveis no README. Nenhuma vulnerabilidade foi declarada confirmada por banner.

## CLI e uso fora do diretório do projeto

O launcher `penpilot.sh`, o instalador e a ajuda foram revisados. Testes de CLI/Web: **14 passaram**. Cobertura adicional: `-h` de todos os subcomandos, ajuda sem argumentos, `--version`, execução a partir de outra pasta, caminho com espaços, launcher via symlink, exportação de perfil na pasta do terminal, wordlist relativa ao JSON e prioridade das opções explícitas.

A instalação editable foi executada novamente após restringir a descoberta de pacotes a `penpilot`, excluindo resultados em `labs`. O comando em `~/.local/bin/penpilot` foi verificado a partir de `/tmp`. Não houve scan de rede nessa revisão. Scripts shell passaram em `bash -n`; JavaScript passou em `node --check`.

## Destino previsível e resultados legíveis

O padrão de saída agora é `~/PenPilot/execucoes`, independente da pasta do terminal. O painel mostra o destino de novas execuções e a pasta exata da execução aberta. Execuções antigas não são movidas.

Foram adicionados `resumo.txt`, relatório HTML estruturado, tabela de serviços no painel e observações em texto. XML permanece como evidência técnica. A abertura de execução começa pelo alvo, com opções recolhidas.

Validação: 29 testes de resumo, core, CLI e Web passaram. Após o ajuste final de carregamento de históricos, os 4 testes de resumo/Web passaram novamente; `node --check penpilot/static/app.js` passou. O painel e o formulário foram conferidos no navegador com uma execução local existente, sem novo scan. Captura atualizada em `painel.jpg`.

## CDN e redirecionamentos HTTP

O resumo agrupa serviços equivalentes por alvo, porta e identificação, preservando os IPs e arquivos de evidência. Falhas repetidas de captura são agrupadas; os erros completos continuam no histórico técnico. Relatórios antigos podem ser regenerados sem novo reconhecimento.

A coleta web acompanha até cinco redirecionamentos da mesma origem ou a passagem HTTP/80 → HTTPS/443 do mesmo hostname. Continua validando escopo, DNS fixado, exclusões e orçamento em cada requisição. Destinos externos, outras portas e downgrade não são seguidos automaticamente. Uma resposta HTTPS recebida confirma o serviço por HTTP, inclusive quando a sondagem Nmap não identificou o protocolo. Capturas usam a página final e explicam respostas HTTP que impedem a captura.

Validação com fixtures locais e transporte simulado: agrupamento de múltiplos IPs, preservação de evidências, upgrade HTTPS, confirmação por resposta HTTP, bloqueio de mudança de origem/downgrade e ciclos de redirecionamento. Nenhum scan externo foi repetido.

## Tema escuro e cobertura de documentos

Painel, formulário e relatório HTML convertidos para tema escuro. Painel e formulário inspecionados no navegador; prévia em `painel-escuro.jpg`. A instância temporária da validação foi encerrada.

Extração estática de URLs em sitemap (inclusive namespace), robots.txt e strings JavaScript; chunks Vite relativos à raiz; URLs dinâmicas não são executadas. Testes verificam extração, restrição de origem e profundidade. Writeup legível sem blocos JSON repetidos; detalhes preservados em `technical.md`. Cobertura anônima e capturas sem JavaScript explicitadas. Capturas sem texto visível recebem estado limitado com evidência preservada.

Suíte antes do último ajuste de captura: 57 testes passaram. Mais 2 testes de extração passaram; após os ajustes finais, 14 testes de documentos, relatórios e integração passaram. Sintaxe JS validada. Relatórios históricos regenerados sem scan externo.

## Respostas equivalentes e cobertura web

Agrupamento conservador por SHA-256 do corpo salvo, status HTTP, origem, tipo de conteúdo e destino de redirecionamento. Hashes de históricos são derivados apenas de body.txt dentro da pasta da execução; arquivos externos não são lidos. Não há agrupamento apenas por título. URLs e evidências preservadas em detalhes recolhidos. Respostas de status, corpo ou origem distintos permanecem separadas.

O histórico de 14/10 às 00:04 contém 29 URLs com resposta: 25 corpos HTML idênticos e quatro outras respostas, totalizando cinco grupos. Há 135 URLs mencionadas sem resposta coletada; o resumo não as apresenta como endpoints confirmados. Relatórios regenerados sem tráfego para o alvo.

Validação final: 62 testes passaram em 42,18 s; JavaScript validado com node --check. Painel inspecionado no navegador, com prévia em painel-resumo.jpg. Instância temporária encerrada após a validação.

## Automação web e documentação integrada — 14/10/2026

- `.venv/bin/python -m pytest -q`: 81 testes passaram (58,68 s).
- Teste adicional `test_browser_cross_origin_session_and_preflight`: passou; renderização com localStorage e Authorization para API em outra origem, em servidores loopback.
- Verificados: sessão restrita à origem, ocultação de credenciais, bloqueio de escritas, respostas genéricas, mapa, comparação, exportação Burp, recorrência e controles CSRF.
- Interface verificada no navegador: card Como usar no desktop, acesso compacto, busca com/sem resultado e cópia de exemplo. Capturas: `painel-card-docs.png` e `painel-documentacao.png`.
- A invocação inicial com Python do sistema encontrou Playwright incompleto; a suíte acima usa o ambiente `.venv`, utilizado pelo launcher instalado.
- Nenhum monitor real foi ativado e nenhum alvo externo foi consultado nessa validação.

## Fluxo de trabalho e interface — 14/10/2026

- Novo fluxo: diagnóstico DNS/escopo/dependências, importação GET Burp/cURL sem execução, leitura de expiração JWT, projetos sem credenciais e histórico reversível.
- Próximos passos considera a última tentativa e resposta de cada recurso, evitando manter pendências já resolvidas. Comparação visual associa capturas pela URL.
- Testes direcionados após os últimos ajustes: 34 passaram em 25,71 s (`tests/test_workflow.py` e `tests/test_automation_features.py`).
- Unidade systemd validada com `systemd-analyze --user verify`, inclusive instalação em caminho com espaços. A instalação é testada com systemctl simulado: não inicia nem habilita o serviço. O serviço real não foi instalado/ativado nesta validação.
- Navegador: importação de cURL fictício, prévia sem scan, projeto salvo sem token, renomear/arquivar/restaurar, comparação com ambas as imagens carregadas e próximos passos. Sem erros de console. Layout compacto sem overflow horizontal da página.
- Dados de demonstração isolados em `/tmp/penpilot-workflow-preview`; nenhum scan externo ou monitor foi iniciado. Servidor de validação encerrado. Captura: `painel-workflow.png`.
- Suíte completa: 99 testes passaram em 86,36 s. O teste adicional de tentativas resolvidas está incluído nos 34 testes direcionados citados acima, executados após esse ajuste.

## Integração do agente · 2026-10-17

- Suíte completa: `111 passed in 131.81s` com `.venv/bin/python -m pytest -q`.
- Teste acrescentado posteriormente para rascunho de bounty e reconferência de handoff automático: `2 passed, 10 deselected`.
- Ferramentas reais em HTTP loopback: mitmdump 12.2.3 (origem, método e orçamento), Nuclei 3.11.1 (template local com marcador), sqlmap 1.10.9 (parâmetro e limite de requisições). Nenhum alvo público foi testado nesta validação.
- Importação offline de dump `.mitm`, redaction de HAR, revisão/paginação, OpenAPI/JS, Repeater e limites CSRF da API cobertos por testes.
- URL explícita continua com HTTP quando a tarefa de descoberta TCP expira; handoff gerado ao terminar.
- Aba Agente verificada no navegador: busca, expansão de rota e geração de handoff. Captura em `painel-agente.png`.
- Sintaxe JavaScript validada com `node --check`. Não houve teste externo de HTTPS nesta rodada. A economia de tokens não foi medida.
