# Guia de uso do PenPilot

[Voltar ao início](../README.md) · [Referência CLI](CLI.md)

## Uso

```bash
penpilot scan 10.10.10.5 -o ./labs
penpilot scan 10.10.10.5 --profile standard --max-duration 15m
penpilot scan 10.10.10.5 --ports 21,80,445,8080 --focus web
penpilot scan 10.10.10.0/28 --exclude 10.10.10.1 --profile quick
penpilot scan lab.exemplo --scope lab.exemplo --profile quick
penpilot profile standard -o meu-perfil.json
penpilot scan 10.10.10.5 --profile-file meu-perfil.json
penpilot scan 10.10.10.5 --smb-user usuario --ftp-user usuario
penpilot resume ./labs/ID-DA-EXECUCAO
penpilot resume ./labs/ID-DA-EXECUCAO --smb-user usuario
penpilot web --open ./labs/ID-DA-EXECUCAO
penpilot export ./labs/ID-DA-EXECUCAO
penpilot export ./labs/ID-DA-EXECUCAO --publication --redact 10.10.10.5
```

Use apenas alvos do seu lab/escopo autorizado. Alvos não são URLs; informe host e `--ports`. O escopo padrão é exatamente o alvo informado. CIDRs são limitados a 256 endereços. Hostnames são exatos, sem wildcard; resolução inicial é fixada para HTTP/Nmap/SMB/FTP e IPs excluídos são bloqueados. Um nome permitido autoriza seus IPs resolvidos nessa execução. Alterações de DNS durante a execução não adicionam alvos.

Senhas são solicitadas sem eco pelo CLI ou inseridas no formulário local. Não entram no perfil, manifesto ou argumentos de processos. SMB usa arquivo temporário 0600, removido ao terminar, com autenticação fornecida somente ao plugin SMB. FTP usa o contexto FTP; não há tentativa automática em outros protocolos. Depois de reiniciar, reintroduza credenciais usando `resume --smb-user/--ftp-user`.

O código de saída do scan é `0` para conclusão, `2` para parcial/cancelado e `1` para erro de entrada. Acesso negado produz execução parcial, mesmo quando a resposta foi corretamente coletada.

## O que está implementado

- **Descoberta Nmap TCP:** XML, identificação por protocolo em portas convencionais ou não, versão, CPE, método e confiança. Enumeração só é liberada por identificação `probed` com confiança >=7. Portas apenas tabeladas passam por confirmação adicional. Sem serviço compatível, o módulo fica ignorado com motivo.
- **HTTP/HTTPS:** status, headers sanitizados, título, banners de tecnologia (sem fingerprinting universal), redirecionamento observado, detalhes TLS, comentários HTML, e-mails, links, scripts e formulários. Respostas originais textuais ficam separadas dos resultados estruturados. Não submete formulários.
- **Crawler e conteúdo:** controle independente de profundidade; coletor integrado ou ffuf; wordlist e extensões configuráveis; baseline para reduzir respostas wildcard; deduplicação; limites de tarefas, duração e HTTP/host. URLs de outra origem são pistas, não visitadas automaticamente.
- **Screenshots e galeria:** PNG real com Playwright. JavaScript desabilitado por padrão; pode ser habilitado em Navegador e sessão web. Requisições GET são intermediadas pelo motor, usando escopo, DNS fixado e orçamento. Origens adicionais exigem configuração explícita. POST, WebSocket e interações automáticas ficam bloqueados. Sessões podem ser fornecidas em memória; consulte WEB_AUTOMATION.md.
- **SMB:** `smbclient -L` e listagem `ls` de até 20 shares Disk. Diferencia share anunciado de acesso realmente permitido. Anônimo ou credenciais fornecidas, com evidência bruta e erro específico. Não presume Windows ou AD.
- **FTP:** banner, FEAT, autenticação anônima/fornecida, SYST, PWD e LIST do diretório inicial; TLS explícito/implícito e dados protegidos quando disponíveis. Conexão passiva fixada ao IP do alvo (ignora IP arbitrário anunciado por PASV). Sem upload/download de conteúdo de arquivos.
- **Motor:** fila condicional; hosts em paralelo, um processo/tarefa por alvo de cada vez; prioridades manuais; cancelamento de ramo; checkpoint atômico; bloqueio de execução por diretório; SIGINT/SIGTERM encerra processos filhos; retomada de tarefas interrompidas sem refazer concluídas.
- **Painel:** árvore progressiva, detalhes, prévia, perfis JSON, logs por tarefa, histórico, repetição e aprofundamento com disponibilidade reconfirmada, seleção de achados, anotações, marcadores, cópia Markdown e download ZIP.
- **Evidências:** manifesto, hashes de wordlist, versões, horários com offset, comandos e stdout/stderr separados, linha do tempo, JSON, HTML escapado, Markdown e checklist. Tentativas novas têm IDs/pastas distintas.
- **Publicação local:** cópia textual separada com substituições escolhidas pelo usuário. Nunca publica externamente. Screenshots e logs originais são deliberadamente omitidos dessa cópia para revisão manual.

## Perfis e profundidades

| Intensidade | Duração | HTTP/host | Crawl | Diretórios | Portas |
| --- | ---: | ---: | ---: | ---: | --- |
| quick | 300 s | 80 | 0 | 0 | lista curta |
| standard | 900 s | 300 | 1 | 1 | lista curta |
| full | 3600 s | 1000 | 2 | 2 | 1–65535 TCP |
| custom | configurável | configurável | 0–5 | 0–5 | configurável |

`quick` habilita HTTP, SMB e FTP. Os outros presets habilitam também conteúdo e screenshot. Foco `web` permite HTTP/conteúdo/screenshot. Foco `windows` mantém SMB e HTTP, sem rotinas de AD nesta versão. Módulo habilitado significa **permitido quando aplicável**, não executado em todo alvo.

Diretórios: 0 enumera só a base, 1 enumera também diretórios encontrados na base, 2 mais uma geração. Ao aprofundar um nó, ele vira a base de uma nova tentativa com as profundidades do perfil atual. Repetir/aprofundar ainda não abre um editor de perfil específico por ação; ambos reconfirmam disponibilidade e executam os módulos aplicáveis. O botão aprofundar é especialmente útil num diretório selecionado. A configuração é reaproveitada sem mutar tentativas anteriores.

O crawler tem outro contador. Uma descoberta de conteúdo pode iniciar um novo crawl relativo àquela URL, ainda sujeito a deduplicação e orçamento global. Diretórios que não usam `/` final nem redirecionam para essa forma podem não gerar cascata.

## Retomada e limites

`resume` abre nova janela de duração e retoma `interrupted`, `running` residual, `limited` e `unavailable`. Mantém os contadores HTTP e o teto de tarefas da execução; não burla orçamento já esgotado. Para um novo orçamento use nova execução com perfil ajustado. Erros, acesso negado e cancelamentos explícitos não são repetidos automaticamente: use Repetir no nó. `full` não garante varredura completa dentro do orçamento.

No processo HTTP interno a taxa e o total são controlados por alvo. Screenshots também consomem esse total. Nmap controla pacotes conservadoramente; SMB/FTP não equivalem a requisições HTTP. Não há garantia de taxa exata agregada entre ferramentas externas. Aliases de host informados como alvos separados têm orçamentos separados.

ffuf: somente URLs com IP fixo, sem seguir redirects, com worker único, rate/delay e limite temporal; candidatas são reservadas no orçamento antes da execução (contagem conservadora, não métrica exata de tráfego efetivo). HTTPS via ffuf requer `insecure_tls` explícito; para validação de certificado use o motor integrado. Não foi concluído benchmark comparativo com Gobuster, portanto não há alegação de superioridade de velocidade.

Fechar a aba não interrompe o backend. Encerrar o backend pausa o trabalho e preserva o checkpoint. O processo do backend deve permanecer rodando para continuar scans.

## Arquivos

```text
labs/ID/
  manifest.json       # configuração efetiva, versões e hash da wordlist
  scope.json          # allowlist, exclusões, DNS fixado
  state.json          # tarefas, entidades, anotações e retomada
  results.json        # entidades e descobertas
  events.jsonl        # eventos completos
  session.log         # transcrição do motor
  wordlist.txt        # cópia para reprodutibilidade
  resumo.txt          # leitura rápida, sem XML/JSON
  report.html         # relatório formatado para leitura
  writeup.md
  commands/ID.json
  logs/ID.stdout.log
  logs/ID.stderr.log
  hosts/HASH/PLUGIN/TAREFA/...
```

O hash de host evita usar nomes de alvos como caminhos. Todos os links de evidência nos relatórios são relativos. O ZIP completo preserva essa estrutura. Não mova/edite uma pasta enquanto sua execução estiver ativa. Não abra o mesmo diretório para mutações simultâneas na CLI e no painel; a trava protege execução concorrente, não edições de anotações de outro processo.

O HTML exportado mostra tabelas, observações legíveis e links técnicos; o painel serve HTML bruto como `text/plain`, para não executar conteúdo coletado. API restrita ao Host localhost e mutações com token de sessão/origem validada. O serviço só escuta 127.0.0.1; não exponha via proxy. Não é uma aplicação multiusuário.

## Validação

```bash
pip install -e '.[test,screenshots]'
pip install pyftpdlib impacket  # somente fixtures de teste FTP/SMB
python -m pytest -q
node --check penpilot/static/app.js
```

A suíte usa Nmap/ffuf reais contra HTTP loopback, SMB local via Impacket, FTP local via pyftpdlib e Chromium para PNG. Fixtures são identificadas como fixtures, e seus resultados vêm de conexões reais; nunca substituem saída de scan do usuário. Inclui protocolo em porta não convencional, serviço ausente, acesso negado, timeout, cancelamento, retomada, deduplicação, escopo, sanitização, exportação e cascata 0/1/2. Testes de SMB/FTP/screenshot são pulados quando seus pacotes de teste não estão instalados. Para screenshot, instale também o navegador.

Lab HTTP interativo, em dois terminais:

```bash
python scripts/local_lab.py
penpilot scan 127.0.0.1 --ports 18081 --modules http,content,screenshot --max-duration 90s
```

O servidor de fixture só escuta 127.0.0.1:18081. As execuções deixadas em `labs/` nesta implementação são testes locais identificados pelas evidências, não demonstrações simuladas.

## Limitações e roadmap

- Não implementados: DNS/subdomínios ativos, UDP, NVD/CVE, consultas de AD/LDAP/Kerberos/RDP/WinRM, SSH/NFS/bancos, Nuclei. Serviços desses tipos podem aparecer no Nmap, mas não têm enumeradores. Não há cartão de AD/CVE inventado.
- Gobuster, enum4linux-ng e Gowitness: referências avaliadas, adaptadores pendentes. Implementação escolhe smbclient, coletor próprio/ffuf e Playwright para o fluxo inicial.
- TLS FTP está implementado; a integração automatizada atual cobre FTP simples e HTTPS precisa de validação adicional com PKI de lab. Nenhuma promessa de interoperabilidade universal com servidores SMB/FTP.
- Retomada reexecuta a tarefa interrompida inteira (mantendo logs acumulados dessa tentativa); novas repetições preservam tentativas anteriores. Não existe checkpoint dentro de cada wordlist.
- Uma única configuração por execução; comparação visual entre tentativas, editor de perfil ao aprofundar, anexos manuais, mapa de relações, VPN/interface, estimativas e modo aprendizado ficam pendentes.
- Filtro wildcard heurístico por corpo/status/tamanho pode omitir páginas legítimas de mesmo tamanho. Evidência de baseline fica disponível para revisão.
- Respostas HTTP e listagens FTP limitadas a 2 MiB; stdout/stderr de processos limitados a 16 MiB. Não coleta arquivos em massa.
- Exportação de publicação **é uma cópia textual para revisão**, com links de evidência omitida; não é pacote pronto para publicação. Não sanitiza pixels nem promete remover todos os dados pessoais. Preserve e revise os originais separadamente.
- Nenhum login, pagamento, licença comercial ou distribuição de binários de terceiros. Revisão de licenças necessária antes de distribuição comercial.

[Arquitetura e contrato dos plugins](ARCHITECTURE.md) · [Checklist e decisões](IMPLEMENTATION.md)
