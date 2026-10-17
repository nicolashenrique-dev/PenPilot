# Prompt completo — construir o PenPilot

Você deve construir o PenPilot, uma ferramenta local de reconhecimento para labs autorizados, com CLI e interface web em localhost. Use este documento como especificação autossuficiente; não dependa do histórico da conversa.

O objetivo é reconhecimento com um clique, automação condicional por serviço e organização de evidências para writeups. Implemente de forma incremental até obter um fluxo funcional de ponta a ponta. Não entregue apenas mockups ou um plano: os controles devem refletir tarefas e resultados reais. Nunca apresente resultados simulados como execução real.

## Como trabalhar

1. Inspecione o repositório e suas instruções antes de editar. Se ainda não houver projeto, crie uma estrutura apropriada.
2. Transforme os requisitos abaixo em um checklist de implementação e defina o contrato dos plugins antes de integrar ferramentas.
3. Preserve as decisões fechadas: execução local, localhost, Linux/Kali inicialmente, ausência de banco/login/pagamento no MVP, evidências em disco e mesmo motor para CLI/web.
4. Resolva escolhas rotineiras autonomamente. Quando algo estiver descrito como sugestão ou avaliação, escolha uma solução justificada e documente a decisão; não trate toda ideia futura como requisito bloqueante da primeira versão.
5. Priorize descoberta, execução condicional, SMB, FTP, HTTP, árvore, perfis, saída e writeups. Registre funcionalidades futuras ainda não implementadas sem fingir que estão prontas.
6. Verifique as interfaces e opções das versões instaladas das ferramentas. Use saídas estruturadas quando disponíveis e preserve saída original para diagnóstico.
7. Teste o motor e integrações em ambientes controlados. Não escaneie alvos externos arbitrários para validar o projeto.
8. Ao concluir, entregue instalação, comandos de uso, documentação de arquitetura/perfis/plugins, verificações realizadas e limitações concretas.

## Contexto e evolução das decisões

- O nome inicial sugerido foi LabPilot; o nome escolhido na discussão posterior é PenPilot.
- Foram sugeridos `penpilot -c` e `penpilot -l`; a proposta consolidada usa subcomandos claros, pois CLI e web são locais.
- SQLite foi sugerido inicialmente para histórico, mas descartado pelo usuário no MVP. Persistência em arquivos continua desejada para evidências, retomada e writeups.
- O modo web também grava no diretório pelo backend. O navegador não executa as ferramentas e fechar a aba não deve cancelar o trabalho.
- Gobuster foi a primeira opção de descoberta web; ffuf passou a ser candidato ao padrão. Não assumir superioridade universal de velocidade: validar comparativamente.
- enum4linux foi citado pelo usuário; avaliar enum4linux-ng pela integração estruturada. ReconSpider.py foi citado para coleta web; distinguir o crawler de frameworks homônimos.
- A ideia comercial ficou para depois: venda online, aplicativo local e validação de licença por serviço remoto. Não construir um scanner hospedado em nuvem como substituição.

## Especificação consolidada

# PenPilot — planejamento consolidado

Status: ideias e requisitos discutidos; implementação ainda não iniciada. As ferramentas citadas precisam de validação de integração, compatibilidade e licença antes da distribuição comercial.

## Objetivo

Automatizar o reconhecimento de labs autorizados com um clique, executando ferramentas na máquina do usuário. Oferecer interface web em localhost e CLI usando o mesmo motor, salvar evidências em diretórios e facilitar writeups.

## Decisões atuais

- Execução local; interface web em localhost.
- MVP sem login, assinatura ou banco de dados.
- Estado ativo em memória e resultados/estado de retomada em arquivos JSON.
- Uma pasta por execução, com resultados originais e relatórios.
- Fechar a aba não interrompe tarefas enquanto o backend estiver rodando.
- Começar validando utilidade do reconhecimento e do painel; comercialização depois.

## CLI proposta

```bash
penpilot doctor
penpilot web -o ./labs
penpilot scan 10.10.10.5 -o ./labs
penpilot scan 10.10.10.5 --profile standard --max-duration 15m
penpilot resume ./labs/execucao
penpilot web --open ./labs/execucao
```

Os nomes dos comandos são propostas. Preferência por subcomandos claros em vez de flags -c/-l, pois ambos os modos executam localmente.

## Funcionalidades do MVP

1. Cadastro de alvos, escopo permitido, exclusões e perfil de intensidade.
2. Nmap para portas, serviços e possíveis versões, com confiança da identificação.
3. Enumeração adaptativa baseada no protocolo identificado, não apenas na porta.
4. SMB: informações do servidor/protocolo, shares e acesso permitido, anônimo ou com credenciais fornecidas.
5. HTTP/HTTPS: URLs, títulos, tecnologias, redirecionamentos e informações TLS.
6. Gowitness para screenshots e galeria visual.
7. Gobuster para diretórios/arquivos com wordlist e limites configuráveis.
8. Descoberta e resolução de subdomínios para domínios no escopo.
9. Crawler/extrator web para comentários HTML, e-mails publicados, links, scripts, formulários, hostnames e caminhos. Avaliar ReconSpider.py ou Photon; implementação final ainda não escolhida.
10. Correlação de CVEs com fontes e pré-requisitos: distinguir candidato pela versão, compatibilidade de requisitos e verificação específica. Banner não confirma vulnerabilidade.
11. Progresso, logs ao vivo, cancelamento, falhas e resultados parciais.
12. Relatórios HTML/JSON, rascunho Markdown de writeup e download ZIP.

## Organização de saída proposta

```text
labs/2026-10-11_213000/
├── scope.json
├── state.json
├── results.json
├── events.jsonl
├── session.log
├── report.html
├── writeup.md
├── commands/
├── logs/
└── hosts/10.10.10.5/
    ├── nmap/
    ├── web/
    │   ├── screenshots/
    │   ├── gobuster/
    │   └── crawl/
    ├── smb/
    └── cves/
```

Cada tarefa registra comando, horários, versão da ferramenta, status, stdout e stderr. Cada pista web guarda URL de origem e trecho de evidência. Senhas/tokens devem ser ocultados nos registros. A transcrição CLI pode usar script, mas arquivos separados por tarefa são necessários para evitar mistura de saídas paralelas. O modo web também salva tudo pelo backend.

## Interface proposta

- Visão geral: progresso, descobertas e pistas prioritárias.
- Serviços: portas, versões, evidências e ações.
- Web: screenshots, tecnologias, caminhos e pistas extraídas.
- SMB: resultados de enumeração e permissões observadas.
- CVEs/achados: confiança, fontes e requisitos.
- Execuções: tarefas, logs, falhas e controles.
- Ações principais: Reconhecer alvo e Aprofundar esta descoberta.

## Motor e confiabilidade

- Plugins por serviço, fila de tarefas e resultados padronizados.
- Web e CLI compartilham o motor.
- Tarefas independentes em paralelo, com limites por host.
- Deduplicação de URLs, serviços e tarefas.
- Timeout, taxa de requisições, concorrência e orçamento de duração configuráveis.
- Falha em uma ferramenta não interrompe as demais.
- Checkpoints em JSON e retomada pelo diretório.
- Novos domínios, redirecionamentos e links só viram alvos se permitidos pelo escopo.
- Ferramentas e regras conhecidas decidem a execução; IA para interpretação/priorização é possibilidade, não requisito fechado.
- Stack sugerida, ainda não decidida: Python/FastAPI e React. SQLite descartado para o MVP atual.

## Melhorias sugeridas

- Panorama rápido primeiro, aprofundamento depois.
- Filtro de respostas falsas/wildcard no Gobuster.
- Resumo de cobertura: verificado, falhou, pendente e não verificado.
- Botão Copiar para o writeup com Markdown, comando e evidências.
- Anotações e marcadores investigar/descartado/relevante.
- Screenshot manual anexada a achados.
- Escolha da interface/VPN e diagnóstico de acessibilidade.
- Credenciais por sessão e repetição autenticada sem expor segredos.
- Estimativa de tempo baseada na velocidade real.
- Modo aprendizado explicando decisões e resultados.
- Mapa de relações entre hosts, domínios, serviços e achados.
- Ranking de pistas com evidência e justificativa.
- Comparação entre execuções e visualização de pastas anteriores.
- Mais plugins para FTP, DNS, SSH, TLS, NFS e bancos; avaliar verificações selecionadas do Nuclei.

Prioridades sugeridas para melhorar qualidade no MVP: filtro de respostas falsas, cobertura e exportação para writeup. Não foram definidas como compromisso final de escopo.

## Duração

Estimativas de planejamento, ainda sem benchmark: rápido 1–5 minutos por alvo, padrão 5–15, completo 15–60 ou mais. Dependem de portas, latência, aplicações, wordlists, extensões e limites. Resultados aparecem progressivamente. Ao atingir o orçamento de tempo, salvar resultados e pendências para retomada.

## Comercialização futura

Landing page → compra de plano → criação de acesso → download do app → login no localhost → execução na máquina do cliente.

Serviço online valida licença e mantém contas/assinaturas em banco separado. Resultados de reconhecimento continuam locais. Login, pagamentos, licença, preços, funcionamento offline e regras de validação ainda não definidos. Não implementar esta parte antes de validar o núcleo.

## Árvore interativa e cascata

- Interface em árvore: alvo → host/domínio → serviço/porta → URL/diretório → achados e evidências.
- Selecionar qualquer nó para repetir uma tarefa, aprofundar a enumeração ou executar novamente o fluxo aplicável àquele nó.
- Repetição cria uma execução identificada e preserva os resultados anteriores.
- Cascata opcional: novas descobertas disparam tarefas específicas ao seu tipo, dentro do escopo.
- Limites de profundidade, número de tarefas e orçamento de tempo/requisições evitam expansão sem fim.
- Entidades compartilhadas são deduplicadas; relações de origem são preservadas mesmo quando a interface mostra uma árvore.
- Cada nó mostra status, origem da descoberta, tarefas e evidências.

## Velocidade e escolha de ferramenta web

- Avaliar ffuf como motor principal de descoberta de conteúdo; Gobuster pode permanecer como alternativa.
- Não há conclusão de que ffuf é sempre mais rápido. Comparar em lab controlado com a mesma wordlist, concorrência, limite de taxa, timeout e comportamento HTTP.
- ffuf oferece recursão, limites globais/por tarefa de tempo, filtros, auto-calibração e saída estruturada. Confirmar suporte na versão integrada.
- Reduzir trabalho: crawl inicial, wordlist pequena primeiro, extensões orientadas por evidências, aprofundamento seletivo e deduplicação.
- Ajustar concorrência pela latência e erros; reduzir ritmo em 429/timeouts. Limite agregado por host vale para todos os plugins juntos.
- Medir duração, requisições por segundo, erros e cobertura/achados para avaliar desempenho sem sacrificar qualidade.

## Perfis e modo personalizado

- Definir modos explícitos: Rápido, Padrão, Completo e Personalizado.
- Separar intensidade do foco: Geral, Web e Windows/SMB, permitindo combinações.
- Modo Personalizado na interface web: seleção de módulos e ferramentas, portas TCP/UDP, wordlists, extensões, profundidade de crawl/cascata, concorrência, taxa por host, timeout, orçamento de tempo, screenshots, CVEs e contexto de autenticação.
- Salvar/carregar configurações de perfil em JSON ou YAML para reproduzir no CLI, sem banco.
- Mostrar resumo das tarefas habilitadas e dependências antes de iniciar. Módulos sem pré-requisitos ficam aguardando descoberta ou são ignorados com justificativa.
- Mesmos perfis disponíveis para execução inicial ou aprofundamento de nó na árvore.
- Avaliar enum4linux-ng como plugin SMB/Windows/Samba: saída JSON/YAML, enumeração seletiva e verificações condicionais favorecem integração.
- Não presumir Windows apenas por SMB aberto. Usar evidências de serviço/SO e indicação manual opcional.
- No foco Windows, agendar módulos específicos de SMB/RPC e, quando descobertos e aplicáveis, LDAP, DNS e RDP. Nenhuma enumeração de AD sem evidência correspondente.
- Evitar sobreposição entre enum4linux-ng e NSE; tarefas equivalentes devem ser reaproveitadas ou executadas como confirmação explícita.

## Enumeração por serviço — prioridade atual

- SMB é prioridade do MVP, pois é uma das etapas que o usuário mais deseja automatizar.
- Incluir FTP no MVP: identificação/banner, suporte a TLS, teste de acesso anônimo e listagem de diretórios/arquivos quando permitida. Usar credenciais fornecidas se configuradas. Guardar metadados e evidência; download em massa, upload e alterações não são parte da enumeração padrão.
- Expandir por plugins para DNS, SSH, SMTP, SNMP, NFS, LDAP, RDP e bancos conforme protocolo descoberto e acesso disponível.
- Cada plugin declara pré-requisitos, consultas disponíveis, custo/limites, contexto de autenticação e formato de saída.
- Cada serviço ganha um nó na árvore com resultados, evidências e ações Repetir/Aprofundar.
- Diferenciar acesso negado, consulta não suportada, timeout e ausência de resultados.
- Meta: automatizar enumeração repetitiva para todos os serviços suportados, sem prometer cobertura universal nem executar tarefas irrelevantes.

## Regra obrigatória de execução condicional

- Módulos de enumeração só entram na fila após descoberta confirmar serviço/protocolo compatível e acessível.
- Habilitar um módulo no perfil significa permitir sua execução se os pré-requisitos forem satisfeitos, não executá-lo em todos os alvos.
- Porta aberta isoladamente não confirma protocolo. Se a identificação for inconclusiva, fazer uma sondagem curta de confirmação antes da enumeração completa.
- Ausência do serviço resulta em tarefa ignorada com justificativa, sem iniciar a ferramenta de enumeração correspondente.
- Descobertas posteriores podem satisfazer pré-requisitos e liberar novas tarefas dentro do escopo.
- Repetir/Aprofundar um nó mantém a mesma checagem; resultados antigos podem exigir uma confirmação curta de disponibilidade.
- Registrar serviço detectado, evidência de identificação e motivo de execução/ignoramento no estado e painel.

## Controle de profundidade da cascata HTTP

- Opção explícita na interface HTTP e no perfil personalizado: profundidade máxima da cascata de descoberta de diretórios.
- Definição: nível 0 enumera somente a URL base selecionada, sem gerar tarefas recursivas; nível 1 enumera também os diretórios encontrados na base; nível 2 permite mais uma geração, e assim sucessivamente.
- Profundidade é relativa ao nó selecionado, inclusive ao usar Aprofundar na árvore.
- Separar profundidade da cascata de diretórios da profundidade do crawler de links; são controles distintos.
- Mostrar estimativa/aviso de expansão de tarefas junto ao controle, sem promessa de tempo fixo.
- Aplicar conjuntamente limites de tarefas, requisições e duração, deduplicação e escopo. Não usar recursão ilimitada como padrão.
- Sugestão de padrão inicial: uma geração adicional (nível 1), sujeita a validação de desempenho.
- Registrar profundidade configurada e motivo de interrupção de ramos no estado, painel e relatório.

## Controles adicionais aprovados

- Prévia da execução com módulos, wordlists, profundidade e limites; mostrar tarefas liberadas conforme serviços são descobertos.
- Cancelar um ramo da árvore sem interromper tarefas de outros ramos. Cancelar também tarefas descendentes pendentes desse ramo.
- Aprofundamento manual tem prioridade sobre tarefas automáticas pendentes, respeitando limites por host; não interrompe tarefas em execução automaticamente.
- Repetir um nó cria tentativa identificada, preservando evidências anteriores e permitindo comparação.
- Suporte inicial proposto e aceito: Linux/Kali; ampliar após validar dependências e instalação.

## Windows e Active Directory

- Perfil Windows/AD com descoberta condicional de SMB/RPC, LDAP/LDAPS, DNS, Kerberos, RDP e WinRM.
- Windows, SMB aberto ou LDAP aberto isoladamente não confirmam Active Directory nem controlador de domínio.
- Cruzar evidências antes de liberar consultas específicas de AD; guardar origem e confiança da inferência.
- SMB/RPC: informações do servidor/domínio, shares e dados permitidos pelo contexto de acesso.
- LDAP/LDAPS: descoberta de informações públicas do diretório e consultas autenticadas quando houver credenciais e permissões.
- DNS: registros de identificação do domínio e serviços, dentro do escopo.
- Kerberos: identificação do serviço como pista de AD; sem rotinas de ataque a contas no perfil de reconhecimento.
- RDP: informações disponíveis na negociação. WinRM: identificação e disponibilidade do endpoint.
- Cartão de resumo do domínio: domínio DNS, hostname, possível controlador e evidências.
- Contextos sem credenciais e com credenciais fornecidas; mostrar contexto de autenticação por resultado sem expor segredos.
- Diagnóstico de resolução DNS e diferenças de horário quando houver evidências disponíveis, para explicar falhas de conexão/autenticação.
- Separar serviço detectado, autenticação bem-sucedida e consulta autorizada; não presumir que descoberta implica acesso.
- Enumeração padrão não altera o diretório ou serviços.

## Critérios de validação dos plugins

- Validar em labs controlados: serviço presente, serviço ausente, identificação inconclusiva, acesso negado e timeout.
- Serviço ausente não inicia enumeração; acesso negado/erro nunca vira ausência de achados.
- Validar limites de escopo, deduplicação, cancelamento de ramo, retomada e preservação de tentativas.
- Comparar desempenho com configuração equivalente e verificar cobertura, além de duração.

## Writeups como objetivo central

- Toda execução deve produzir material organizado para writeups, além de automatizar reconhecimento.
- Manifesto da execução: configuração efetiva, escopo, horários, versões das ferramentas e identificação/hash das wordlists, sem credenciais ou tokens.
- Rascunho writeup.md com alvo, metodologia, serviços, descobertas, comandos reproduzíveis com segredos ocultados, evidências e limitações.
- Links relativos para screenshots e saídas, mantendo o pacote utilizável após mover a pasta ou extrair o ZIP.
- Origem de cada descoberta e contexto de autenticação documentados; separar observações confirmadas de hipóteses/CVEs candidatas.
- Linha do tempo, anotações manuais e tentativas preservadas ajudam a reconstruir a investigação.
- Botão Copiar para o writeup por achado e exportação do pacote completo.
- O rascunho descreve apenas o que foi executado/observado; não inventar exploração, impacto ou conclusão ausente nas evidências.

## Próximo passo proposto

Fechar escopo da primeira versão, definir fluxo de execução e contrato dos plugins; então implementar motor, saída organizada e interface. Nenhum scanner foi construído ou executado nesta conversa.

## Complementos finais discutidos que também devem ser preservados

### Exportação para publicação

- Oferecer seleção dos achados que entram no writeup; evitar relatório narrativo cheio de resultados irrelevantes.
- Preparar uma cópia de publicação com revisão/ocultação de dados sensíveis em textos, logs e screenshots: senhas, tokens, cookies e dados pessoais.
- Preservar evidências originais separadas da cópia sanitizada. Isso não autoriza gravar credenciais fornecidas em logs: elas devem ser ocultadas desde a coleta. Os originais podem conter outros dados sensíveis obtidos como evidência.
- Não prometer sanitização automática perfeita, principalmente em screenshots. Mostrar o material para revisão antes de exportação/publicação.
- Exportação gera arquivos locais; não publica automaticamente em serviços externos.

### Checklist de pendências do writeup

- Evidências sem descrição.
- Screenshots sem legenda.
- Hipóteses não verificadas.
- Etapas interrompidas, falhas e consultas pendentes.
- Diferenciar pendência de documentação e pendência de reconhecimento.

### Visualização e relações

- A árvore é a navegação principal para investigar; o mapa de relações é uma melhoria complementar.
- Um serviço/endpoint pode ter mais de uma origem de descoberta: preservar essas relações sem duplicar tarefas.
- Galeria web exibe screenshot, URL, título e tecnologias quando disponíveis.
- Ordenação/priorização de pistas deve vir acompanhada de evidência e justificativa, sem alegar vulnerabilidade confirmada só pela versão.

### Perfis de execução e autenticação

- Rápido, Padrão, Completo e Personalizado controlam intensidade; foco Geral, Web e Windows/AD controla seleção de módulos.
- Autenticado é contexto de execução com credenciais fornecidas, não uma obrigação de tentar autenticação em todos os serviços.
- Testes que alteram estado seriam uma funcionalidade separada e futura. O núcleo discutido é reconhecimento/enumeração.
- Dentro do personalizado, deixar claro que módulo marcado só será executado se o serviço existir e os pré-requisitos forem satisfeitos.

### Dados e reprodutibilidade

- Manifesto deve incluir identidade da execução, configuração efetiva, versões, timestamps com fuso/offset e hashes de wordlists quando aplicável.
- Arquivos por ferramenta/tarefa, stdout e stderr separados, eventos estruturados e transcrição de terminal atendem objetivos diferentes; a transcrição não substitui resultados estruturados.
- O utilitário `script` pode ser usado para a sessão CLI se disponível. O modo web precisa do registro próprio do backend.
- Preservar tentativas anteriores em vez de sobrescrever. Reexecução deve permanecer associada ao nó investigado.

## Diretrizes técnicas para tornar os requisitos concretos

Estas são orientações de implementação derivadas dos requisitos, não decisões históricas adicionais:

- Preferir invocação de processos com argumentos estruturados, sem concatenar entrada do usuário em shell.
- Vincular o servidor a 127.0.0.1 por padrão, controlar origem das requisições e impedir que conteúdo de evidências execute scripts no painel/relatório.
- IDs de entidades e tarefas devem permitir deduplicação, associação de evidências e retomada consistente.
- Distinguir estados aguardando descoberta, pendente, em execução, concluído, falhou, ignorado, cancelado e interrompido por limite.
- Escrita de checkpoints deve evitar arquivo parcialmente atualizado. Encerramento do backend deve preservar pendências e finalizar processos filhos adequadamente.
- Perfis exportáveis precisam guardar opções efetivas para que CLI e web tenham comportamento equivalente.
- Mostrar dependência ausente como indisponibilidade concreta, não como serviço ausente no alvo.
- Caso não seja viável controlar exatamente a taxa agregada de ferramentas externas, declarar a limitação e aplicar controle conservador de agendamento/configuração; não exibir limite fictício como garantido.

## Critérios de aceite para o primeiro fluxo funcional

- `penpilot doctor` diagnostica dependências e apresenta instruções úteis.
- CLI e localhost iniciam uma execução usando o mesmo motor e diretório de evidências.
- Descoberta libera somente módulos compatíveis; ausência de SMB/FTP/HTTP não inicia os respectivos enumeradores.
- Serviço em porta não convencional é tratado pelo protocolo identificado.
- HTTP gera screenshot, pistas e descoberta de conteúdo conforme perfil e disponibilidade.
- SMB e FTP registram resultados ou motivos específicos de falha/acesso negado.
- Árvore atualiza progressivamente e permite repetir/aprofundar um nó com tentativa preservada.
- Profundidade 0/1/2 respeita a definição explícita; crawler e cascata de diretórios têm limites independentes.
- Cancelar ramo não cancela outras tarefas; limite de tempo salva estado e resultados parciais.
- Retomada não repete tarefas concluídas desnecessariamente.
- Logs não expõem credenciais fornecidas.
- Relatório, Markdown e ZIP mantêm evidências acessíveis por links relativos.
- Resumo de cobertura e checklist deixam claras as limitações da execução.
- O README diferencia funcionalidades implementadas, dependências opcionais e roadmap.

## Referências citadas durante a discussão

Consultar documentação atual e a versão efetivamente integrada:

- Nmap NSE: https://nmap.org/book/nse-usage.html
- NVD/CPE: https://nvd.nist.gov/developers/products
- NVD/CVE: https://nvd.nist.gov/developers/vulnerabilities
- Gowitness: https://github.com/sensepost/gowitness
- Gobuster: https://github.com/OJ/gobuster
- ffuf: https://github.com/ffuf/ffuf
- enum4linux-ng: https://github.com/cddmp/enum4linux-ng
- Photon: https://github.com/s0md3v/Photon
- Nuclei: https://github.com/projectdiscovery/nuclei
- Exemplo de ReconSpider.py mencionado: https://gist.github.com/ZishanAdThandar — validar origem, versão e licença; não tratar esse perfil como um repositório oficial fechado.

## Resultado esperado

Uma ferramenta local que poupa enumeração repetitiva, mostra descobertas e suas relações, permite aprofundamento seletivo e entrega uma pasta de evidências pronta para apoiar um writeup. Velocidade, cobertura e rastreabilidade devem ser avaliadas juntas. A primeira implementação deve validar esse núcleo; contas, pagamentos e licenças ficam no roadmap comercial.
