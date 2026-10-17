# Análise web e automação

## Começar pelo painel

1. Execute `penpilot web` e abra **Nova execução**.
2. Informe uma URL. Em **Navegador e sessão web**, marque **Renderizar JavaScript** para observar uma aplicação dinâmica.
3. Para uma área logada, informe a **origem exata** e um Bearer ou Cookie da sua própria sessão de teste. Os valores ficam somente na memória do processo, são apagados do formulário ao iniciar e não entram no perfil, manifesto ou exportação para Burp.
4. Inicie. Consulte **Mapa** para relações e chamadas observadas, **Revisões** para evidências e próximos passos, e **Comparar** para diferenças entre execuções.

As credenciais não são renovadas automaticamente. Respostas 401/403 ficam registradas; não há tentativa de login, MFA ou contorno de permissões. Após reiniciar, forneça novamente a sessão ao retomar. No CLI, use `resume --http-origin ORIGEM --http-token` ou `--session-file`.

## Frontend e API em origens diferentes

Para permitir `https://api.lab.exemplo` durante a renderização de `https://lab.exemplo`, adicione a origem da API em **Origens adicionais** e inclua ambos os hosts no **Escopo permitido**. O token é enviado somente à origem configurada para a sessão, comparando protocolo, host e porta.

```bash
penpilot scan 'https://lab.exemplo/' --render-js --focus web \
  --scope lab.exemplo api.lab.exemplo \
  --browser-origins 'https://api.lab.exemplo' \
  --http-origin 'https://api.lab.exemplo' --http-token
```

O navegador envia GET e o preflight OPTIONS necessário a essas chamadas, preservando a resposta CORS do servidor. POST, PUT, DELETE, WebSocket, service workers e downloads são bloqueados. Isso permite reconhecimento sem submeter formulários ou realizar operações automáticas na conta, mas aplicações que dependam desses canais podem renderizar parcialmente. Origens de scripts/CDNs também precisam constar na lista e no escopo. Não são liberadas por aparecerem no HTML.

## Sessão JSON opcional

Use o importador no painel ou `--session-file /caminho/sessao.json`. O arquivo permanece onde você o criou; o PenPilot não copia a sessão para a pasta de evidências.

```json
{
  "origin": "https://api.lab.exemplo",
  "token": "TOKEN_DE_TESTE",
  "cookie": "sid=COOKIE_DE_TESTE",
  "storage_origin": "https://lab.exemplo",
  "storage": {
    "chave-usada-pela-aplicacao": "valor-string-do-localStorage"
  }
}
```

Inclua somente os campos necessários. `storage` injeta pares de strings no localStorage da origem indicada, antes dos scripts. Não é um arquivo Playwright storageState; é o formato de sessão do PenPilot. Sem `storage_origin`, utiliza `origin`. Autorizações produzidas pelo navegador são encaminhadas apenas à origem de sessão. Cookies recebidos não atualizam automaticamente o contexto. Sessões em sessionStorage ou fluxos interativos não são suportados.

## Respostas genéricas e revisões

A análise padrão consulta uma URL aleatória inexistente por origem. Compara status, tipo de conteúdo e hash do corpo, sem considerar tamanho igual como prova de equivalência. O perfil rápido desliga essa sondagem por padrão; `--generic-check` habilita e `--no-generic-check` desabilita. Não há declaração automática de vulnerabilidade por HTTP 200, cabeçalho ausente ou banner.

As revisões incluem HTML genérico, acesso recusado, CSP, HSTS, tipo de conteúdo, atributos de cookies (sem valores), versão TLS observada, validação do certificado e proximidade de vencimento na data da coleta. Há evidência e próximo passo para cada observação. Não há teste exaustivo de suites TLS nem exploração de CVEs.

## Mapa e comparação

O mapa registra referências, redirecionamentos e chamadas GET observadas no navegador. URLs mencionadas e requisições bloqueadas não são apresentadas como acessíveis. Os arquivos `map.json` e `review.json` são incluídos nas evidências.

A comparação destaca URLs novas, alterações de status/corpo/cabeçalhos relevantes e alterações de serviços. URLs não observadas na nova coleta não são chamadas de removidas. Escopo, configuração e autenticação diferentes reduzem a comparabilidade; conteúdo dinâmico pode gerar diferenças legítimas. Não há comparação de imagens por pixels.

## Burp

**Enviar para Burp** ou `penpilot export PASTA --burp` cria `burp-review.zip` com `requests/*.http`, `requests.har` e instruções. Copie uma requisição `.http` para o Repeater e configure host, porta e TLS indicados no HAR. Não há transmissão automática ao Burp. São GETs reconstruídos para revisão, sem Authorization, Cookie, corpos de requisição ou valores de query. Adicione a sessão localmente se precisar reproduzir uma chamada autenticada.

## Monitoramento

No painel, selecione uma execução anônima encerrada, abra **Monitorar** e escolha o intervalo. A primeira repetição ocorre após esse intervalo. A configuração persiste em `.monitors.json`; **Pausar** interrompe futuras coletas e solicita parada da coleta ativa. Não há sobreposição entre coletas do mesmo serviço de monitores. O computador e `penpilot web` precisam permanecer em execução. O monitor não envia e-mail, Slack ou notificações fora do painel.

Para usar terminal e, opcionalmente, sessão em memória:

```bash
penpilot watch /pasta/modelo --interval 30m --count 3
penpilot watch /pasta/modelo --interval 1h --http-origin 'https://lab.exemplo' --http-token
```

`watch` começa a primeira coleta imediatamente; `--count 0` repete até Ctrl+C. Intervalo mínimo: 60 segundos, contado após concluir a coleta. Imprime somente mudanças ou alterações de estado. O monitor do painel registra também falhas de inicialização, sem repetir avisos idênticos. Resultados completos de cada repetição permanecem no histórico.

## Fluxo de trabalho

**Verificar configuração** consulta DNS, escopo, dependências locais e a expiração declarada de JWTs, sem enviar credenciais ao alvo. **Verificar e iniciar** executa a checagem antes da coleta. JWTs não são verificados criptograficamente; não é um teste de login. HTTP 401/403 e pendências aparecem em **Próximos passos**. Um 403 não comprova expiração.

**Importar do Burp ou cURL**, em Navegador e sessão web, extrai URL, Bearer e Cookie de uma requisição GET. Não executa shell nem lê arquivos. cURL aceita URL, `-H/--header`, `-b/--cookie` literal, `-X/--request GET`, `--url`, `--compressed`, `--http1.1`, `--http2`, `-s/--silent`. Opções diferentes são rejeitadas. Para HTTP bruto, selecione HTTP ou HTTPS. Use **Limpar sessão** para voltar à coleta anônima.

**Projetos** guardam alvos, escopo, exclusões e perfil em `.workspace.json`, sem credenciais. URLs com query são rejeitadas ao salvar projetos, pois podem carregar sessões. Selecionar um projeto limpa as credenciais anteriores. **Histórico e arquivos** permite buscar e filtrar execuções; **Mais ações** permite renomear ou arquivar. Arquivamento é apenas organização: não remove arquivos nem pausa monitores. Restaure pelo filtro Arquivadas.

**Comparação visual** apresenta capturas da mesma URL lado a lado, quando disponíveis. Não calcula diferença de pixels. Sessão, conteúdo dinâmico e horário podem alterar a aparência.

## Serviço local opcional (Linux / systemd)

```bash
penpilot service install
# Encerre o painel manual com Ctrl+C antes de iniciar o serviço na mesma porta.
penpilot service start
penpilot service status
penpilot service stop
```

Para outra pasta/porta, instale com `penpilot service install -o /pasta --port 8766` e use a mesma pasta `-o /pasta` nos comandos de controle. A porta é definida na instalação. O serviço usa o Python e a instalação atuais; após mover o projeto, reinstale a unidade. Instalar cria a unidade em `~/.config/systemd/user` e recarrega o systemd, mas não inicia nem habilita o serviço. Não ativa início no boot ou linger. Funciona enquanto o serviço de usuário estiver disponível e o computador estiver ligado. Credenciais não são persistidas. Há um único painel/agendador por pasta de histórico para evitar coletas duplicadas.
