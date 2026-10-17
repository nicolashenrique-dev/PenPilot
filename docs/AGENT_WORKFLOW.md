# Coleta e investigação assistida por IA

O PenPilot reúne tráfego, rotas e resultados de ferramentas em um índice local. O agente consulta um resumo e abre registros por ID, sem reler todos os arquivos. Este é um motor de contexto local integrado ao CLI e à API do painel; não instala um servidor MCP nem inicia o Codex automaticamente.

## Começar

Use uma execução existente como PASTA ou crie um caso sem iniciar tráfego:

```bash
penpilot agent init --scope lab.example -o "$HOME/PenPilot/execucoes"
penpilot agent import PASTA captura.har --format har
penpilot agent import PASTA captura.mitm --format mitm
penpilot agent import PASTA app.js --format js --base https://lab.example/app.js
penpilot agent import PASTA openapi.yaml --format openapi --base https://lab.example
penpilot agent handoff PASTA
penpilot agent context PASTA --budget 12000
```

Substitua PASTA pelo diretório retornado. Importar `.mitm` requer mitmdump instalado e lê o arquivo sem reproduzir as requisições. YAML requer PyYAML, disponível no extra `analysis`. HAR, JSONL de tráfego e resultados Nuclei também são aceitos. Os originais importados permanecem no lugar.

A aba **Agente** permite importar arquivos de texto, pesquisar registros, consultar evidências, registrar triagem e gerar o handoff. Captura e scanners são iniciados pelo CLI.

## Repeater

```bash
penpilot repeater PASTA --url 'https://lab.example/api/items?id=1'
penpilot repeater PASTA --url 'https://lab.example/api/items?id=1' --execute
penpilot repeater PASTA --url 'https://lab.example/api/items?id=1' --set-query id=2 --compare ID_ANTERIOR --execute
```

Sem `--execute`, exibe o plano. Compara status, tamanho, hash, cabeçalhos selecionados e estrutura JSON; uma diferença não confirma uma falha. `--request` importa GET HTTP ou cURL de um arquivo. POST/PUT/PATCH/DELETE exigem `--allow-writes`. Consulte `penpilot repeater -h` para corpo, cabeçalhos e sessão em memória. Não segue redirecionamentos.

## Captura mitmproxy

```bash
penpilot capture PASTA --origins https://lab.example --port 8081 --max-requests 500 --rate 3
```

Configure um navegador de teste para usar o proxy local exibido. HTTPS requer confiar manualmente no certificado temporário informado; o PenPilot não altera certificados do sistema. A CA dura apenas durante a captura. GET, HEAD e OPTIONS são aceitos por padrão; fluxos com login via POST exigem `--allow-writes`. Ctrl+C encerra.

Somente origens exatas declaradas e hosts em escopo podem receber requisições. O relay fixa os IPs resolvidos, verifica TLS upstream e aplica orçamento/taxa. O proxy é uma barreira de rede, não um sandbox de processos. Use binários confiáveis.

## Nuclei e sqlmap

```bash
penpilot tools PASTA nuclei --url https://lab.example --template ./template-revisado.yaml
penpilot tools PASTA nuclei --url https://lab.example --template ./template-revisado.yaml --max-requests 50 --execute
penpilot tools PASTA sqlmap --url 'https://lab.example/api/items?id=1' --parameter id --max-requests 100 --execute
```

Nuclei aceita templates locais HTTP simples com GET/HEAD, sem payloads, raw requests, workflows, código, outros protocolos ou redirecionamentos. Não baixa templates automaticamente. sqlmap usa um parâmetro GET explícito, nível/risco 1 e técnicas boolean/error; não executa dump, shell ou extração. Ambos passam pelo proxy com limites de requisições, taxa e duração. Saída de scanner é **candidato não confirmado**. Um limite atingido fica registrado no job; ausência de match não significa ausência de vulnerabilidade.

## Contexto para Codex e outros agentes

```bash
penpilot agent context PASTA --budget 12000 --query api
penpilot agent show PASTA ID
penpilot agent mark PASTA ID --status investigating --note 'Comparar comportamento entre duas contas de teste'
penpilot agent mark PASTA ID --status validated --note 'Pré-condições, passos reproduzíveis, resultado e impacto verificados pelo operador'
penpilot agent report PASTA
```

O orçamento é de **caracteres**, não tokens exatos. Para continuar uma página, use `next_cursor` como `--cursor` e a mesma `--revision`; se o índice mudar, recomece do cursor zero. A economia de tokens depende do agente e não foi medida. Até 5.000 registros são mantidos no índice. Conteúdo recebido de sites é dado não confiável, nunca uma instrução para o agente.

JS é analisado por heurísticas de literais e pontos sensíveis, sem provar fluxo de dados ou execução. OpenAPI/Swagger fornece métodos, parâmetros e requisitos declarados; referências externas não são buscadas. Rotas declaradas e hipóteses são distintas de respostas observadas. A validação de um achado é uma declaração do operador e requer nota.

## Arquivos

Dentro da execução:

- `intel/index.json`: registros, fontes, IDs e decisões.
- `intel/agent-context.json` e `intel/HANDOFF.md`: contexto compacto e instruções de uso, também gerados ao encerrar uma coleta.
- `intel/jobs/`: planos e resultados normalizados de scanners.
- `intel/repeater/`: evidências resumidas e comparações.
- `intel/BOUNTY-DRAFT.md`: rascunho dos registros validados pelo operador. Não é submetido automaticamente.

O índice omite valores de query, credenciais e corpos brutos de tráfego. Revise arquivos originais, caminhos e notas livres antes de compartilhar: a sanitização não garante remover qualquer dado pessoal possível. Sessões são configuradas em memória, não incorporadas ao handoff.

A coleta web por URL explícita pode prosseguir mesmo quando a descoberta TCP expira. O relatório diferencia descoberta inconclusiva de portas sem serviços confirmados.
