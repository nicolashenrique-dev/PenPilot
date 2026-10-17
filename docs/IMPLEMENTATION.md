# Contrato e checklist

## Contrato antes das integrações
Um plugin declara ID, protocolos confirmados, dependências, custo, autenticação e consultas. Recebe Engine e Task, produz entidades/findings com origem e evidências. Apenas o scheduler cria tarefas, deduplica por plugin/nó/tentativa, verifica serviço e aplica limites. Nenhum plugin recebe shell arbitrário. Exceções têm estados específicos (denied, timeout, unavailable, failed); resultados vazios são diferentes de falha. Descoberta é o único plugin sem serviço prévio. HTTP crawler e content usam profundidades independentes.

## Plano de implementação
- [x] Perfis, escopo, modelos e contrato de plugins.
- [x] Executor, eventos, checkpoint, retomada, cancelamento e tentativas.
- [x] Nmap XML e liberação condicional.
- [x] HTTP, crawler, conteúdo, screenshots; SMB e FTP.
- [x] CLI e painel com árvore, prévia, logs e ações.
- [x] Manifesto, relatório, Markdown, ZIP, seleção e revisão de publicação.
- [x] Testes unitários e integração real em loopback.
- [x] Instalação, limitações e roadmap documentados.

## Decisões
Python/FastAPI e JS nativo evitam build de frontend para distribuição local. Um worker por host impede sobreposição de ferramentas que não compartilham rate limiter; hosts distintos podem executar em paralelo. Crawler próprio para coleta rastreável. ffuf opcional e coletor interno com orçamento exato de HTTP. Screenshots Playwright com interceptação de rede para preservar escopo; Gowitness fica para um adaptador isolado, pois um navegador externo pode seguir redirecionamentos/subrecursos fora do escopo. smbclient fornece enumeração de shares com credenciais em arquivo temporário 0600. Sem inferir AD/CVE só por porta/banner. Implementações adiadas ficam explícitas no README.

## Escopo entregue
O checklist acima corresponde ao primeiro fluxo funcional. Recursos futuros e partes não implementadas da especificação estão enumerados explicitamente no README. Não houve benchmark ffuf/Gobuster nem implementação de AD/CVEs/DNS ativo.
