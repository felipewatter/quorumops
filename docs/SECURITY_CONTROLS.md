# Catálogo de controles e matriz de validação

## QOP-001 — Autorização M-de-N

**Objetivo:** negar uso de plano sem pelo menos duas assinaturas digitais válidas de identidades distintas. `requiredApprovals`: inteiro de 2 a 10. Chaves confiáveis devem ser Ed25519 e únicas. Solicitante é inelegível como aprovador.

## QOP-002 — Plano, política e autorização vinculados

**Objetivo:** negar aprovação após mudança em qualquer parâmetro da política, lista de etapas, solicitante, prazo ou nonce. SHA-256 sobre JSON canônico; aprovação digital sobre payload com prefixo de domínio.

## QOP-003 — Tempo e validade

**Objetivo:** rejeitar plano futuro/expirado, janela acima do máximo definido e aprovação fora da janela temporal. Relógio externo não faz parte desta implementação.

## QOP-004 — Parser de entradas hostis

**Objetivo:** limitar JSON a 1 MiB e 32 níveis, rejeitar chave duplicada, campos desconhecidos, tipos incorretos, path traversal, nomes de dispositivos reservados no Windows, arrays e strings fora dos limites.

## QOP-005 — Execução de comando autorizada

**Objetivo:** recusar comando não cadastrado, hash divergente do executável ou argumentos arbitrários. Sem shell, sem stdin e com timeout. Não registra stdout/stderr; apenas códigos e bytes de saída.

## QOP-006 — Dry-run e anti-replay

**Objetivo:** manter simulação como padrão; `--commit` exige estado privado e cria tentativa exclusiva atômica. Planos consumidos não podem ser reutilizados no mesmo estado persistente.

## QOP-007 — Evidência e integridade local

**Objetivo:** associar receipt a plano, etapas e resultado com SHA-256; nenhum arquivo de receipt existente pode ser sobrescrito. Hash não equivale a assinatura contra adversário com acesso de escrita.

## QOP-008 — Verificações de CI

**Objetivo:** testes e smoke em Node 22/24 e Ubuntu/Windows; release apenas em push na main do repositório esperado após sucesso da matriz. Release inclui snapshot versionado e SHA-256.

## Matriz resumida de testes locais

| Cenário | Expectativa |
| --- | --- |
| JSON com chave duplicada e `NaN` | Rejeitar |
| Ordem diferente de propriedades JSON | Mesmo digest |
| Quórum 1 / mesma chave com identidades distintas | Rejeitar |
| Traversal, caminho absoluto, shell livre | Rejeitar |
| Solicitante igual ao aprovador | Rejeitar |
| Expiração, política diferente, nonce de outro plano | Rejeitar |
| Quórum insuficiente, duplicado, signatário estranho | Rejeitar |
| Assinatura ou conteúdo alterado | Rejeitar |
| Dry-run com preflight válido | Aprovar sem alterar estado |
| Execução com quórum | Criar marcador e receipt |
| Replay do mesmo plano e execução concorrente | Apenas uma execução permitida |
| Leitura de JSON com symlink | Rejeitar (POSIX testado) |
| Falha em arquivo de pré-condição | Bloquear antes da tentativa |
| JSON Pointer com `~1` e `~0` | Conferir valor correto |
| Comando não cadastrado | Rejeitar |
| Comando permitido com hash real | Executar e registrar metadados |
| Comando cadastrado com hash falso | Rejeitar antes de executar |
| Aprovação emitida no futuro fora da tolerância | Rejeitar |
| Receipt alterado | Detectar digest incorreto |
| State directory público | Rejeitar (POSIX testado) |

## Comandos de validação

```bash
npm ci --ignore-scripts
npm run syntax
npm test
npm run smoke
npm pack --dry-run
```

Os resultados de `npm test` e `npm run smoke` executados localmente devem ser registrados na entrega. O status do CI remoto só pode ser confirmado depois de um workflow run real no GitHub.
