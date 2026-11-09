# Validação técnica de entrega (ambiente local)

**Data de referência:** 2026-11-09.

**Ambiente comprovado no preparo do pacote:** Node.js `v22.16.0`, npm `10.9.2`, Linux. Os jobs remotos Node.js 22/24 e Ubuntu/Windows foram definidos, mas **somente serão confirmados após a criação e a publicação do repositório**.

## Comandos executados

| Comando | Resultado local |
| --- | --- |
| `npm install --package-lock-only --offline --ignore-scripts --no-audit --no-fund` | Sucesso; `package-lock.json` gerado sem dependências de runtime |
| `npm run syntax` | Sucesso; 4 arquivos de código da CLI/motor verificados |
| `npm test` | **26 testes aprovados, 0 falhas** |
| `npm run smoke` | Sucesso: geração de 2 chaves, plano, 2 aprovações, verificação, simulação, execução, receipt, replay bloqueado |
| `npm pack --dry-run` | Sucesso; manifesto sem chaves privadas, `demo/` ou `state/` |
| `npm run demo:init` | Sucesso em ambiente local com diretório ignorado pelo Git |

**Não executado até a publicação:** GitHub Actions remoto, validação de permissões de workflow no repositório, GitHub Release e publicação de tags. Não afirmar que essas etapas foram concluídas antes de revisar a aba **Actions**.

## Controles verificados nos testes

- JSON ambíguo ou malformado, chaves duplicadas e objetos com propriedades extras.
- Quórum mínimo 2, identidade distinta e chaves públicas sem duplicação.
- Plano expirado, datas UTC inválidas, política modificada e assinatura inválida.
- Planos e aprovações adulterados ou reutilizados.
- Paths absolutos, traversal e symlink de arquivo/workspace (POSIX).
- Falha de preflight antes de qualquer alteração.
- Execução fixa aprovada com verificação do SHA-256 do binário.
- Rejeição de comando desconhecido e hash de executável incorreto.
- Ausência de mutação em dry-run, teste simultâneo do claim atômico de replay.
- Integridade do recibo e permissão privada do estado em POSIX.

## Critérios de release remoto

1. Código enviado para `felipewatter/quorumops`, branch `main`.
2. Quatro combinações de Node e SO (Ubuntu/Windows, Node 22/24) com sucesso.
3. Job `release` com sucesso e GitHub Release correspondente a `package.json` (`v1.0.0`).
4. ZIP e `.sha256` disponíveis como assets do release.
5. Conferência dos arquivos publicados e do commit SHA, além de conferir que nenhuma chave privada foi versionada.
