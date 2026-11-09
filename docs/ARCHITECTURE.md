# Arquitetura técnica do QuorumOps

## 1. Objetivo e limites

O QuorumOps é um **gate de admissão e execução local de runbooks**. Sua API de entrada é composta por arquivos JSON versionados, chaves PEM Ed25519 e um workspace físico preexistente. Sua API de saída é JSON no stdout e, com confirmação, arquivos locais de tentativa/receipt. **Não escuta rede**, não mantém banco de dados e não possui servidor web.

## 2. Componentes

| Arquivo | Responsabilidade |
| --- | --- |
| `src/strict-json.mjs` | Parser de JSON limitado em tamanho e profundidade, com rejeição de objetos contendo chaves duplicadas; serialização canônica com chaves lexicograficamente ordenadas |
| `src/core.mjs` | Validadores de esquema, digest SHA-256, assinatura/verificação Ed25519, identidade/quórum/prazos, segurança de arquivos e workspace |
| `src/workflow.mjs` | Preflight de todas as etapas, execução explicitamente confirmada, reivindicação anti-replay, comandos fixos e receipt |
| `src/cli.mjs` | Argumentos, operações públicas, exit codes e JSON stdout |
| `scripts/setup-demo.mjs` | Gerador local de política e chaves exclusivamente demonstrativas |
| `scripts/smoke.mjs` | Teste de ponta a ponta com isolamento temporário e tentativa de replay rejeitada |
| `tests/quorumops.test.mjs` | Testes positivos, negativos, de segurança e concorrência |

## 3. Formatos e hashing

O serializador canônico ordena as chaves dos objetos e mantém a ordem dos arrays. A representação é adequada ao **perfil JSON fechado do projeto**; não promete compatibilidade geral com o RFC 8785/JCS. O digest do plano é `SHA-256(canonical(plan))`. A política é identificada por `SHA-256(canonical(policy))` e fica vinculada ao plano aprovado.

Uma aprovação tem os campos:

```json
{
  "schema": "quorumops.approval.v1",
  "approver": "security",
  "planDigest": "...64 hex...",
  "issuedAt": "2026-11-09T18:00:00.000Z",
  "decision": "approve",
  "signature": "base64 de 64 bytes Ed25519"
}
```

A assinatura Ed25519 incide sobre os bytes UTF-8 de:

```
quorumops.approval.v1\n + canonical(approval_without_signature)
```

O prefixo de domínio evita confundir o payload com assinaturas genéricas de outros protocolos.

## 4. Invariantes de autorização

1. O plano é bem formado, tem `nonce` de 128 bits, `requester`, horários UTC e runbook válido.
2. O hash da política carregada no ato da autorização é exatamente igual ao hash que consta do plano.
3. Horário atual entre criação e vencimento do plano; duração não supera `maxTtlSeconds` da política.
4. Cada aprovação assinada pertence ao digest do plano, usa signatário confiável com chave Ed25519, declara aprovação e tem hora compatível com a janela do plano.
5. Quórum igual ou maior que o requerido; signatários sem IDs nem chaves públicas duplicados.
6. ID do solicitante distinto dos signatários.
7. Todas as etapas possuem formatos reconhecidos. Operação `exec` aponta exclusivamente para nome existente no cadastro de comandos da política.
8. Todas as pré-condições são checadas antes de qualquer mutação.
9. Apenas `--commit` permite iniciar execução. Seu primeiro registro é um arquivo criado exclusivamente em `stateDir/attempts/<digest>.json`; esse arquivo impede duas execuções simultâneas que compartilhem o mesmo estado.
10. Se o processo chegar à finalização, escreve `stateDir/receipts/<digest>.json` sem sobrescrever arquivo anterior.

## 5. Máquina de estados

```text
new plan
  | two or more valid approvals
  v
AUTHORIZED
  | --dry-run -> PREFLIGHT -> REPORT (nothing consumed)
  |
  | --commit -> PREFLIGHT -> ATOMIC CLAIM
                             | success
                             v
                         IN_PROGRESS
                          /      \
                    completed    failed
                        |           |
                    receipt OK   receipt error
                        \           /
                          CONSUMED

A crash after ATOMIC CLAIM leaves the plan CONSUMED and may leave no receipt.
```

O bloqueio de replay é implementado por `O_EXCL` em um **diretório de estado persistente confiável**. Não é uma trava distribuída e pode não funcionar como esperado em compartilhamentos de rede com semântica inadequada de criação exclusiva. Para novas tentativas após falha, crie **um novo plano com novo nonce e novas assinaturas**; não exclua o arquivo `attempts` para reutilizar autorização antiga.

## 6. Execução de comandos

Para cada `exec`, a política carrega **caminho absoluto**, **SHA-256 do executável regular não-symlink**, **args literais** e timeout. O runner invoca `child_process.spawn` com `shell:false`, sem stdin, sem shell implícito, com ambiente reduzido, sem registrar stdout/stderr e com stdout/stderr limitados a 16 KiB. A saída pública conserva apenas código de saída e total de bytes produzidos.

O programa autorizado roda **como o mesmo usuário do QuorumOps**. O hash do binário limita alterações não aprovadas, mas não prova segurança do próprio binário, de bibliotecas carregadas, arquivos ou recursos que esse binário consome. A segurança exige restringir administradores de política e manter o host sob controle. Não se deve aprovar interpretadores de shell com scripts arbitrários ou executáveis auto-atualizáveis sem revisão.

## 7. Armazenamento e confidencialidade

- `keys/` e `demo/` ignorados pelo Git; chaves privadas criadas em modo 0600 quando suportado.
- Estado contém identificador de plano, aprovadores, sucesso/falha e metadados das etapas; deve ter permissão 0700 em POSIX.
- Não são persistidos stdout, stderr ou conteúdo original dos arquivos do workspace.
- Receipts incluem digest SHA-256 não autenticado por chave. São úteis para detectar alterações de conteúdo contra uma referência externa, não para atestar de maneira independente a origem de quem escreveu o receipt.
- O pacote de origem para release é produzido por `git archive`, incluindo somente arquivos versionados. Chaves demonstrativas nunca devem ser versionadas.

## 8. Portabilidade

Node.js 22/24 e hosts Windows/Ubuntu são os alvos de CI. Restrições POSIX como bits de modo de arquivo não se traduzem de forma exata para ACLs do Windows. Os testes de symlink que exigem privilégio são omitidos no Windows; não interprete isso como certificação de equivalência de proteção entre sistemas operacionais.
