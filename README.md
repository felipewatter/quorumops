<div align="center">

# QuorumOps

### Secure Runbook Execution Gate

**Autorização criptográfica de procedimentos operacionais de TI, com dupla aprovação independente, controle de execução e evidências locais.**

[![CI](https://github.com/felipewatter/quorumops/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/quorumops/actions/workflows/ci.yml)
![Node.js 22+](https://img.shields.io/badge/Node.js-22%2B-339933?logo=nodedotjs&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Zero Runtime Dependencies](https://img.shields.io/badge/dependencies-runtime%200-informational.svg)

**Projeto de portfólio em segurança e gestão operacional de TI** · [Felipe Silva](https://github.com/felipewatter) · **Versão proposta:** `v1.0.0`

[Arquitetura](docs/ARCHITECTURE.md) · [Modelo de ameaças](docs/THREAT_MODEL.md) · [Catálogo de segurança](docs/SECURITY_CONTROLS.md) · [Versão em inglês](README.en.md)

</div>

> **Status de lançamento:** implementação local testada. O selo CI e o release remoto passam a refletir execuções reais somente após o código ser enviado ao GitHub e o workflow ser concluído. Este projeto é experimental e **não substitui** um ITSM, PAM, HSM, sandbox nem um controle de acesso ao sistema operacional.

## Sumário

1. [Problema que resolve](#1-problema-que-resolve)
2. [Funcionalidades e garantias](#2-funcionalidades-e-garantias)
3. [Arquitetura e fluxo de aprovação](#3-arquitetura-e-fluxo-de-aprovação)
4. [Pré-requisitos e instalação](#4-pré-requisitos-e-instalação)
5. [Demonstração completa](#5-demonstração-completa)
6. [Runbooks e políticas](#6-runbooks-e-políticas)
7. [Tipos de operação](#7-tipos-de-operação)
8. [CLI e códigos de saída](#8-cli-e-códigos-de-saída)
9. [Segurança e limitações](#9-segurança-e-limitações)
10. [Testes, GitHub Actions e releases](#10-testes-github-actions-e-releases)
11. [Casos de uso em TI](#11-casos-de-uso-em-ti)
12. [Documentação e referências](#12-documentação-e-referências)

## 1. Problema que resolve

Uma rotina de manutenção ou resposta a incidente pode exigir ações simples, mas críticas: conferir arquivos de configuração, verificar um serviço, documentar evidências ou executar uma rotina operacional previamente aprovada. Executar essas tarefas a partir de comandos avulsos não comprova quem autorizou o procedimento, se o conteúdo aprovado foi alterado ou se uma autorização antiga foi reutilizada.

O **QuorumOps** implementa um *gate local* que decide se um procedimento versionado pode ser executado. O solicitante formula um plano com prazo definido; pessoas com chaves confiáveis assinam exatamente aquele plano; a ferramenta verifica assinaturas, separação de funções, expiração, política e pré-condições. A execução é **simulada por padrão** e só produz alterações com `--commit`.

A proposta se diferencia de executores amplos como o Rundeck por manter uma superfície reduzida e demonstrável: **aprovação criptográfica vinculada a um conjunto de operações previamente enumerado**. Não concorre com o próprio sistema de autenticação do host nem substitui uma plataforma de orquestração.

## 2. Funcionalidades e garantias

| Recurso | Implementação | Observações |
| --- | --- | --- |
| Assinaturas digitais | **Ed25519** da biblioteca `node:crypto` | Sem biblioteca criptográfica externa |
| Quórum | De **2 a 10 aprovadores distintos** | IDs e chaves públicas independentes; identidade real precisa ser validada fora da aplicação |
| Separação de funções | Solicitante não pode ser aprovador | Regra vinculada à identidade textual cadastrada no plano/política |
| Plano imutável para aprovação | Digest SHA-256 de JSON canônico | Qualquer mudança no plano invalida aprovações existentes |
| Política vinculante | Digest SHA-256 da política no plano | Alteração de chave, quórum ou permissão invalida o plano |
| Validade temporal | UTC, prazo máximo por política, nonce aleatório | Exige relógio confiável no host |
| Anti-replay | Criação exclusiva de arquivo de tentativa por plano | Requer estado persistente privado em filesystem local |
| Dry-run | Preflight, sem escrita nem execução de comandos | Simula permissões e disponibilidade atuais, não efeitos futuros |
| Check de arquivo | SHA-256 calculado por streaming | Até 16 MiB por arquivo de asserção |
| Check JSON | JSON Pointer e igualdade escalar | Parser estrito detecta chaves duplicadas |
| Evidência de conclusão | Criação exclusiva de marcador de texto | Sem sobrescrever arquivos existentes; conteúdo literal aprovado |
| Execução controlada | ID de comando registrado na política | Executável absoluto com digest, argumentos fixos, timeout e `shell: false` |
| Recibos | Resultado, etapas, aprovadores e hash local | **Não** são assinaturas; necessitam ancoragem externa para prova contra administrador malicioso |
| Sanitização | Sem stdout/stderr de processos nos relatórios | Previne divulgação acidental de saída sensível; não garante ausência de dados sensíveis em erros |
| Dependências | Zero bibliotecas externas em runtime | Node.js 22+ |
| CI/CD | 4 combinações de Node/OS, testes e smoke | Release automático depende de conclusão efetiva de CI |

## 3. Arquitetura e fluxo de aprovação

```text
                    OPERADOR (solicitante)
          runbook.json + policy.json + prazo UTC
                         |
                         v
                 PLAN (nonce + SHA-256)
                 /                  \
                v                    v
       APROVADOR SEGURANÇA      APROVADOR OPERAÇÕES
          chave Ed25519            chave Ed25519
                 \                  /
                  v                v
                   GATE DE AUTORIZAÇÃO
              - política atual == hash do plano
              - assinaturas válidas e distintas
              - solicitante diferente dos aprovadores
              - validade temporal e quórum suficiente
              - operações permitidas e preflight OK
                              |
                 +------------+-------------+
                 |                          |
                DRY-RUN                 --commit
          sem alterar nada       claim atômico de replay
                                            |
                                     executar operações
                                            |
                               receipt + hash SHA-256
```

O conjunto de etapas está inteiramente dentro do plano assinado. O arquivo de política contém a lista de aprovadores confiáveis e os comandos que podem ser executados. O executor **não aceita texto de shell** como etapa de runbook.

## 4. Pré-requisitos e instalação

- Node.js 22 ou superior (CI preparado para 22 e 24).
- Windows PowerShell ou terminal Linux/macOS.
- Para operações de comando (`exec`), acesso local ao binário aprovado; para os demais tipos, nenhum software de terceiros.

```bash
git clone https://github.com/felipewatter/quorumops.git
cd quorumops
npm ci --ignore-scripts
node src/cli.mjs --help
npm test
npm run smoke
```

> **O clone funcionará depois que o repositório for criado e publicado.** Antes da publicação, utilize o ZIP de origem fornecido junto com o projeto. `npm ci` utiliza `package-lock.json` e não precisa instalar pacotes de runtime.

Para instalar o comando globalmente a partir da cópia local:

```bash
npm link
quorumops --help
```

## 5. Demonstração completa

A rotina abaixo **gera duas chaves privadas novas em `demo/keys`**, cria uma política com as chaves públicas e copia um arquivo fictício. A pasta `demo/` está no `.gitignore`. Use somente para treinamento.

**Etapa 1 — gerar o laboratório**

```powershell
npm run demo:init
```

**Etapa 2 — preparar plano com validade de 20 minutos**

```powershell
node src/cli.mjs plan --runbook demo/runbook.json --policy demo/policy.json --requester felipe --ttl 1200 --out demo/plan.json
```

**Etapa 3 — aprovar com dois responsáveis independentes**

```powershell
node src/cli.mjs approve --plan demo/plan.json --approver security --key demo/keys/security.private.pem --out demo/security.approval.json
node src/cli.mjs approve --plan demo/plan.json --approver operations --key demo/keys/operations.private.pem --out demo/operations.approval.json
```

**Etapa 4 — verificar quórum e assinaturas, sem executar nada**

```powershell
node src/cli.mjs verify --plan demo/plan.json --policy demo/policy.json --approval demo/security.approval.json --approval demo/operations.approval.json
```

**Etapa 5 — testar em dry-run**

```powershell
node src/cli.mjs run --plan demo/plan.json --policy demo/policy.json --approval demo/security.approval.json --approval demo/operations.approval.json --root demo/workspace --state demo/state
```

**Etapa 6 — executar explicitamente, uma única vez**

```powershell
node src/cli.mjs run --plan demo/plan.json --policy demo/policy.json --approval demo/security.approval.json --approval demo/operations.approval.json --root demo/workspace --state demo/state --commit
```

O comando cria `demo/workspace/completed.txt` e salva um receipt em `demo/state/receipts/<digest-do-plano>.json`. Repetir a execução com o mesmo plano será bloqueado. O argumento `--state` é obrigatório com `--commit`; em dry-run ele é opcional.

Uma execução automatizada equivalente, inclusive com tentativa de replay esperada como bloqueada, pode ser conferida com `npm run smoke`.

## 6. Runbooks e políticas

### 6.1. Exemplo de runbook

Arquivo: [`examples/runbook.json`](examples/runbook.json)

```json
{
  "schema": "quorumops.runbook.v1",
  "id": "verificacao-pos-manutencao",
  "description": "Confere arquivo de saude apos manutencao e registra um marcador",
  "steps": [
    {
      "id": "conferir-arquivo",
      "type": "assert_file",
      "path": "health.txt",
      "sha256": "DIGEST_SHA256_DE_64_CARACTERES_HEXADECIMAIS"
    },
    {
      "id": "registrar",
      "type": "record_marker",
      "path": "completed.txt",
      "text": "Manutencao verificada em laboratorio"
    }
  ]
}
```

O campo `sha256` do exemplo ilustrativo acima precisa ser substituído por um digest real. O arquivo [`examples/runbook.json`](examples/runbook.json) já contém um hash válido do exemplo. Caminhos são sempre **relativos ao `--root`** e proíbem `..`, caminhos absolutos e symlinks nas partes verificadas.

### 6.2. Exemplo de política

```json
{
  "schema": "quorumops.policy.v1",
  "requiredApprovals": 2,
  "maxTtlSeconds": 3600,
  "allowMarkers": true,
  "commands": {},
  "approvers": [
    { "id": "security", "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" },
    { "id": "operations", "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" }
  ]
}
```

A política ilustrativa exige substituir os `...` pelas **chaves públicas Ed25519 reais**. `npm run demo:init` faz isso automaticamente para um laboratório isolado. Não use as chaves do laboratório para ambientes reais.

### 6.3. Definição de comando permitido

O runbook só referencia o identificador de um comando. Caminho, argumentos e tempo-limite são definidos **na política**, independentemente do solicitante:

```json
{
  "commands": {
    "check-version": {
      "executable": "/usr/bin/true",
      "sha256": "HASH_SHA256_REAL_DO_BINARIO",
      "args": [],
      "timeoutMs": 2000
    }
  }
}
```

`/usr/bin/true` é apenas um exemplo para sistemas onde o arquivo existe. O digest deve ser calculado sobre os bytes reais do binário no host que executará o procedimento. No Windows, use um caminho absoluto apropriado. A função não aceita interpolação, redirecionamento, `sh -c` ou `powershell -Command` como linguagem livre; porém o operador que administra a política ainda poderia cadastrar um interpretador. **Cabe ao administrador impedir esse uso em políticas confiáveis.**

## 7. Tipos de operação

| Tipo | Especificação | Efeito |
| --- | --- | --- |
| `assert_file` | `id`, `path`, `sha256` | Compara digest calculado dos bytes do arquivo no workspace |
| `assert_json` | `id`, `path`, `pointer`, `equals` | Compara escalar JSON em localização RFC 6901 (`/chave/subchave`) |
| `record_marker` | `id`, `path`, `text` | Cria, exclusivamente, novo arquivo de texto no workspace |
| `exec` | `id`, `command` | Executa binário registrado na política, com hash, args fixos e timeout |

O preflight avalia **todas as etapas antes** de registrar a tentativa. Depois as pré-condições são revalidadas durante a execução. Se um passo falhar após o início, **não há rollback**; o plano permanece consumido e o receipt informa a falha quando possível.

## 8. CLI e códigos de saída

| Comando | Finalidade |
| --- | --- |
| `keygen` | Criar par Ed25519 PEM, recusando sobrescrita de chaves existentes |
| `plan` | Criar plano vinculado ao runbook e à política, com nonce e expiração |
| `approve` | Assinar uma aprovação com chave privada de um signatário |
| `verify` | Validar prazo, assinaturas, identidades, política e quórum |
| `run` | Executar preflight; apenas com `--commit` aplica operações e grava estado |
| `receipt` | Verificar a integridade local do receipt relativo ao plano |

- **`0`**: comando concluído; um `run` sem `--commit` é uma simulação bem-sucedida.
- **`1`**: execução iniciada, mas um passo retornou falha e foi possível registrar o receipt.
- **`2`**: argumentos inválidos, entrada rejeitada, falta de autorizações, replay ou outra impossibilidade de operação.

Saídas de sucesso são JSON, para integração com automação. Erros são emitidos no stderr sem imprimir o conteúdo das chaves privadas.

## 9. Segurança e limitações

A ferramenta implementa defesa em profundidade em escopo restrito, mas **não comprova conformidade regulatória** e não impede todas as ameaças de um administrador local comprometido.

**Controles de entrada:** JSON de até 1 MiB, profundidade de até 32 níveis, chaves duplicadas rejeitadas, campos inesperados bloqueados, tipos e ranges controlados, limites de etapas, nomes de arquivo conservadores e não sobrescrita de artefatos.

**Controles de autorização:** aprovação Ed25519 com domínio de assinatura, chave pública verificada como Ed25519, assinaturas canônicas, IDs distintos, rejeição de autoaprovação, prazo UTC e vínculo da política e do plano.

**Controles operacionais:** comando predefinido sem shell, binário com SHA-256, timeout, ambiente reduzido, não gravação do stdout/stderr, claim atômico por plano e `stateDir` privado. A privacidade do estado e a integridade das chaves dependem do host.

**Limitações relevantes:** não há execução distribuída nem sandbox, revogação remota, rollback automático, gestão de identidades corporativas, logs append-only externos ou relógio confiável independente; symlinks podem ser introduzidos por processo concorrente após validação (*TOCTOU*). Duas chaves distintas **não garantem** dois humanos independentes. Veja [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) e [`SECURITY.md`](SECURITY.md).

## 10. Testes, GitHub Actions e releases

```bash
npm ci --ignore-scripts --no-audit
npm run syntax
npm test
npm run smoke
npm pack --dry-run
```

O workflow [`ci.yml`](.github/workflows/ci.yml) prepara uma matriz de **Ubuntu e Windows** com **Node.js 22 e 24**, executa verificação sintática, testes unitários e adversariais, smoke de ponta a ponta e inspeção do empacotamento. PRs têm permissões de leitura e **não** criam release.

**Publicação automatizada:** ao receber um push na branch `main` de `felipewatter/quorumops`, o job `release` espera todos os testes terminarem com sucesso. Se `main` continuar apontando para o commit testado e a versão ainda não tiver release, cria a tag/release `v1.0.0` a partir do `package.json`, anexa o ZIP dos arquivos rastreados pelo Git e o checksum `.sha256`.

- Não há promessa de CI remoto antes de um run real.
- O release é idempotente por versão; novas versões exigem atualizar `package.json`, `package-lock.json` e `RELEASE_NOTES.md`.
- Os checksums validam bytes, mas sua distribuição confiável e autenticação permanecem necessárias.
- O workflow espera que o repositório tenha **nome `quorumops`**, branch padrão **`main`** e GitHub Actions habilitado.

## 11. Casos de uso em TI

- **Pós-manutenção:** exigir duas aprovações para validar um arquivo conhecido e registrar o encerramento de uma intervenção.
- **Change management:** anexar o plano assinado e o recibo de execução ao chamado ITSM como evidência adicional (integração manual nesta versão).
- **Resposta a incidentes:** limitar diagnósticos a comandos explícitos aprovados e registrar a tentativa que foi efetivamente iniciada.
- **Revisão de configuração:** bloquear uma execução caso a configuração JSON ou o binário autorizado não corresponda ao estado aprovado.
- **Laboratório DevSecOps:** demonstrar riscos de replay, adulteração de plano, assinatura inválida, permissões excessivas e ausência de segregação de funções.

## 12. Documentação e referências

- [Modelo de ameaças](docs/THREAT_MODEL.md)
- [Arquitetura detalhada](docs/ARCHITECTURE.md)
- [Catálogo de controles e testes](docs/SECURITY_CONTROLS.md)
- [Política de segurança](SECURITY.md)
- [Como contribuir](CONTRIBUTING.md)
- [Histórico de versões](CHANGELOG.md)
- [Rundeck — plataforma de automação de runbooks](https://docs.rundeck.com/docs/introduction/introduction.html)
- [NIST SP 800-53 Rev. 5 — AC-5, AC-6, CM-3, CM-5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [Node.js — Ed25519 e `crypto.sign`/`crypto.verify`](https://nodejs.org/api/crypto.html)
- [RFC 6901 — JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901)

---

**Licença:** [MIT](LICENSE) · **Autor:** [Felipe Silva](https://github.com/felipewatter) · **Escopo:** pesquisa prática, segurança defensiva e operações autorizadas de TI.
