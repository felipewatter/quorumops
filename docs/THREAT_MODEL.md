# Modelo de ameaças — QuorumOps v1.0.0

## Ativos e fronteiras de confiança

1. **Política**: quórum mínimo, conjunto de chaves públicas e catálogo de comandos são configurados por autoridade externa confiável.
2. **Chaves privadas**: cada titular deve protegê-las separadamente, fora de repositórios e canais públicos. A CLI não constitui um HSM.
3. **Workspace**: diretório local fornecido pelo operador, com arquivos controlados; não pode ser influenciado por adversário com permissão de escrita concorrente para ameaças de race condition.
4. **Estado persistente**: diretório privado e durável não controlado por usuário malicioso; é o único mecanismo contra reexecução no mesmo host/instância.
5. **Relógio e runtime**: sistema operacional, Node.js e relógio do host considerados confiáveis.

## Adversários considerados

- Usuário que edita ou substitui JSON não confiável e tenta inserir campos extras, caminhos perigosos, IDs repetidos, prazo alterado ou operações não previstas.
- Ator com **um** arquivo de aprovação legítimo que tenta reutilizá-lo em plano diferente, adulterar campos ou assinar como outra identidade.
- Processo local que tenta enviar uma segunda execução do mesmo plano ao mesmo estado.
- Remetente de runbook que tenta executar binário não autorizado ou instrução de shell arbitrária.

## Controles e testes

| Ameaça | Controle | Teste exercitado |
| --- | --- | --- |
| Plano adulterado | Assinatura vinculada a `planDigest` | `tampered plan` |
| Política substituída | Digest da política registrado no plano | `plan binds policy` |
| Aprovação reutilizada | Nonce do plano + digest assinado | `plan nonce differs` |
| Um único aprovador | Quórum mínimo 2, IDs e chaves distintos | `one approval ... blocked` |
| Signatário malicioso/forjado | Chave Ed25519 pública em trust root | `tampered ... signature` |
| Autorização expirada | UTC e prazo máximo por política | `plan binds policy, expiry` |
| Campos ocultos/ambíguos | Parser estrito e whitelist de propriedades | `strict decoder`, `unknown fields` |
| Traversal e symlinks | Paths relativos seguros, checagens de `lstat`, `O_NOFOLLOW` quando disponível | `runbook rejects traversal`, `workspace refuses symlink` |
| Comando inesperado | Cadastro por ID, hash do executável e args fixos | `exec requires registered`, `tampered executable` |
| Execução implícita | Ausência de `--commit` é dry-run | `dry run never writes` |
| Replay/concorrrência | `O_EXCL` no estado local | `atomic one-time claim` |
| Dados de saída de comando | Descarta stdout/stderr, limita 16 KiB | `successful allowlisted exec` |
| Falha silenciosa de etapa | Receipt com `success:false` quando possível | Smoke e testes de receipt |

## Ameaças **não** mitigadas

1. **Admin/root comprometido:** pode copiar chaves privadas, alterar relógio, trocar Node.js, alterar executáveis ou apagar o estado. QuorumOps não substitui confiança no host ou monitoramento externo.
2. **Colusão real ou identidade falsa:** duas chaves distintas não garantem duas pessoas diferentes, e cadastro de IDs depende de processo organizacional externo.
3. **TOCTOU:** entre validação de caminhos, hashes e abertura/execução, um adversário com acesso de escrita concorrente pode alterar arquivos ou substituí-los. A revalidação reduz, mas não elimina esse risco.
4. **Rollback:** comandos e marcadores que tiveram efeito antes de erro não são revertidos. O plano é consumido após uma tentativa, inclusive se o processo cair.
5. **Revogação centralizada:** não há CRL, OCSP, serviço central de chave ou identidade federada. Alterar a política invalida planos antigos, mas não impede uso de cópia antiga da política em host descontrolado.
6. **Execução remota / ambiente isolado:** processos são locais e têm permissões do usuário que invoca a CLI. O programa aprovado pode executar outras ações não modeladas.
7. **Assinatura de receipt:** o hash não é assinatura. Se o estado for controlado por adversário, ele pode reescrever o receipt e recalcular o hash. Recomenda-se exportar o digest para log/WORM independente, caso seja necessária comprovação externa.
8. **Filesystem remoto / compartilhado:** sem garantia de criação exclusiva atômica, o mecanismo anti-replay não é confiável. Utilize disco local com semântica documentada.
9. **Grande volume ou abuso de CPU:** limites protegem alguns tamanhos, mas não existem cotas globais de CPU/memória, isolamento de processo ou gerenciamento distribuído de filas.
10. **Windows ACLs:** não há validação equivalente integral de permissões da DACL nem garantia universal de `O_NOFOLLOW`.

## Recomendações de adoção

- Use usuário de serviço sem privilégios, com permissões mínimas e root de workspace confiável.
- Proteja cada chave privada com cofre separado ou hardware onde disponível, e mantenha a distribuição de chaves públicas sob governança.
- Faça os aprovadores inspecionarem o **digest do plano, runbook, política e escopo da ação**, não apenas o nome da mudança.
- Mantenha estado em volume local persistente, com backup protegido e controle de alterações independente.
- Garanta relógio sincronizado e registro externo dos eventos e receipts quando o requisito for rastreabilidade auditável.
- Trate falhas após `claim` como incidentes de operação; reanalise estado antes de gerar **novo** plano.

## Referências de controle

Inspirado em conceitos de **NIST SP 800-53 Rev. 5**: AC-5 (segregação de funções), AC-6 (menor privilégio), CM-3 (controle de mudanças) e CM-5(4) (dupla autorização). Estes alinhamentos são conceituais; o projeto **não afirma aderência ou certificação NIST**.
