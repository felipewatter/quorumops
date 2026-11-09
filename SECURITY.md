# Política de segurança

## Relato responsável

Não publique detalhes exploráveis ou chaves privadas em issues públicas. Use o mecanismo **Report a vulnerability** do GitHub, caso esteja habilitado no repositório, ou contate o mantenedor por um canal privado disponibilizado em seu perfil. Se um canal privado não estiver disponível, solicite-o sem incluir prova de conceito explorável.

## Escopo de segurança

- QuorumOps **não** oferece execução remota, conta central, autenticação de rede, controle de acesso ao host, proteção de chave privada por HSM ou isolamento de processos.
- Executa localmente, com **a mesma identidade e os mesmos privilégios do processo Node.js**. Nunca execute como root/administrador sem justificativa e controles externos.
- O controle de reexecução pressupõe um `stateDir` local, privado e **persistente**. Apagá-lo ou copiá-lo de maneira inconsistente elimina garantias de replay.
- Chaves privadas devem ser protegidas pelo titular, idealmente criptografadas em armazenamento externo/HSM. `keygen` grava PEM sem senha para uso laboratorial; é responsabilidade do usuário administrar a proteção dessas chaves.
- Um `record_marker` cria um novo arquivo e um `exec` chama um binário aprovado. **Não há rollback**, nem sandbox, nem atestação independente da veracidade da execução.
- O arquivo de receipt possui hash de integridade para detecção de alterações acidentais ou em verificação ancorada externamente; **não é uma assinatura** e não impede que um administrador com acesso ao estado o reescreva com outro hash.
- Não utilize em ambientes de produção sem revisão de risco, piloto e monitoramento independente.

## Antes de um release

`npm ci --ignore-scripts`, `npm run syntax`, `npm test`, `npm run smoke`, revisão do pacote (`npm pack --dry-run`) e execução real de GitHub Actions. A presença de um workflow não comprova sua execução remota.

## Versões

Node.js 22 e 24 são os alvos de CI. Para outras plataformas, valide previamente as regras de permissões, paths, symlinks e modos de arquivo.
