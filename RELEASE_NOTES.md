# QuorumOps v1.0.0

Lançamento inicial do motor local de aprovação criptográfica de runbooks de TI.

**Principais entregas:** autorização de 2 ou mais aprovadores independentes com Ed25519; planos vinculados à política, limitados por prazo e nonce; comandos somente por cadastro de executáveis com SHA-256; operações `assert_file`, `assert_json`, `record_marker` e `exec`; modo seguro de simulação; bloqueio de replay por estado persistente; receipts de execução verificáveis localmente.

**Segurança e uso:** projeto experimental de demonstração profissional. Não é executor remoto, HSM, sandbox ou solução corporativa completa de ITSM. Testar em laboratório antes de usar na operação. Não armazene chaves privadas no Git.

**Qualidade:** CI roda testes nas combinações Node 22/24 e Ubuntu/Windows e só gera esta publicação após todos os jobs passarem. Confira os resultados reais em Actions e os checksums anexos.
