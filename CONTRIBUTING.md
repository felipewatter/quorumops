# Contribuindo com o QuorumOps

1. Abra issue com cenário, efeito esperado, limites de segurança e passos de reprodução usando **dados fictícios**.
2. Proponha mudanças pequenas, inclua testes para caminho seguro, caminho malicioso e comportamento de falha fechada.
3. Execute `npm ci --ignore-scripts && npm run syntax && npm test && npm run smoke` antes de abrir o PR.
4. Não introduza chamadas de shell, execução de texto arbitrário, downloads automáticos ou telemetria sem revisão do modelo de ameaças.
5. Documente mudanças de esquema, semântica de autorização, compatibilidade Windows/Linux, códigos de saída e migrações de estado.

## Convenções

Código em JavaScript ESM, sem dependências de runtime, funções defensivas de parsing, tipos de step explicitamente enumerados, saída de erro com detalhes mínimos. A documentação do usuário é em PT-BR; contribuições em inglês são aceitas.

Código de conduta: mantenha a discussão técnica, respeitosa e voltada à segurança defensiva.
