# Histórico de versões

## [1.0.0] - 2026-11-09 (candidato local; release remoto pendente)

- Primeira implementação do gate local com planos efêmeros e vinculação de política por SHA-256.
- Assinaturas Ed25519 de aprovações com identidades e chaves públicas distintas.
- Quórum de no mínimo dois aprovadores e impedimento de autoaprovação.
- Runbooks de checagem de arquivo, asserção JSON, registro de marcador e comandos predefinidos por política.
- Simulação padrão; execução requer `--commit` e diretório de estado privado.
- Controle de replay mediante reclamação atômica do identificador do plano.
- Receipt com resumo das etapas, SHA-256 local e inspeção posterior.
- Testes unitários/de segurança, smoke E2E, CI matricial e release automático somente após CI aprovado na branch main.
