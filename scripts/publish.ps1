<#
  PUBLICAÇÃO OPCIONAL VIA CLI DO WINDOWS.
  Uso SOMENTE após criar https://github.com/felipewatter/quorumops vazio.
  Só atua no diretório atual e no repositório público felipewatter/quorumops.
  O workflow CI criará o release v1.0.0 APÓS passar toda a matriz.
#>
[CmdletBinding()]
param(
  [string]$Repository = 'felipewatter/quorumops'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Repository -ne 'felipewatter/quorumops') {
  throw 'Este script é deliberadamente limitado ao repositório felipewatter/quorumops.'
}
if (-not (Test-Path './package.json') -or -not (Test-Path './src/cli.mjs')) {
  throw 'Execute este script na raiz do projeto QuorumOps extraído.'
}
foreach ($cmd in @('git','gh','node','npm')) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "Comando nao instalado: $cmd" }
}
Write-Host 'Autenticacao GitHub CLI:'
& gh auth status
if ($LASTEXITCODE -ne 0) {
  & gh auth login --web --git-protocol https
  if ($LASTEXITCODE -ne 0) { throw 'Falha na autenticacao GitHub CLI' }
}
$repo = (& gh repo view $Repository --json nameWithOwner,visibility --jq '.nameWithOwner + "|" + .visibility')
if ($LASTEXITCODE -ne 0 -or $repo.Trim() -ne 'felipewatter/quorumops|PUBLIC') {
  throw 'Crie primeiro o repositorio PUBLICO felipewatter/quorumops.'
}
& npm ci --ignore-scripts --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw 'npm ci falhou' }
& npm run syntax
if ($LASTEXITCODE -ne 0) { throw 'Syntax check falhou' }
& npm test
if ($LASTEXITCODE -ne 0) { throw 'Testes falharam' }
& npm run smoke
if ($LASTEXITCODE -ne 0) { throw 'Smoke falhou' }
if (-not (Test-Path './.git')) {
  & git init -b main
  if ($LASTEXITCODE -ne 0) { throw 'git init falhou' }
}
$remote = 'https://github.com/felipewatter/quorumops.git'
$existing = & git remote get-url origin 2>$null
if ($LASTEXITCODE -eq 0) {
  if ($existing.Trim() -ne $remote) { throw "O origin atual e outro: $existing" }
} else {
  & git remote add origin $remote
}
& git add -- .
if ($LASTEXITCODE -ne 0) { throw 'git add falhou' }
$unwanted = & git diff --cached --name-only | Select-String -Pattern '(^|/)(demo|keys|state)/|\.private\.pem$|\.approval\.json$'
if ($unwanted) { throw 'Detectados arquivos de chaves privadas ou estado no staging. Publicacao cancelada.' }
& git diff --cached --quiet
if ($LASTEXITCODE -eq 1) {
  $accountId = (& gh api user --jq '.id').Trim()
  if ($LASTEXITCODE -ne 0 -or $accountId -notmatch '^[0-9]+$') { throw 'Nao foi possivel obter ID publico da conta GitHub autenticada' }
  $noReplyEmail = "${accountId}+felipewatter@users.noreply.github.com"
  & git -c user.name='Felipe Silva' -c "user.email=$noReplyEmail" commit -m 'feat: initial QuorumOps secure runbook gate v1.0.0'
  if ($LASTEXITCODE -ne 0) { throw 'git commit falhou' }
}
& git branch -M main
& git push -u origin main
if ($LASTEXITCODE -ne 0) { throw 'git push falhou; verifique se o repositorio esta vazio e sua permissao de push.' }
Write-Host 'Codigo enviado. Confira o Actions; o release sera criado automaticamente somente apos CI aprovada.'
Write-Host 'https://github.com/felipewatter/quorumops/actions'
