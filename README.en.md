# QuorumOps — Secure Runbook Execution Gate

QuorumOps is a **local**, defensive IT-operations runbook authorization gate. An operator creates a time-bound plan bound to a JSON policy and a runbook. Two or more independent Ed25519 signers approve the canonical plan digest. The gate verifies signatures, authorization policy, expiry, strict input validation, command allowlisting, and workspace preconditions **before** any action is allowed.

The default mode is a read-only dry-run. Mutations require `--commit`, and each plan can be claimed for execution at most once per trusted persistent state directory. Supported steps: SHA-256 file assertion, strict JSON Pointer assertion, exclusive marker-file creation, and a fixed, explicitly allowlisted native executable with binary fingerprint, fixed arguments, and timeout. No arbitrary shell expressions, remote executor or third-party runtime dependencies are included.

## Quick start

Requires Node.js 22+.

```bash
npm ci --ignore-scripts
npm run demo:init
node src/cli.mjs plan --runbook demo/runbook.json --policy demo/policy.json --requester operator --ttl 1200 --out demo/plan.json
node src/cli.mjs approve --plan demo/plan.json --approver security --key demo/keys/security.private.pem --out demo/security.approval.json
node src/cli.mjs approve --plan demo/plan.json --approver operations --key demo/keys/operations.private.pem --out demo/operations.approval.json
node src/cli.mjs verify --plan demo/plan.json --policy demo/policy.json --approval demo/security.approval.json --approval demo/operations.approval.json
node src/cli.mjs run --plan demo/plan.json --policy demo/policy.json --approval demo/security.approval.json --approval demo/operations.approval.json --root demo/workspace --state demo/state
# Add --commit to actually create the example marker.
```

## Security boundaries

- This is **not** a remote automation engine, OS sandbox, PAM/ITSM replacement, tamper-proof audit ledger, certified compliance control, or corporate identity provider.
- Independent key IDs do not prove independently controlled human identities. Keep private keys in separate custody.
- Do not execute untrusted approved binaries, and do not run the tool with elevated privileges by default.
- The replay guard requires trusted, private, durable local state and a trusted system clock.
- Receipts have an unkeyed digest and are **not cryptographically signed evidence against a malicious local administrator**.
- On failures there is no rollback; refer to the Portuguese [`README.md`](README.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for complete constraints.

## CI and release

`npm run syntax && npm test && npm run smoke` checks the current local version. GitHub Actions is configured for Ubuntu and Windows on Node.js 22/24. A push to the `main` branch of `felipewatter/quorumops` triggers a release only if the entire CI matrix succeeds, the commit remains the branch tip, and that package version has not been released. No CI or release is claimed to have run before actual publication.

**License:** MIT · **Author:** [Felipe Silva](https://github.com/felipewatter).
