#!/usr/bin/env node
import { promises as fs } from 'node:fs';
import { generateKeys, preparePlan, createApproval, verifyApprovals, readJSON, writeJSONNew, digest } from './core.mjs';
import { runWorkflow, verifyReceipt } from './workflow.mjs';

const help = `QuorumOps v1.0.0 — aprovações Ed25519 e runbooks locais

Uso:
  quorumops keygen --id alice --out keys
  quorumops plan --runbook runbook.json --policy policy.json --requester operator --ttl 1800 --out plan.json
  quorumops approve --plan plan.json --approver alice --key keys/alice.private.pem --out alice.approval.json
  quorumops verify --plan plan.json --policy policy.json --approval alice.approval.json --approval bob.approval.json
  quorumops run --plan plan.json --policy policy.json --approval alice.approval.json --approval bob.approval.json --root ./workspace --state ./state [--commit]
  quorumops receipt --plan plan.json --receipt state/receipts/PLAN_HASH.json

Sem --commit, 'run' apenas simula; com --commit, utiliza uma autorização uma única vez.
`;
function args(rest) {
  const parsed = {approval:[]};
  for (let i=0;i<rest.length;i++) {
    const part = rest[i];
    if (part === '--commit') { if (parsed.commit) throw new Error('Duplicate --commit'); parsed.commit=true;continue; }
    if (!part.startsWith('--')) throw new Error('Unexpected argument: '+part);
    const key=part.slice(2),value=rest[++i];
    if (!['id','out','runbook','policy','requester','ttl','plan','approver','key','approval','root','state','receipt'].includes(key)) throw new Error('Unknown argument: '+key);
    if (!value || value.startsWith('--')) throw new Error('Missing value for '+part);
    if (key === 'approval') parsed.approval.push(value);
    else {if (parsed[key] !== undefined) throw new Error('Duplicate argument: '+key); parsed[key]=value;}
  }
  return parsed;
}
function requireArgs(a, fields) { for (const f of fields) if (!a[f]) throw new Error('Missing --'+f); }
async function main() {
  const [command,...rest]=process.argv.slice(2);
  if (!command || command === '--help' || command === 'help') {process.stdout.write(help);return;}
  if (command === '--version') {console.log('1.0.0');return;}
  const a=args(rest);
  let result;
  if (command === 'keygen') {
    requireArgs(a,['id','out']);result=await generateKeys(a.out,a.id);
  } else if (command === 'plan') {
    requireArgs(a,['runbook','policy','requester','ttl','out']);
    const plan=preparePlan(await readJSON(a.runbook),await readJSON(a.policy),a.requester,Number(a.ttl));
    await writeJSONNew(a.out,plan);result={planDigest:digest(plan),expiresAt:plan.expiresAt,output:a.out};
  } else if (command === 'approve') {
    requireArgs(a,['plan','approver','key','out']);
    const stat=await fs.lstat(a.key);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Private key must be a regular file');
    if (process.platform !== 'win32' && (stat.mode & 0o077)!==0) throw new Error('Private key permissions must be 600');
    const privatePem=await fs.readFile(a.key,'utf8');
    const approval=createApproval(await readJSON(a.plan),a.approver,privatePem);
    await writeJSONNew(a.out,approval);result={approver:a.approver,planDigest:approval.planDigest,output:a.out};
  } else if (command === 'verify') {
    requireArgs(a,['plan','policy']);
    result=verifyApprovals(await readJSON(a.plan),await readJSON(a.policy),await Promise.all(a.approval.map(readJSON)));
  } else if (command === 'run') {
    requireArgs(a,['plan','policy','root']);
    if (a.commit) requireArgs(a,['state']);
    result=await runWorkflow({plan:await readJSON(a.plan),policy:await readJSON(a.policy),
      approvals:await Promise.all(a.approval.map(readJSON)),root:a.root,stateDir:a.state,commit:!!a.commit});
    if (result.receipt && !result.receipt.success) process.exitCode=1;
  } else if (command === 'receipt') {
    requireArgs(a,['plan','receipt']);
    result=await verifyReceipt(await readJSON(a.receipt),await readJSON(a.plan));
  } else throw new Error('Unsupported command: '+command);
  console.log(JSON.stringify(result,null,2));
}
main().catch(e=>{ console.error(JSON.stringify({error:e?.message ?? String(e)}));process.exitCode=2; });
