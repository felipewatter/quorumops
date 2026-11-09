/** Complete CLI smoke test using temporary keys that are never placed in the repository. */
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const home=await fs.mkdtemp(path.join(os.tmpdir(),'quorumops-smoke-'));
const cli=fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
function run(...args) {
 const p=spawnSync(process.execPath,[cli,...args],{encoding:'utf8',timeout:15000});
 if(p.status!==0) throw new Error(`smoke ${args[0]} failed: ${p.stdout} ${p.stderr}`);
 return JSON.parse(p.stdout);
}
try {
 const keys=path.join(home,'keys');
 const a=run('keygen','--id','sec','--out',keys);
 const b=run('keygen','--id','ops','--out',keys);
 const policy={schema:'quorumops.policy.v1',requiredApprovals:2,maxTtlSeconds:3600,allowMarkers:true,commands:{},
   approvers:[a,b].map(({id,publicKey})=>({id,publicKey}))};
 const policyFile=path.join(home,'policy.json');const planFile=path.join(home,'plan.json');
 const runbook=fileURLToPath(new URL('../examples/runbook.json',import.meta.url));
 const root=path.join(home,'workspace');const state=path.join(home,'state');
 await fs.mkdir(root);await fs.copyFile(new URL('../examples/workspace/health.txt',import.meta.url),path.join(root,'health.txt'));
 await fs.writeFile(policyFile,JSON.stringify(policy,null,2));
 const plan=run('plan','--runbook',runbook,'--policy',policyFile,'--requester','operator','--ttl','1200','--out',planFile);
 const approvals=[];
 for(const id of ['sec','ops']) {
  const out=path.join(home,id+'.json');
  run('approve','--plan',planFile,'--approver',id,'--key',path.join(keys,id+'.private.pem'),'--out',out);
  approvals.push('--approval',out);
 }
 const verification=run('verify','--plan',planFile,'--policy',policyFile,...approvals);
 const dry=run('run','--plan',planFile,'--policy',policyFile,...approvals,'--root',root,'--state',state);
 if(!dry.dryRun || !verification.ok) throw new Error('Dryrun or signatures failed');
 const result=run('run','--plan',planFile,'--policy',policyFile,...approvals,'--root',root,'--state',state,'--commit');
 if(!result.receipt.success)throw new Error('Run failed');
 const receiptFile=path.join(state,'receipts',plan.planDigest+'.json');
 const receipt=run('receipt','--plan',planFile,'--receipt',receiptFile);
 if(!receipt.ok)throw new Error('Receipt failed');
 const marker=await fs.readFile(path.join(root,'completed.txt'),'utf8');
 if(!marker.includes('QuorumOps'))throw new Error('Marker not written');
 const replay=spawnSync(process.execPath,[cli,'run','--plan',planFile,'--policy',policyFile,...approvals,'--root',root,'--state',state,'--commit'],{encoding:'utf8'});
 if(replay.status===0)throw new Error('Replay was incorrectly authorized');
 console.log(JSON.stringify({ok:true,scenario:'keygen->plan->2 signatures->verify->dry-run->commit->receipt->replay-blocked'}));
} finally { await fs.rm(home,{recursive:true,force:true}); }
