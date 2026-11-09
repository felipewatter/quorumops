/** Prepare an isolated training-only environment. Never publishes or reuses demo keys. */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeys } from '../src/core.mjs';
const dir=path.resolve(process.argv[2] || 'demo');
try { await fs.mkdir(dir,{mode:0o700}); } catch(e) {if(e.code==='EEXIST') throw new Error('Destination already exists; refusing to reuse training keys');throw e;}
const keyDir=path.join(dir,'keys');
const a=await generateKeys(keyDir,'security');const b=await generateKeys(keyDir,'operations');
const policy={schema:'quorumops.policy.v1',requiredApprovals:2,maxTtlSeconds:3600,allowMarkers:true,commands:{},
  approvers:[a,b].map(({id,publicKey})=>({id,publicKey}))};
await fs.writeFile(path.join(dir,'policy.json'),JSON.stringify(policy,null,2)+'\n',{mode:0o600,flag:'wx'});
await fs.copyFile(fileURLToPath(new URL('../examples/runbook.json',import.meta.url)),path.join(dir,'runbook.json'));
await fs.mkdir(path.join(dir,'workspace'),{mode:0o700});
await fs.copyFile(fileURLToPath(new URL('../examples/workspace/health.txt',import.meta.url)),path.join(dir,'workspace','health.txt'));
console.log('Demo initialized at '+dir+'; training private keys under keys/ (DO NOT COMMIT)');
