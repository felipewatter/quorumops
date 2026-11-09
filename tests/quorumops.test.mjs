import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { strictParse, canonical } from '../src/strict-json.mjs';
import { generateKeys, preparePlan, createApproval, verifyApprovals, sha256, digest,
  validatePolicy, validateRunbook, safeWorkspaceFile, readJSON, hashFile, writeJSONNew } from '../src/core.mjs';
import { runWorkflow, verifyReceipt } from '../src/workflow.mjs';

const DATE=new Date('2026-11-09T18:00:00.000Z');
async function env(t) {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'quorumops-test-'));
  t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const root=path.join(dir,'workspace');const keys=path.join(dir,'keys');
  await fs.mkdir(root);
  await fs.writeFile(path.join(root,'health.txt'),'HEALTHY\n');
  const a=await generateKeys(keys,'sec'); const b=await generateKeys(keys,'ops');
  const policy={schema:'quorumops.policy.v1',requiredApprovals:2,maxTtlSeconds:3600,allowMarkers:true,commands:{},
    approvers:[a,b].map(({id,publicKey})=>({id,publicKey}))};
  const runbook={schema:'quorumops.runbook.v1',id:'change-1',description:'A verified local operational runbook',steps:[
    {id:'assert-hash',type:'assert_file',path:'health.txt',sha256:sha256('HEALTHY\n')},
    {id:'marker',type:'record_marker',path:'success.txt',text:'Completed'}
  ]};
  const plan=preparePlan(runbook,policy,'requester',1200,DATE);
  async function approve(id, currentPlan=plan) {
    const pem=await fs.readFile(path.join(keys,id+'.private.pem'),'utf8');
    return createApproval(currentPlan,id,pem,new Date(DATE.getTime()+1000));
  }
  const approvals=[await approve('sec'),await approve('ops')];
  return {dir,root,keys,policy,runbook,plan,approvals,approve};
}

test('strict decoder rejects duplicate keys including nested objects',()=>{
  assert.throws(()=>strictParse('{"a":1,"a":2}'),/Duplicate/);
  assert.throws(()=>strictParse('{"deep":{"x":1,"x":2}}'),/Duplicate/);
  assert.throws(()=>strictParse('{"a": 3} trailing'),/trailing/);
  assert.throws(()=>strictParse('{"x":NaN}'),/Invalid/);
  assert.throws(()=>strictParse('['.repeat(40)+'0'+']'.repeat(40)),/nesting/);
});
test('canonical JSON is order invariant and rejects nonfinite numbers',()=>{
  assert.equal(canonical({a:1,b:{c:3,d:2}}),canonical({b:{d:2,c:3},a:1}));
  assert.throws(()=>canonical(Infinity),/Nonfinite/);
});
test('policy refuses quorum one and key reuse',async t=>{
  const x=await env(t);
  assert.throws(()=>validatePolicy({...x.policy,requiredApprovals:1}),/2..10/);
  assert.throws(()=>validatePolicy({...x.policy,approvers:[x.policy.approvers[0],{...x.policy.approvers[1],publicKey:x.policy.approvers[0].publicKey}]}),/Duplicate approver public key/);
});
test('runbook rejects traversal, absolute paths, shell-like unsupported step',async t=>{
  const x=await env(t);
  for(const bad of ['../private','/etc/passwd','C:/windows/system.ini','ok/../../escape','x\\y']){
    assert.throws(()=>validateRunbook({...x.runbook,steps:[{id:'a',type:'assert_file',path:bad,sha256:sha256('x')}]}),/Invalid/);
  }
  assert.throws(()=>validateRunbook({...x.runbook,steps:[{id:'a',type:'shell',command:'rm -rf /'}]}),/Unrecognized/);
});
test('plan binds policy, expiry and requesting identity',async t=>{
  const x=await env(t);
  assert.throws(()=>preparePlan(x.runbook,x.policy,'sec',100,DATE),/Requester/);
  assert.throws(()=>preparePlan(x.runbook,x.policy,'req',7200,DATE),/TTL/);
  assert.throws(()=>verifyApprovals(x.plan,{...x.policy,allowMarkers:false},x.approvals,DATE),/Policy changed/);
  assert.throws(()=>verifyApprovals(x.plan,x.policy,x.approvals,new Date(DATE.getTime()+3600000)),/expired/);
});
test('approval signatures verify for distinct eligible signers',async t=>{
  const x=await env(t);
  const result=verifyApprovals(x.plan,x.policy,x.approvals,DATE);
  assert.equal(result.ok,true);assert.deepEqual(result.validApprovers,['ops','sec']);
});
test('one approval, repeated signer and untrusted signer are blocked',async t=>{
  const x=await env(t);
  assert.throws(()=>verifyApprovals(x.plan,x.policy,x.approvals.slice(0,1),DATE),/Quorum/);
  assert.throws(()=>verifyApprovals(x.plan,x.policy,[x.approvals[0],x.approvals[0]],DATE),/duplicate/);
  assert.throws(()=>verifyApprovals(x.plan,x.policy,[{...x.approvals[0],approver:'rogue'},x.approvals[1]],DATE),/Untrusted/);
});
test('tampered plan, approval content and signature are blocked',async t=>{
  const x=await env(t);
  const modifiedPlan={...x.plan,runbook:{...x.plan.runbook,id:'changed'}};
  assert.throws(()=>verifyApprovals(modifiedPlan,x.policy,x.approvals,DATE),/different plan/);
  assert.throws(()=>verifyApprovals(x.plan,x.policy,[{...x.approvals[0],issuedAt:DATE.toISOString()},x.approvals[1]],DATE),/Signature invalid/);
  assert.throws(()=>verifyApprovals(x.plan,x.policy,[{...x.approvals[0],signature:'A'.repeat(88)},x.approvals[1]],DATE),/signature|Signature/);
});
test('unknown or forbidden fields are rejected fail-closed',async t=>{
  const x=await env(t);
  assert.throws(()=>verifyApprovals({...x.plan,magic:true},x.policy,x.approvals,DATE),/forbidden/);
  assert.throws(()=>validatePolicy({...x.policy,unknown:true}),/forbidden/);
});
test('dry run proves authorization but never writes a marker or state',async t=>{
  const x=await env(t);
  const stateDir=path.join(x.dir,'state');
  const result=await runWorkflow({...x,root:x.root,stateDir,commit:false,now:DATE});
  assert.equal(result.dryRun,true); assert.equal(result.steps.length,2);
  await assert.rejects(fs.access(path.join(x.root,'success.txt')), /ENOENT/);
  await assert.rejects(fs.access(stateDir), /ENOENT/);
});
test('committed run creates marker and replay-safe receipt',async t=>{
  const x=await env(t);const stateDir=path.join(x.dir,'state');
  const result=await runWorkflow({...x,stateDir,commit:true,now:DATE});
  assert.equal(result.receipt.success,true);
  assert.equal(await fs.readFile(path.join(x.root,'success.txt'),'utf8'),'Completed\n');
  assert.equal((await verifyReceipt(result.receipt,x.plan)).ok,true);
  await assert.rejects(()=>runWorkflow({...x,stateDir,commit:true,now:DATE}),/EEXIST|Marker already exists/);
});
test('plan nonce differs for two otherwise identical plans',async t=>{
  const x=await env(t);
  const other=preparePlan(x.runbook,x.policy,'requester',1200,DATE);
  assert.notEqual(digest(other),digest(x.plan));
  assert.throws(()=>verifyApprovals(other,x.policy,x.approvals,DATE),/different plan/);
});
test('readJSON rejects duplicate keys and symlinked input',async t=>{
  const x=await env(t);
  await fs.writeFile(path.join(x.dir,'duplicate.json'),'{"a":1,"a":2}');
  await assert.rejects(readJSON(path.join(x.dir,'duplicate.json')),/Duplicate/);
  if (process.platform !== 'win32') {
    await fs.symlink(path.join(x.dir,'duplicate.json'),path.join(x.dir,'alias.json'));
    await assert.rejects(readJSON(path.join(x.dir,'alias.json')),/regular/);
  }
});
test('workspace refuses symlink traversal and symlinked root',async t=>{
  if (process.platform === 'win32') return;
  const x=await env(t);
  await fs.symlink('health.txt',path.join(x.root,'alias.txt'));
  await assert.rejects(()=>safeWorkspaceFile(x.root,'alias.txt'),/Symlink/);
  await fs.symlink(x.root,path.join(x.dir,'root-alias'));
  await assert.rejects(()=>safeWorkspaceFile(path.join(x.dir,'root-alias'),'health.txt'),/non-symlink/);
});
test('failing preflight never mutates files and consumes no authorization',async t=>{
  const x=await env(t);
  await fs.writeFile(path.join(x.root,'health.txt'),'TAMPERED');
  await assert.rejects(()=>runWorkflow({...x,stateDir:path.join(x.dir,'state'),commit:true,now:DATE}),/mismatch/);
  await assert.rejects(fs.access(path.join(x.root,'success.txt')),/ENOENT/);
  await assert.rejects(fs.access(path.join(x.dir,'state')),/ENOENT/);
});
test('assert_json supports escaped pointers and scalar equality',async t=>{
  const x=await env(t);
  await fs.writeFile(path.join(x.root,'config.json'),'{"a/b":{"~key":true}}');
  x.runbook.steps=[{id:'assert-json',type:'assert_json',path:'config.json',pointer:'/a~1b/~0key',equals:true}];
  x.plan=preparePlan(x.runbook,x.policy,'requester',600,DATE);
  x.approvals=[await x.approve('sec',x.plan),await x.approve('ops',x.plan)];
  const result=await runWorkflow({...x,commit:false,now:DATE});
  assert.equal(result.steps.length,1);
});
test('exec requires registered fixed command, no arbitrary arguments',async t=>{
  const x=await env(t);
  x.runbook.steps=[{id:'execute-unknown',type:'exec',command:'unlisted'}];
  x.plan=preparePlan(x.runbook,x.policy,'requester',600,DATE);
  x.approvals=[await x.approve('sec',x.plan),await x.approve('ops',x.plan)];
  await assert.rejects(()=>runWorkflow({...x,commit:false,now:DATE}),/not approved/);
});
test('hashFile handles bounded size and hash matching',async t=>{
  const x=await env(t);
  assert.equal(await hashFile(path.join(x.root,'health.txt')),sha256('HEALTHY\n'));
  await assert.rejects(()=>hashFile(path.join(x.root,'health.txt'),2),/limit/);
});
test('writeJSONNew refuses to overwrite existing approvals',async t=>{
  const x=await env(t);const file=path.join(x.dir,'protected.json');
  await writeJSONNew(file,{ok:true});
  await assert.rejects(()=>writeJSONNew(file,{ok:false}),/EEXIST/);
});
test('receipt rejects modified execution evidence',async t=>{
  const x=await env(t);const stateDir=path.join(x.dir,'state');
  const result=await runWorkflow({...x,stateDir,commit:true,now:DATE});
  await assert.rejects(()=>verifyReceipt({...result.receipt,success:false},x.plan),/digest invalid/);
});
test('state directory must be private',async t=>{
  if(process.platform==='win32')return;
  const x=await env(t);const stateDir=path.join(x.dir,'state');
  await fs.mkdir(stateDir,{mode:0o777});await fs.chmod(stateDir,0o777);
  await assert.rejects(()=>runWorkflow({...x,stateDir,commit:true,now:DATE}),/owner-only/);
});
test('successful allowlisted exec runs fixed args, returns only metadata',async t=>{
  const x=await env(t);
  const binHash=await hashFile(process.execPath,256*1024*1024);
  x.policy.commands={nodeVersion:{executable:process.execPath,sha256:binHash,args:['--version'],timeoutMs:10000}};
  x.runbook.steps=[{id:'exec-version',type:'exec',command:'nodeVersion'}];
  x.plan=preparePlan(x.runbook,x.policy,'requester',600,DATE);
  x.approvals=[await x.approve('sec',x.plan),await x.approve('ops',x.plan)];
  const result=await runWorkflow({...x,commit:true,stateDir:path.join(x.dir,'state'),now:DATE});
  assert.equal(result.receipt.success,true);
  assert.equal(result.receipt.steps[0].exitCode,0);
  assert.ok(result.receipt.steps[0].outputBytes>0);
  assert.equal(JSON.stringify(result.receipt).includes(process.version),false);
});
test('tampered approved executable fingerprint blocks exec before claiming state',async t=>{
  const x=await env(t);
  x.policy.commands={nodeVersion:{executable:process.execPath,sha256:sha256('not-node'),args:['--version'],timeoutMs:1000}};
  x.runbook.steps=[{id:'version',type:'exec',command:'nodeVersion'}];
  x.plan=preparePlan(x.runbook,x.policy,'requester',600,DATE);
  x.approvals=[await x.approve('sec',x.plan),await x.approve('ops',x.plan)];
  await assert.rejects(()=>runWorkflow({...x,commit:true,stateDir:path.join(x.dir,'state'),now:DATE}),/hash mismatch/);
});
test('atomic one-time claim rejects a concurrent attempt even with no marker step',async t=>{
  const x=await env(t);x.runbook.steps=x.runbook.steps.slice(0,1);
  x.plan=preparePlan(x.runbook,x.policy,'requester',600,DATE);
  x.approvals=[await x.approve('sec',x.plan),await x.approve('ops',x.plan)];
  const stateDir=path.join(x.dir,'state');
  const all=await Promise.allSettled([runWorkflow({...x,stateDir,commit:true,now:DATE}),runWorkflow({...x,stateDir,commit:true,now:DATE})]);
  assert.equal(all.filter(r=>r.status==='fulfilled').length,1);
  assert.equal(all.filter(r=>r.status==='rejected').length,1);
  assert.match(all.find(r=>r.status==='rejected').reason.message,/EEXIST/);
});
test('future dated approval beyond tolerance is rejected',async t=>{
  const x=await env(t);
  const privatePem=await fs.readFile(path.join(x.keys,'sec.private.pem'),'utf8');
  const future=createApproval(x.plan,'sec',privatePem,new Date(DATE.getTime()+100000));
  assert.throws(()=>verifyApprovals(x.plan,x.policy,[future,x.approvals[1]],DATE),/timestamp/);
});

test('nonexistent UTC calendar dates are rejected instead of normalized',async t=>{
  const x=await env(t);
  assert.throws(()=>verifyApprovals({...x.plan,createdAt:'2026-02-30T18:00:00.000Z'},x.policy,x.approvals,DATE),/Invalid plan identity or dates/);
});
