import { promises as fs } from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { canonical } from './strict-json.mjs';
import { SCHEMA, ensure, digest, verifyApprovals, readJSON,
  safeWorkspaceFile, hashFile, writeJSONNew, writeNew } from './core.mjs';

function jsonPointer(obj, pointer) {
  if (pointer === '') return obj;
  let current = obj;
  for (const part of pointer.slice(1).split('/')) {
    ensure(!/~(?![01])/.test(part), 'Invalid JSON Pointer escape');
    const key = part.replace(/~1/g, '/').replace(/~0/g, '~');
    ensure(current !== null && typeof current === 'object' && Object.prototype.hasOwnProperty.call(current, key), 'JSON pointer value missing');
    current = current[key];
  }
  return current;
}
async function preflightStep(step, policy, root) {
  switch (step.type) {
    case 'assert_file': {
      const file = await safeWorkspaceFile(root, step.path);
      ensure(await hashFile(file) === step.sha256, `File hash mismatch: ${step.id}`);
      return { id:step.id, type:step.type, status:'ready' };
    }
    case 'assert_json': {
      const file = await safeWorkspaceFile(root, step.path);
      // readJSON enforces size, symlink and strict JSON constraints.
      const json = await readJSON(file);
      ensure(canonical(jsonPointer(json, step.pointer)) === canonical(step.equals), `JSON assertion failed: ${step.id}`);
      return { id:step.id, type:step.type, status:'ready' };
    }
    case 'record_marker': {
      ensure(policy.allowMarkers, 'Marker operations disabled by policy');
      await safeWorkspaceFile(root, step.path, true);
      return { id:step.id, type:step.type, status:'ready' };
    }
    case 'exec': {
      const command = Object.prototype.hasOwnProperty.call(policy.commands, step.command) ? policy.commands[step.command] : null;
      ensure(command, `Command is not approved in policy: ${step.command}`);
      const binary = await fs.lstat(command.executable);
      ensure(binary.isFile() && !binary.isSymbolicLink(), 'Executable must be regular non-symlink file');
      ensure(await hashFile(command.executable, 256*1024*1024) === command.sha256, 'Approved executable hash mismatch');
      return {id:step.id, type:step.type, status:'ready'};
    }
    default: throw new Error('Unsupported step type');
  }
}

async function runApprovedCommand(command, root) {
  return await new Promise((resolve, reject) => {
    // Fixed command, no arguments from the runbook; no shell, no stdin, no caller env.
    const child = spawn(command.executable, command.args, {
      cwd:root, shell:false, stdio:['ignore','pipe','pipe'],
      env: {PATH: process.platform === 'win32' ? 'C:\\Windows\\System32' : '/usr/bin:/bin',
        LANG:'C', LC_ALL:'C'}, windowsHide:true,
    });
    let bytes = 0; let finished = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), command.timeoutMs);
    const consume = chunk => { bytes += chunk.length; if (bytes > 16384) child.kill('SIGKILL'); };
    child.stdout.on('data',consume); child.stderr.on('data',consume);
    child.on('error', error => { if (!finished) { finished=true;clearTimeout(timer);reject(new Error('Approved command could not start: ' + error.code)); } });
    child.on('close', (code, signal) => {
      if (finished) return; finished=true; clearTimeout(timer);
      if (code !== 0 || signal) reject(new Error(`Approved command returned failure (exit=${code}, signal=${signal ?? 'none'})`));
      else resolve({exitCode:code, outputBytes:bytes});
    });
  });
}

async function doStep(step, policy, root) {
  // Revalidate file preconditions at execution time. No shell or runbook-provided executables.
  await preflightStep(step,policy,root);
  if (step.type === 'record_marker') {
    const target = await safeWorkspaceFile(root,step.path,true);
    await writeNew(target, step.text + '\n');
    return {id:step.id, type:step.type, status:'completed'};
  }
  if (step.type === 'exec') {
    const result = await runApprovedCommand(policy.commands[step.command],root);
    return {id:step.id, type:step.type, status:'completed', ...result};
  }
  return {id:step.id, type:step.type, status:'passed'};
}

/** Offline gate. One-time attempts must be persisted on trusted local storage. */
export async function runWorkflow({plan,policy,approvals,root,stateDir,commit=false,now=new Date()}) {
  const authorization = verifyApprovals(plan,policy,approvals,now);
  const workspace = path.resolve(root);
  const prepared = [];
  for (const step of plan.runbook.steps) prepared.push(await preflightStep(step,policy,workspace));
  if (!commit) return {dryRun:true,authorized:true, authorization, steps:prepared};
  ensure(typeof stateDir === 'string' && stateDir.length > 0, 'State directory required for committed run');
  const dir = path.resolve(stateDir);
  await fs.mkdir(dir, {recursive:true,mode:0o700});
  const stateStat = await fs.lstat(dir);
  ensure(stateStat.isDirectory() && !stateStat.isSymbolicLink(), 'State path is not a safe directory');
  if (process.platform !== 'win32') ensure((stateStat.mode & 0o077) === 0, 'State directory must be owner-only (chmod 700)');
  const attemptsDir = path.join(dir,'attempts'); const receiptsDir = path.join(dir,'receipts');
  await fs.mkdir(attemptsDir,{mode:0o700}); await fs.mkdir(receiptsDir,{mode:0o700});
  for (const d of [attemptsDir,receiptsDir]) {
    const st = await fs.lstat(d);
    ensure(st.isDirectory() && !st.isSymbolicLink() && (process.platform === 'win32' || (st.mode & 0o077) === 0), 'State subdirectory unsafe');
  }
  const planHash = digest(plan);
  // O_EXCL is the local atomic one-time claim; a crash consumes the plan deliberately.
  await writeJSONNew(path.join(attemptsDir,planHash+'.json'), {
    planDigest:planHash, status:'claimed', at:now.toISOString(), approvers:authorization.validApprovers,
  });
  const executed=[]; let success=true; let failure;
  for (const step of plan.runbook.steps) {
    try { executed.push(await doStep(step,policy,workspace)); }
    catch (e) {success=false; failure=e.message;executed.push({id:step.id,type:step.type,status:'failed'});break;}
  }
  const body = { schema:SCHEMA.receipt, planDigest:planHash, runbookId:plan.runbook.id,
    recordedAt:new Date().toISOString(), approvers:authorization.validApprovers, success, steps:executed,
    ...(failure ? {error:failure}:{}), };
  const receipt = {...body, receiptDigest:digest(body)};
  await writeJSONNew(path.join(receiptsDir,planHash+'.json'),receipt);
  return {dryRun:false,authorized:true,receipt};
}

export async function verifyReceipt(receipt, plan) {
  ensure(receipt?.schema === SCHEMA.receipt, 'Receipt schema invalid');
  const {receiptDigest, ...payload}=receipt;
  ensure(typeof receiptDigest === 'string' && receiptDigest === digest(payload), 'Receipt digest invalid');
  ensure(receipt.planDigest === digest(plan), 'Receipt bound to different plan');
  return {ok:true,receiptDigest,success:receipt.success};
}
