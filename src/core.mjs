import { createHash, generateKeyPairSync, sign, verify, randomBytes, createPublicKey } from 'node:crypto';
import { promises as fs, constants } from 'node:fs';
import path from 'node:path';
import { canonical, strictParse } from './strict-json.mjs';

export const SCHEMA = {
  policy: 'quorumops.policy.v1', runbook: 'quorumops.runbook.v1',
  plan: 'quorumops.plan.v1', approval: 'quorumops.approval.v1', receipt: 'quorumops.receipt.v1',
};

export function ensure(condition, message) { if (!condition) throw new Error(message); }
export const sha256 = input => createHash('sha256').update(input).digest('hex');
export const digest = value => sha256(canonical(value));
export const isObject = x => x !== null && typeof x === 'object' && !Array.isArray(x);
export const isId = x => typeof x === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(x);
export const isSha = x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
export const isDate = x => typeof x === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x) && Number.isFinite(Date.parse(x)) && new Date(x).toISOString() === x;

export function exactFields(obj, fields, label) {
  ensure(isObject(obj), label + ' must be an object');
  for (const key of Object.keys(obj)) ensure(fields.includes(key), `${label}: forbidden field ${key}`);
}
export async function readJSON(filename) {
  const stat = await fs.lstat(filename);
  ensure(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 1024 * 1024, 'JSON file must be regular and <= 1 MiB');
  const handle = await fs.open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try { return strictParse(await handle.readFile('utf8')); } finally { await handle.close(); }
}
export async function writeNew(filename, text, mode = 0o600) {
  const fd = await fs.open(filename, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), mode);
  try { await fd.writeFile(text, 'utf8'); await fd.sync(); } finally { await fd.close(); }
}
export async function writeJSONNew(filename, object) { await writeNew(filename, JSON.stringify(object, null, 2) + '\n'); }

export async function generateKeys(folder, id) {
  ensure(isId(id), 'Key ID invalid');
  await fs.mkdir(folder, { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ format:'pem',type:'pkcs8' }).toString();
  const publicPem = publicKey.export({ format:'pem',type:'spki' }).toString();
  await writeNew(path.join(folder, id + '.private.pem'), privatePem, 0o600);
  await writeNew(path.join(folder, id + '.public.pem'), publicPem, 0o644);
  return { id, publicKey: publicPem };
}

export function validatePolicy(p) {
  exactFields(p, ['schema','requiredApprovals','approvers','maxTtlSeconds','allowMarkers','commands'], 'policy');
  ensure(p.schema === SCHEMA.policy, 'Policy schema unsupported');
  ensure(Number.isInteger(p.requiredApprovals) && p.requiredApprovals >= 2 && p.requiredApprovals <= 10, 'requiredApprovals must be 2..10');
  ensure(Number.isInteger(p.maxTtlSeconds) && p.maxTtlSeconds >= 60 && p.maxTtlSeconds <= 86400, 'Invalid maxTtlSeconds');
  ensure(Array.isArray(p.approvers) && p.approvers.length >= p.requiredApprovals && p.approvers.length <= 20, 'Insufficient approvers');
  const ids = new Set(); const keys = new Set();
  for (const item of p.approvers) {
    exactFields(item, ['id','publicKey'], 'approver');
    ensure(isId(item.id) && !ids.has(item.id), 'Approver IDs must be distinct'); ids.add(item.id);
    ensure(typeof item.publicKey === 'string' && item.publicKey.length < 2048, 'Invalid public key');
    let key;
    try { key = (awaitlessPublicKey)(item.publicKey); } catch { throw new Error('Invalid Ed25519 public key'); }
    const der = key.export({ type:'spki',format:'der' }).toString('hex');
    ensure(!keys.has(der), 'Duplicate approver public key'); keys.add(der);
  }
  ensure(typeof p.allowMarkers === 'boolean', 'allowMarkers must be boolean');
  ensure(isObject(p.commands), 'commands must be object');
  ensure(Object.keys(p.commands).length <= 32, 'Too many commands');
  for (const [name, c] of Object.entries(p.commands)) {
    ensure(isId(name), 'Invalid command ID');
    exactFields(c, ['executable','sha256','args','timeoutMs'], 'command');
    ensure(typeof c.executable === 'string' && path.isAbsolute(c.executable), 'Executable must have absolute path');
    ensure(isSha(c.sha256), 'Executable sha256 required');
    ensure(Array.isArray(c.args) && c.args.length <= 16 && c.args.every(v => typeof v === 'string' && v.length <= 256 && !v.includes('\0')), 'Invalid command arguments');
    ensure(Number.isInteger(c.timeoutMs) && c.timeoutMs >= 100 && c.timeoutMs <= 30000, 'Command timeout outside 100..30000');
  }
  return p;
}
// Key objects are constrained to Ed25519 SPKI; no RSA or unexpected algorithms.
function awaitlessPublicKey(pem) { const k = createPublicKey(pem); ensure(k.asymmetricKeyType === 'ed25519', 'Key must be Ed25519'); return k; }

export function validateRunbook(b) {
  exactFields(b, ['schema','id','description','steps'], 'runbook');
  ensure(b.schema === SCHEMA.runbook && isId(b.id), 'Runbook schema or id invalid');
  ensure(typeof b.description === 'string' && b.description.length >= 5 && b.description.length <= 300, 'Runbook description invalid');
  ensure(Array.isArray(b.steps) && b.steps.length >= 1 && b.steps.length <= 50, 'Runbook needs 1..50 steps');
  const ids = new Set();
  for (const s of b.steps) {
    ensure(isObject(s) && isId(s.id) && !ids.has(s.id), 'Step ID invalid or repeated'); ids.add(s.id);
    if (s.type === 'assert_file') {
      exactFields(s, ['id','type','path','sha256'], 'assert_file');
      ensure(isSafeRel(s.path) && isSha(s.sha256), 'Invalid file assertion');
    } else if (s.type === 'assert_json') {
      exactFields(s, ['id','type','path','pointer','equals'], 'assert_json');
      ensure(isSafeRel(s.path), 'Invalid JSON assertion path');
      ensure(typeof s.pointer === 'string' && (s.pointer === '' || (s.pointer.startsWith('/') && s.pointer.length <= 256)), 'Invalid JSON pointer');
      ensure(['string','boolean','number'].includes(typeof s.equals) || s.equals === null, 'JSON assertion compares scalar values only');
    } else if (s.type === 'record_marker') {
      exactFields(s, ['id','type','path','text'], 'record_marker');
      ensure(isSafeRel(s.path) && typeof s.text === 'string' && Buffer.byteLength(s.text) <= 1024, 'Invalid marker');
    } else if (s.type === 'exec') {
      exactFields(s, ['id','type','command'], 'exec');
      ensure(isId(s.command), 'Invalid command id');
    } else throw new Error('Unrecognized step type: ' + s.type);
  }
  return b;
}

export function isSafeRel(s) {
  return typeof s === 'string' && s.length > 0 && s.length <= 240 && !s.includes('\\') && !s.includes('\0') && !s.startsWith('/') &&
    !/^[A-Za-z]:/.test(s) && !s.split('/').some(x => !x || x === '.' || x === '..' || x.includes(':') || /[. ]$/.test(x) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(x));
}
export function validatePlan(plan) {
  exactFields(plan, ['schema','nonce','requester','createdAt','expiresAt','policyDigest','runbook'], 'plan');
  ensure(plan.schema === SCHEMA.plan && /^[a-f0-9]{32}$/.test(plan.nonce), 'Invalid plan');
  ensure(isId(plan.requester) && isDate(plan.createdAt) && isDate(plan.expiresAt) && isSha(plan.policyDigest), 'Invalid plan identity or dates');
  validateRunbook(plan.runbook);
  return plan;
}
export function preparePlan(runbook, policy, requester, ttlSeconds, now = new Date()) {
  validateRunbook(runbook); validatePolicy(policy);
  ensure(isId(requester) && !policy.approvers.some(x => x.id === requester), 'Requester must differ from all approvers');
  ensure(Number.isInteger(ttlSeconds) && ttlSeconds >= 60 && ttlSeconds <= policy.maxTtlSeconds, 'Plan TTL exceeds policy');
  const plan = {schema:SCHEMA.plan, nonce:randomBytes(16).toString('hex'), requester,
    createdAt:now.toISOString(), expiresAt:new Date(now.getTime()+ttlSeconds*1000).toISOString(),
    policyDigest:digest(policy), runbook};
  return validatePlan(plan);
}
export function createApproval(plan, approver, privatePem, at = new Date()) {
  validatePlan(plan); ensure(isId(approver), 'Invalid approver ID');
  const body = {schema:SCHEMA.approval, approver, planDigest:digest(plan), issuedAt:at.toISOString(), decision:'approve'};
  const signature = sign(null, Buffer.from('quorumops.approval.v1\n' + canonical(body)), privatePem).toString('base64');
  return {...body, signature};
}
export function verifyApprovals(plan, policy, approvals, now = new Date()) {
  validatePlan(plan); validatePolicy(policy);
  ensure(digest(policy) === plan.policyDigest, 'Policy changed after plan creation');
  const time = now.getTime(), start = Date.parse(plan.createdAt), end = Date.parse(plan.expiresAt);
  ensure(time >= start && time <= end && end - start <= policy.maxTtlSeconds * 1000, 'Plan expired, future-dated or exceeds policy TTL');
  ensure(Array.isArray(approvals), 'Approvals must be list');
  const seen = new Set();
  for (const a of approvals) {
    exactFields(a, ['schema','approver','planDigest','issuedAt','decision','signature'], 'approval');
    ensure(a.schema === SCHEMA.approval && a.decision === 'approve' && isId(a.approver) && isDate(a.issuedAt), 'Invalid approval schema');
    ensure(a.planDigest === digest(plan), 'Approval references different plan');
    ensure(a.approver !== plan.requester && !seen.has(a.approver), 'Self-approval or duplicate approval');
    const issued = Date.parse(a.issuedAt);
    ensure(issued >= start && issued <= end && issued <= time + 60000, 'Approval timestamp outside plan window');
    const trusted = policy.approvers.find(x => x.id === a.approver);
    ensure(Boolean(trusted), 'Untrusted approver');
    ensure(typeof a.signature === 'string' && /^[a-zA-Z0-9+/]+={0,2}$/.test(a.signature) && a.signature.length === 88, 'Signature base64 malformed');
    const bytes = Buffer.from(a.signature, 'base64');
    ensure(bytes.length === 64 && bytes.toString('base64') === a.signature, 'Noncanonical signature');
    const {signature, ...payload} = a;
    ensure(verify(null, Buffer.from('quorumops.approval.v1\n' + canonical(payload)), trusted.publicKey, bytes), 'Signature invalid');
    seen.add(a.approver);
  }
  ensure(seen.size >= policy.requiredApprovals, `Quorum not reached: ${seen.size}/${policy.requiredApprovals}`);
  return {ok:true, planDigest:digest(plan), validApprovers:[...seen].sort(), threshold:policy.requiredApprovals, expiresAt:plan.expiresAt};
}

/** Confines resolution to an operator-controlled workspace; rejects each symlinked ancestor. */
export async function safeWorkspaceFile(root, rel, mayNotExist = false) {
  ensure(isSafeRel(rel), 'Unsafe path');
  const base = path.resolve(root);
  const baseStat = await fs.lstat(base);
  ensure(baseStat.isDirectory() && !baseStat.isSymbolicLink(), 'Workspace root must be a non-symlink directory');
  let current = base;
  const parts = rel.split('/');
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    const isLast = i === parts.length - 1;
    try {
      const stat = await fs.lstat(current);
      ensure(!stat.isSymbolicLink(), 'Symlink forbidden in workspace path');
      if (!isLast) ensure(stat.isDirectory(), 'Ancestor must be a directory');
      else ensure(stat.isFile(), 'Expected a regular file');
      if (isLast && mayNotExist) throw new Error('Marker already exists');
    } catch (e) {
      if (e?.code === 'ENOENT' && isLast && mayNotExist) return current;
      throw e;
    }
  }
  return current;
}
export async function hashFile(filename, limit = 16*1024*1024) {
  const stat = await fs.lstat(filename);
  ensure(stat.isFile() && !stat.isSymbolicLink() && stat.size <= limit, 'File not regular or exceeds size limit');
  const handle = await fs.open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const h = createHash('sha256'); let total = 0;
    for await (const block of handle.createReadStream({autoClose:false,highWaterMark:65536})) {
      total += block.length; ensure(total <= limit, 'File exceeds limit while reading'); h.update(block);
    }
    return h.digest('hex');
  } finally { await handle.close(); }
}
