/** Bounded JSON decoder that rejects duplicate object keys and deeply nested inputs. */
export function strictParse(source, maxDepth = 32) {
  if (typeof source !== 'string' || Buffer.byteLength(source, 'utf8') > 1024 * 1024) {
    throw new Error('JSON input exceeds 1 MiB');
  }
  let i = 0;
  const ws = () => { while (/\s/.test(source[i] ?? '') && i < source.length) i++; };
  function string() {
    const start = i++;
    let escaped = false;
    for (; i < source.length; i++) {
      const ch = source[i];
      if (!escaped && ch === '"') { i++; return JSON.parse(source.slice(start, i)); }
      if (!escaped && ch === '\\') escaped = true;
      else escaped = false;
    }
    throw new Error('Unterminated JSON string');
  }
  function value(depth) {
    if (depth > maxDepth) throw new Error('JSON nesting exceeds limit');
    ws(); const c = source[i];
    if (c === '"') return string();
    if (c === '{') {
      i++; ws(); const object = Object.create(null); const seen = new Set();
      if (source[i] === '}') { i++; return object; }
      while (true) {
        ws(); if (source[i] !== '"') throw new Error('Expected JSON object key');
        const key = string();
        if (seen.has(key)) throw new Error('Duplicate JSON object key: ' + key);
        seen.add(key); ws(); if (source[i++] !== ':') throw new Error('Expected :');
        object[key] = value(depth + 1); ws(); const next = source[i++];
        if (next === '}') return object;
        if (next !== ',') throw new Error('Expected , or }');
      }
    }
    if (c === '[') {
      i++; ws(); const arr = [];
      if (source[i] === ']') { i++; return arr; }
      while (true) {
        if (arr.length > 100000) throw new Error('Array exceeds limit');
        arr.push(value(depth + 1)); ws(); const next = source[i++];
        if (next === ']') return arr;
        if (next !== ',') throw new Error('Expected , or ]');
      }
    }
    const match = /^(true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(source.slice(i));
    if (!match) throw new Error('Invalid JSON value');
    i += match[0].length;
    return JSON.parse(match[0]);
  }
  const result = value(0); ws();
  if (i !== source.length) throw new Error('Unexpected trailing JSON content');
  return result;
}

export function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Nonfinite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',')}}`;
  }
  throw new Error('Unsupported value in canonical JSON');
}
