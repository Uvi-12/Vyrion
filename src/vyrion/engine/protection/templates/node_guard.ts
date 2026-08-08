// Vyrion execution guard (TypeScript). Installed by `vyrion apply` next to the
// protected TS action. Holds public verification keys only and fails closed.
// Verifies the Ed25519 signature over the RFC 8785 canonicalization of the seal
// (everything except `signature`), then checks the execution bindings.
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

function fmtNumber(n: number): string {
  if (!isFinite(n)) throw new Error('non-finite number not permitted in JCS');
  if (Number.isInteger(n)) return String(n);
  return String(n);
}
function esc(s: string): string {
  let out = '"';
  for (const ch of s) {
    const o = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (o === 0x08) out += '\\b';
    else if (o === 0x09) out += '\\t';
    else if (o === 0x0a) out += '\\n';
    else if (o === 0x0c) out += '\\f';
    else if (o === 0x0d) out += '\\r';
    else if (o < 0x20) out += '\\u' + o.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}
function canon(v: Json): string {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return fmtNumber(v);
  if (typeof v === 'string') return esc(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  const keys = Object.keys(v).sort();  // UTF-16 code-unit order (== code point for BMP)
  return '{' + keys.map((k) => esc(k) + ':' + canon((v as any)[k])).join(',') + '}';
}
function canonicalize(v: Json): Buffer { return Buffer.from(canon(v), 'utf-8'); }
function sha256Hex(b: Buffer): string { return crypto.createHash('sha256').update(b).digest('hex'); }
function argumentsCommitment(args: Json): string { return 'sha256:' + sha256Hex(canonicalize(args)); }

function findVyrionDir(start: string): string | null {
  let dir = path.resolve(start);
  for (;;) {
    if (fs.existsSync(path.join(dir, '.vyrion', 'manifest.json'))) return path.join(dir, '.vyrion');
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

const _seen = new Set<string>();   // in-memory replay guard (Redis/DB in production)

export interface Ctx { seal: any; args: Json; run_id: string; checkpoint_id: string; }

export function authorize(ctx: Ctx, root?: string): boolean {
  try {
    const vdir = findVyrionDir(root || __dirname) || findVyrionDir(process.cwd());
    if (!vdir) return false;
    const manifest = JSON.parse(fs.readFileSync(path.join(vdir, 'manifest.json'), 'utf-8'));
    const seal = typeof ctx.seal === 'string' ? JSON.parse(ctx.seal) : ctx.seal;
    if (!seal) return false;
    // 1) signature over canonical(seal minus signature)
    const { signature, ...signing } = seal;
    const payload = canonicalize(signing as Json);
    const keydir = path.join(vdir, 'public-keys');
    let verified = false;
    for (const f of fs.existsSync(keydir) ? fs.readdirSync(keydir) : []) {
      if (!f.endsWith('.pem')) continue;
      const pub = crypto.createPublicKey(fs.readFileSync(path.join(keydir, f)));
      try {
        if (crypto.verify(null, payload, pub, Buffer.from(signature, 'hex'))) { verified = true; break; }
      } catch { /* try next key */ }
    }
    if (!verified) return false;
    // 2) bindings
    if (seal.decision !== 'approve') return false;
    if (seal.action?.id !== manifest.action_id) return false;
    if (seal.action?.arguments_commitment !== argumentsCommitment(ctx.args)) return false;
    if ((seal.workflow?.run_id || '') !== (ctx.run_id || '')) return false;
    if ((seal.workflow?.checkpoint_id || '') !== (ctx.checkpoint_id || '')) return false;
    if (manifest.approval_point && seal.approval_point_id !== manifest.approval_point) return false;
    if (seal.expires_at && Date.now() / 1000 > seal.expires_at) return false;
    // 3) replay: consume the nonce once
    if (seal.nonce) { if (_seen.has(seal.nonce)) return false; _seen.add(seal.nonce); }
    return true;
  } catch {
    return false;   // fail closed on any error
  }
}
