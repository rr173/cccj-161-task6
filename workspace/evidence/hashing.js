// 证据归档模块的确定性编码原语：
//  - canonicalJSON：键名字典序、无多余空白（null 原型对象，杜绝 __proto__ 注入）；
//  - 哈希链：genesis 锚定 packageId，记录 hash 覆盖除 hash 外全部字段（含 prevHash）；
//  - fingerprint：只覆盖“语义字段”，同内容由不同网关重传指纹一致（用于去重/冲突判定）；
//  - redact：递归脱敏凭据，任何导出/页面只输出脱敏后的证据。
import { createHash } from 'node:crypto';

export const SCHEMA = 'offline-evidence/1';
export const REPORT_SCHEMA = 'evidence-report/1';

export const KINDS = ['manifest', 'fence', 'segment', 'checkpoint'];
export const OUTCOMES = ['EXECUTED', 'SKIPPED', 'FAILED'];
export const FENCE_ACTIONS = ['CREATED', 'REVISED', 'CLOSED'];

// 键按字典序稳定排序的规范化 JSON（用于哈希/签名），任意实现可独立复算。
export function canonicalJSON(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(v) {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v && typeof v === 'object') {
    // null 原型：避免 {"__proto__": ...} 在赋值时触发原型 setter。
    const out = Object.create(null);
    for (const k of Object.keys(v).sort()) out[k] = sortValue(v[k]);
    return out;
  }
  return v;
}

export function sha256Hex(s) {
  return createHash('sha256').update(s).digest('hex');
}

export function sha256Buf(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

// 每个 packageId 独立的链起源：同一记录串换到别的包即断链。
export function genesisHash(packageId) {
  return sha256Hex(`offline-evidence-genesis-v1\n${packageId}`);
}

// 记录哈希：覆盖除 hash 外的全部字段（含 prevHash、ts 与业务字段）。
export function recordHash(rec) {
  const clone = { ...rec };
  delete clone.hash;
  return sha256Hex(canonicalJSON(clone));
}

function normEntry(e) {
  return {
    seq: Number(e.seq),
    deviceId: String(e.deviceId),
    outcome: String(e.outcome),
    note: e.note == null ? null : String(e.note),
  };
}

// 语义指纹：只挑业务字段（不含 ts/prevHash/hash/网关身份），
// 同一语义内容由不同网关、不同时刻重传，指纹一致 → 判定为重复证据而非冲突。
export function fingerprintRecord(rec) {
  let body;
  switch (rec.kind) {
    case 'manifest':
      body = { kind: 'manifest', manifestHash: rec.manifestHash, manifest: rec.manifest };
      break;
    case 'fence':
      body = {
        kind: 'fence', fenceId: rec.fenceId, version: rec.version,
        action: rec.action, prevVersion: rec.prevVersion, detail: rec.detail,
      };
      break;
    case 'segment':
      body = {
        kind: 'segment', fenceId: rec.fenceId, fenceVersion: rec.fenceVersion,
        segSeq: rec.segSeq,
        entries: [...rec.entries].map(normEntry).sort((a, b) => {
          for (const k of ['seq', 'deviceId', 'outcome', 'note']) {
            const av = a[k]; const bv = b[k];
            if (av < bv) return -1;
            if (av > bv) return 1;
          }
          return 0;
        }),
      };
      break;
    case 'checkpoint':
      body = {
        kind: 'checkpoint', fenceId: rec.fenceId, fenceVersion: rec.fenceVersion,
        lastSeq: rec.lastSeq, counts: rec.counts,
      };
      break;
    default:
      throw new Error(`未知记录类型: ${rec.kind}`);
  }
  return sha256Hex(canonicalJSON(body));
}

// 归档槽位：同围栏同版本的围栏变更、同围栏同版本同分段号的回执各占一槽。
// manifest 全包唯一一槽；checkpoint 不占冲突槽（按 max(lastSeq) 合并，天然不倒退）。
export function slotKey(rec) {
  switch (rec.kind) {
    case 'manifest': return 'manifest';
    case 'fence': return `fence:${rec.fenceId}:v${rec.version}`;
    case 'segment': return `segment:${rec.fenceId}:v${rec.fenceVersion}:seg${rec.segSeq}`;
    case 'checkpoint': return `checkpoint:${rec.fenceId}:v${rec.fenceVersion}`;
    default: throw new Error(`未知记录类型: ${rec.kind}`);
}
}

// ---------- 脱敏 ----------

const SECRET_KEY_RE = /(^|[-_])(secret|password|passwd|pwd|token|credential|credentials?|privatekey|private_key|apikey|api_key|hmac|uploadsecret)([-_]|$)/i;
const PEM_PRIVATE_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;

function isSensitiveKey(key) {
  return SECRET_KEY_RE.test(key);
}

// 递归脱敏。literals 为进程内已知密钥原文（如 upload secret），
// 即使它出现在非约定字段名（备注/自由文本）里也整体打码。
export function redact(value, literals = []) {
  const seen = new WeakSet();
  const walk = (v, parentKey = '') => {
    if (typeof v === 'string') return scrubString(v, parentKey, literals);
    if (Array.isArray(v)) return v.map((x) => walk(x, parentKey));
    if (v && typeof v === 'object') {
      if (seen.has(v)) return null;
      seen.add(v);
      const out = {};
      for (const [k, val] of Object.entries(v)) {
        // 敏感字段名：整个值直接打码（不递归暴露其内部结构）。
        if (isSensitiveKey(k)) out[k] = '***REDACTED***';
        else out[k] = walk(val, k);
      }
      return out;
    }
    return v;
  };
  return walk(value);
}

function scrubString(s, key, literals) {
  if (isSensitiveKey(key)) return '***REDACTED***';
  if (PEM_PRIVATE_RE.test(s)) return '***REDACTED-PRIVATE-KEY***';
  let out = s;
  for (const lit of literals) {
    if (lit && typeof lit === 'string' && lit.length >= 8 && out.includes(lit)) {
      out = out.split(lit).join('***REDACTED***');
    }
  }
  return out;
}

// 供日志使用：只允许安全字段输出；并对任何字符串做字面量打码。
export function safeLog(fields, literals = []) {
  const ALLOWED = new Set([
    'level', 'msg', 'packageId', 'gatewayId', 'keyId', 'importId', 'envelopeHash',
    'recordHash', 'slot', 'kind', 'code', 'reason', 'accepted', 'duplicate',
    'conflict', 'records', 'envelopes', 'tipSeq', 'port', 'file', 'fenceId',
    'version', 'segSeq', 'digest', 'at', 'quarantine', 'count',
  ]);
  const out = {};
  for (const [k, v] of Object.entries(fields || {})) {
    if (!ALLOWED.has(k)) continue;
    out[k] = typeof v === 'string' ? scrubString(v, k, literals) : v;
  }
  return out;
}
