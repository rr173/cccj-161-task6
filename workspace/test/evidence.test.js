// 证据归档模块单测：规范化/指纹幂等、脱敏、哈希链（残尾恢复/篡改隔离）、
// 归档裁决（重复/冲突/围栏连续性/检查点不倒退/重启重放）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  canonicalJSON, fingerprintRecord, redact,
  recordHash,
} from '../evidence/hashing.js';
import { ChainLog, chainGenesis } from '../evidence/chains.js';
import { EvidenceArchive, ArchiveManager } from '../evidence/archive.js';
import { GatewayRegistry, signEnvelope } from '../evidence/crypto.js';
import { buildEnvelope, R, manifestHashOf, generateGatewayKeyPair, envelopeHashOf } from '../evidence/pack.js';
import { buildReport } from '../evidence/report.js';

function tmp() {
  return mkdtempSync(join(tmpdir(), 'ev-test-'));
}

test('canonicalJSON 键序确定且不受输入键序影响', () => {
  const a = canonicalJSON({ b: 1, a: { z: 2, y: 3 }, c: [3, 1, 2] });
  const b = canonicalJSON({ c: [3, 1, 2], a: { y: 3, z: 2 }, b: 1 });
  assert.equal(a, b);
  assert.ok(a.startsWith('{"a":{"y":3,"z":2}'));
});

test('canonicalJSON 对 __proto__ 键不污染原型', () => {
  const s = canonicalJSON(JSON.parse('{"__proto__":{"polluted":true},"x":1}'));
  assert.equal({}.polluted, undefined);
  assert.ok(s.includes('__proto__'));
});

test('指纹只依赖语义字段：键序变化与来源网关变化不影响指纹', () => {
  const r1 = {
    kind: 'segment', ts: '2026-10-01T08:00:00Z', fenceId: 'f', fenceVersion: 1, segSeq: 1,
    entries: [{ seq: 1, deviceId: 'D-2', outcome: 'FAILED', note: null }, { seq: 0, deviceId: 'D-1', outcome: 'EXECUTED', note: 'n' }],
  };
  const r2 = {
    kind: 'segment', ts: '2026-10-02T09:00:00Z', fenceId: 'f', fenceVersion: 1, segSeq: 1,
    entries: [{ seq: 0, deviceId: 'D-1', outcome: 'EXECUTED', note: 'n' }, { seq: 1, deviceId: 'D-2', outcome: 'FAILED', note: null }],
  };
  assert.equal(fingerprintRecord(r1), fingerprintRecord(r2));
  const r3 = { ...r2, entries: [{ ...r2.entries[0], outcome: 'SKIPPED' }, r2.entries[1]] };
  assert.notEqual(fingerprintRecord(r1), fingerprintRecord(r3));
});

test('redact：敏感键名、私钥 PEM、密钥字面量均打码', () => {
  const secret = 'supersecretvalue-0123456789abcdef';
  const out = redact({
    uploadSecret: secret,
    nested: { password: 'p', ok: 'x' },
    note: `detail includes ${secret} here`,
    pem: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----',
    list: [{ apiKey: 'k' }, { v: secret }],
  }, [secret]);
  const s = JSON.stringify(out);
  assert.ok(!s.includes(secret));
  assert.equal(out.uploadSecret, '***REDACTED***');
  assert.equal(out.nested.password, '***REDACTED***');
  assert.equal(out.nested.ok, 'x');
  assert.ok(out.note.includes('***REDACTED***'));
  assert.equal(out.pem, '***REDACTED-PRIVATE-KEY***');
  assert.equal(out.list[0].apiKey, '***REDACTED***');
});

test('ChainLog：append/重放、genesis 隔离、篡改隔离', () => {
  const dir = tmp();
  try {
    const file = join(dir, 'ledger.jsonl');
    const c1 = new ChainLog(file, { chainName: 'ledger', packageId: 'P' });
    c1.append({ kind: 'manifest', x: 1 });
    c1.append({ kind: 'fence', version: 1 });
    assert.deepEqual(c1.verify().ok, true);

    const c2 = new ChainLog(file, { chainName: 'ledger', packageId: 'P' });
    const loaded2 = c2.load();
    assert.deepEqual(loaded2.ok, true);
    assert.equal(c2.records.length, 2);
    assert.equal(c2.tipHash, c1.tipHash);

    // 不同 packageId genesis 不同 → 第一条即断链
    const c3 = new ChainLog(file, { chainName: 'ledger', packageId: 'OTHER' });
    const v3 = c3.load();
    assert.equal(v3.ok, false);
    assert.equal(c3.writable, false);
    assert.throws(() => c3.append({ kind: 'x' }), { code: 'CHAIN_QUARANTINED' });

    // 不同链名 genesis 也不同
    const c4 = new ChainLog(file, { chainName: 'quarantine', packageId: 'P' });
    assert.equal(c4.load().ok, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('ChainLog：中途篡改记录内容 → 只读隔离，文件原样保留', () => {
  const dir = tmp();
  try {
    const file = join(dir, 'ledger.jsonl');
    const c1 = new ChainLog(file, { chainName: 'ledger', packageId: 'P' });
    c1.append({ kind: 'manifest', v: 1 });
    c1.append({ kind: 'fence', v: 2 });
    const before = readFileSync(file, 'utf8');
    const tampered = before.replace('"v":2', '"v":9');
    writeFileSync(file, tampered);
    const c2 = new ChainLog(file, { chainName: 'ledger', packageId: 'P' });
    const loadRes = c2.load();
    assert.equal(loadRes.ok, false);
    assert.match(loadRes.recovery.reason, /哈希/);
    assert.equal(readFileSync(file, 'utf8'), tampered); // 原样保留
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('ChainLog：末尾断电残尾 → 归档续链，之后可继续追加', () => {
  const dir = tmp();
  try {
    const file = join(dir, 'ledger.jsonl');
    const c1 = new ChainLog(file, { chainName: 'ledger', packageId: 'P' });
    c1.append({ kind: 'manifest', v: 1 });
    const goodLen = readFileSync(file).length;
    appendFileSync(file, '{"seq":2,"kind":"fence",'); // 无换行残尾
    const c2 = new ChainLog(file, { chainName: 'ledger', packageId: 'P' });
    const v = c2.load();
    assert.equal(v.ok, true);
    assert.equal(v.length, 1);
    assert.equal(v.recovery?.kind, 'torn-tail-recovered');
    assert.equal(readFileSync(file).length, goodLen); // 残尾已截断
    c2.append({ kind: 'fence', v: 2 });
    assert.equal(c2.verify().ok, true);
    assert.equal(c2.records.length, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('ChainLog：残尾后还有内容 → 损坏隔离而非残尾恢复', () => {
  const dir = tmp();
  try {
    const file = join(dir, 'ledger.jsonl');
    const c1 = new ChainLog(file, { chainName: 'ledger', packageId: 'P' });
    c1.append({ kind: 'manifest', v: 1 });
    appendFileSync(file, 'not-json-line\n{"x":1}\n');
    const c2 = new ChainLog(file, { chainName: 'ledger', packageId: 'P' });
    const v = c2.load();
    assert.equal(v.ok, false);
    assert.equal(v.recovery.kind, 'corrupt');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('recordHash 覆盖 prevHash：改链即检出', () => {
  const r = { seq: 1, kind: 'x', prevHash: chainGenesis('ledger', 'P') };
  const h = recordHash(r);
  assert.notEqual(recordHash({ ...r, prevHash: '0'.repeat(64) }), h);
});

// ---------- 归档裁决 ----------

function setup() {
  const dir = tmp();
  const gw = generateGatewayKeyPair();
  const registry = new GatewayRegistry(join(dir, 'gateways.json'));
  registry.register({ gatewayId: 'gw-A', keyId: 'k1', publicKeyPem: gw.publicKeyPem, createdAt: '2026-10-01T08:00:00Z' });
  const gw2 = generateGatewayKeyPair();
  registry.register({ gatewayId: 'gw-B', keyId: 'k1', publicKeyPem: gw2.publicKeyPem, createdAt: '2026-10-01T08:00:00Z' });
  const manager = new ArchiveManager(dir);
  return {
    dir, gw, gw2, registry, manager,
    env(packageId, gateway, keyId, priv, records) {
      return buildEnvelope({ packageId, gatewayId: gateway, keyId, records, privateKeyPem: priv });
    },
    cleanup() { rmSync(dir, { recursive: true, force: true }); },
  };
}

const T = '2026-10-01T08:00:00Z';
const MANIFEST = { entries: [{ seq: 0, deviceId: 'D-1' }, { seq: 1, deviceId: 'D-2' }], issuedAt: T, validUntil: null };

test('有效信封导入并生成稳定 digest', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    const env = s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
      R.segment(T, 'f1', 1, 1, [{ seq: 0, deviceId: 'D-1', outcome: 'EXECUTED' }]),
    ]);
    const out = a.importEnvelope(env, { registry: s.registry, nowIso: T });
    assert.equal(out.result, 'ACCEPTED');
    assert.equal(out.disposition.recordsAccepted, 3);
    const r = buildReport(a);
    assert.match(r.reportDigest, /^[0-9a-f]{64}$/);
    assert.equal(r.currentFence.version, 1);
  } finally { s.cleanup(); }
});

test('重复导入返回原结果且不追加链', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    const env = s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
    ]);
    const o1 = a.importEnvelope(env, { registry: s.registry, nowIso: T });
    const tip1 = a.ledger.seq;
    const o2 = a.importEnvelope(env, { registry: s.registry, nowIso: '2026-10-02T00:00:00Z' });
    assert.equal(o2.duplicate, true);
    assert.equal(o2.importId, o1.importId);
    assert.equal(o2.firstImportedAt, T);
    assert.equal(a.ledger.seq, tip1); // 不追加
    assert.equal(buildReport(a).reportDigest, buildReport(a).reportDigest);
  } finally { s.cleanup(); }
});

test('同分段不同内容冲突隔离，已存证据不覆盖', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
      R.segment(T, 'f1', 1, 1, [{ seq: 0, deviceId: 'D-1', outcome: 'EXECUTED' }]),
    ]), { registry: s.registry, nowIso: T });
    const conflict = s.env('PKG1', 'gw-B', 'k1', s.gw2.privateKeyPem, [
      R.segment(T, 'f1', 1, 1, [{ seq: 0, deviceId: 'D-1', outcome: 'FAILED' }]),
    ]);
    const o = a.importEnvelope(conflict, { registry: s.registry, nowIso: T });
    assert.equal(o.result, 'CONFLICTS');
    assert.equal(o.disposition.conflicts[0].reason, 'SEGMENT_CONTENT_CONFLICT');
    assert.equal(a.quarantine.records.length, 1);
    // ledger 中仍只有原 EXECUTED
    const segs = a.ledger.records.filter((r) => r.kind === 'segment');
    assert.equal(segs.length, 1);
    assert.equal(segs[0].entries[0].outcome, 'EXECUTED');
    // 冲突链自身哈希链完好
    assert.equal(a.quarantine.verify().ok, true);
  } finally { s.cleanup(); }
});

test('语义相同的记录（来源不同）判为重复而非冲突', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
      R.segment(T, 'f1', 1, 1, [{ seq: 0, deviceId: 'D-1', outcome: 'EXECUTED', note: null }]),
    ]), { registry: s.registry, nowIso: T });
    // 另一网关提交同槽位同语义分段（entry 顺序不同）
    const o = a.importEnvelope(s.env('PKG1', 'gw-B', 'k1', s.gw2.privateKeyPem, [
      R.segment('2026-10-03T00:00:00Z', 'f1', 1, 1, [{ note: null, outcome: 'EXECUTED', deviceId: 'D-1', seq: 0 }]),
    ]), { registry: s.registry, nowIso: T });
    assert.equal(o.result, 'ACCEPTED');
    assert.equal(o.disposition.recordsDuplicate, 1);
    assert.equal(o.disposition.recordsConflicted, 0);
  } finally { s.cleanup(); }
});

test('围栏版本必须连续；引用不存在围栏被拒', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
    ]), { registry: s.registry, nowIso: T });
    assert.throws(() => a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.fence(T, 'f3', 3, 'CREATED', 2),
    ]), { registry: s.registry, nowIso: T }), { code: 'FENCE_VERSION_GAP' });
    assert.throws(() => a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.segment(T, 'f9', 9, 1, [{ seq: 0, deviceId: 'D-1', outcome: 'EXECUTED' }]),
    ]), { registry: s.registry, nowIso: T }), { code: 'FENCE_UNKNOWN' });
  } finally { s.cleanup(); }
});

test('CLOSED 是生命周期推进：不与 CREATED 冲突，重复 CLOSED 幂等', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
    ]), { registry: s.registry, nowIso: T });
    const o1 = a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.fence(T, 'f1', 1, 'CLOSED', 0, 'done'),
      R.fence(T, 'f2', 2, 'CREATED', 1),
    ]), { registry: s.registry, nowIso: T });
    assert.equal(o1.result, 'ACCEPTED');
    assert.equal(o1.disposition.recordsAccepted, 2);
    const r1 = buildReport(a);
    assert.equal(r1.fences.find((f) => f.version === 1).closedAt, T);
    // 再次 CLOSED v1 → 幂等
    const o2 = a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.fence(T, 'f1', 1, 'CLOSED', 0, 'done'),
    ]), { registry: s.registry, nowIso: T });
    assert.equal(o2.disposition.recordsDuplicate, 1);
  } finally { s.cleanup(); }
});

test('检查点跨围栏不倒退：低水位隔离，当前水位保留', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
      R.checkpoint(T, 'f1', 1, 5, { EXECUTED: 5, SKIPPED: 0, FAILED: 0 }),
      R.fence(T, 'f2', 2, 'CREATED', 1),
    ]), { registry: s.registry, nowIso: T });
    const o = a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.checkpoint(T, 'f2', 2, 2, { EXECUTED: 2, SKIPPED: 0, FAILED: 0 }),
    ]), { registry: s.registry, nowIso: T });
    assert.equal(o.disposition.conflicts[0].reason, 'CHECKPOINT_REGRESSED');
    const r = buildReport(a);
    assert.equal(r.currentProgress.lastSeq, 5);
  } finally { s.cleanup(); }
});

test('重启重放：digest、冲突列表、链尖全部一致', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
      R.segment(T, 'f1', 1, 1, [{ seq: 0, deviceId: 'D-1', outcome: 'EXECUTED' }]),
      R.checkpoint(T, 'f1', 1, 0, { EXECUTED: 1, SKIPPED: 0, FAILED: 0 }),
    ]), { registry: s.registry, nowIso: T });
    a.importEnvelope(s.env('PKG1', 'gw-B', 'k1', s.gw2.privateKeyPem, [
      R.segment(T, 'f1', 1, 1, [{ seq: 0, deviceId: 'D-1', outcome: 'FAILED' }]),
    ]), { registry: s.registry, nowIso: T });
    const before = buildReport(a);
    const tips = [a.ledger.tipHash, a.quarantine.tipHash, a.audit.tipHash];

    // 全新进程等价：新建 manager 从磁盘重放
    const manager2 = new ArchiveManager(s.dir);
    const a2 = manager2.open('PKG1');
    const after = buildReport(a2);
    assert.equal(after.reportDigest, before.reportDigest);
    assert.deepEqual(after.conflicts.map((c) => c.slot + c.reason),
      before.conflicts.map((c) => c.slot + c.reason));
    assert.deepEqual([a2.ledger.tipHash, a2.quarantine.tipHash, a2.audit.tipHash], tips);
  } finally { s.cleanup(); }
});

test('不同 packageId 独立链与独立摘要', () => {
  const s = setup();
  try {
    for (const id of ['P-A', 'P-B']) {
      const a = s.manager.open(id);
      a.importEnvelope(s.env(id, 'gw-A', 'k1', s.gw.privateKeyPem, [
        R.manifest(T, { entries: [{ seq: 0, deviceId: 'X' }], issuedAt: T }),
        R.fence(T, 'f', 1, 'CREATED'),
      ]), { registry: s.registry, nowIso: T });
    }
    const ids = s.manager.list();
    assert.deepEqual(ids.sort(), ['P-A', 'P-B']);
    const dA = buildReport(s.manager.open('P-A')).reportDigest;
    const dB = buildReport(s.manager.open('P-B')).reportDigest;
    assert.notEqual(dA, dB);
  } finally { s.cleanup(); }
});

test('非法 packageId 被拒（防路径穿越）', () => {
  const s = setup();
  try {
    assert.throws(() => s.manager.open('../escape'), { code: 'PACKAGE_ID_INVALID' });
    assert.throws(() => s.manager.open('a/b'), { code: 'PACKAGE_ID_INVALID' });
  } finally { s.cleanup(); }
});

test('清单内容不同 → MANIFEST_CONTENT_CONFLICT 拒绝（不覆盖）', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
    ]), { registry: s.registry, nowIso: T });
    const m2 = { ...MANIFEST, entries: [{ seq: 0, deviceId: 'OTHER' }, { seq: 1, deviceId: 'D-2' }] };
    assert.throws(() => a.importEnvelope(s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, m2, manifestHashOf(m2)),
    ]), { registry: s.registry, nowIso: T }), { code: 'MANIFEST_CONTENT_CONFLICT' });
  } finally { s.cleanup(); }
});

test('未知网关/错签名/坏哈希分别拒绝', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    const env = s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
    ]);
    // 改 gatewayId（同时也改 keyId）后重签 → 目标网关不存在（hash 自洽、走到注册表校验）
    const envUnknown = s.env('PKG1', 'gw-X', 'kX', s.gw.privateKeyPem, env.records);
    assert.throws(() => a.importEnvelope(envUnknown, { registry: s.registry, nowIso: T }), { code: 'GATEWAY_UNKNOWN' });
    // 网关注册但声称的 keyId 不符
    const envBadKey = s.env('PKG1', 'gw-A', 'wrong-key-id', s.gw.privateKeyPem, env.records);
    assert.throws(() => a.importEnvelope(envBadKey, { registry: s.registry, nowIso: T }), { code: 'SIGNATURE_KEY_MISMATCH' });
    // 仅改 signature 字段（签名本身不在 envelopeHash 覆盖内）→ SIGNATURE_INVALID
    assert.throws(() => a.importEnvelope({ ...env, signature: '0'.repeat(128) }, { registry: s.registry, nowIso: T }), { code: 'SIGNATURE_INVALID' });
    // hash 自洽但用他人私钥签名 → SIGNATURE_INVALID
    const resignWrongKey = s.env('PKG1', 'gw-A', 'k1', s.gw2.privateKeyPem, env.records);
    assert.throws(() => a.importEnvelope(resignWrongKey, { registry: s.registry, nowIso: T }), { code: 'SIGNATURE_INVALID' });
    // 内容被改、hash 未重算 → ENVELOPE_HASH_MISMATCH
    const mut = JSON.parse(JSON.stringify(env));
    mut.records[0].manifest.issuedAt = '2099-01-01T00:00:00Z';
    assert.throws(() => a.importEnvelope(mut, { registry: s.registry, nowIso: T }), { code: 'ENVELOPE_HASH_MISMATCH' });
  } finally { s.cleanup(); }
});

test('多余字段（夹带）被结构校验拒绝', () => {
  const s = setup();
  try {
    const a = s.manager.open('PKG1');
    const env = s.env('PKG1', 'gw-A', 'k1', s.gw.privateKeyPem, [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      R.fence(T, 'f1', 1, 'CREATED'),
    ]);
    // 夹带未签名字段（绕过制包规范化直接构造信封）：重算 hash 并合法签名后，
    // 仍应被归档端的字段白名单拒绝。
    const rawRecords = [
      R.manifest(T, MANIFEST, manifestHashOf(MANIFEST)),
      { ...R.fence(T, 'f1', 1, 'CREATED'), extra: 'injected' },
    ];
    const injected = {
      schema: 'offline-evidence/1', packageId: 'PKG1', gatewayId: 'gw-A', keyId: 'k1', records: rawRecords,
    };
    injected.envelopeHash = envelopeHashOf(injected);
    injected.signature = signEnvelope(s.gw.privateKeyPem, injected.envelopeHash);
    assert.throws(() => a.importEnvelope(injected, { registry: s.registry, nowIso: T }), { code: 'RECORD_MALFORMED' });
  } finally { s.cleanup(); }
});
