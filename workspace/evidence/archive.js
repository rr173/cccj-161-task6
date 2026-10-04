// 证据归档内核：校验带签名的证据信封 → 哈希链/签名/业务规则 → 按 packageId 归档。
//
// 每个包目录下三条独立哈希链（重启重放，摘要不变）：
//   ledger.jsonl      已接受证据（manifest / fence / segment / checkpoint，只增，永不覆盖）
//   quarantine.jsonl  冲突隔离记录（原证据原样留存 + 已存证据指纹，互不覆盖）
//   audit.jsonl       导入裁决（ACCEPTED / DUPLICATE / CONFLICTS / REJECTED）
//
// 关键规则：
//  - 槽位（slot）：manifest 全包一槽；fence 按全局版本一槽；segment 按 fence 版本+分段号一槽；
//    checkpoint 按 fence 版本一槽。槽位已有【同指纹】→ 幂等跳过；【异指纹】→ 冲突隔离，不覆盖。
//  - 围栏版本全局只增、必须连续；高版本为当前围栏，旧版本证据保留可查但不充当当前进度。
//  - 检查点跨围栏不倒退：新版本 checkpoint 的 lastSeq 低于旧版本 → CHECKPOINT_REGRESSED 隔离。
import { mkdirSync, existsSync, readdirSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { ChainLog, ChainQuarantineError } from './chains.js';
import {
  SCHEMA,
  KINDS,
  OUTCOMES,
  FENCE_ACTIONS,
  canonicalJSON,
  sha256Hex,
  fingerprintRecord,
  slotKey,
} from './hashing.js';
import { verifyEnvelope } from './crypto.js';
import { envelopeHashOf, manifestHashOf } from './pack.js';

const HEX64 = /^[0-9a-f]{64}$/;
const PKG_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

// 严格键白名单：多余字段一律拒绝（归档形状确定，防止夹带未签名语义的自由字段）。
const ENVELOPE_KEYS = new Set(['schema', 'packageId', 'gatewayId', 'keyId', 'records', 'envelopeHash', 'signature']);
const RECORD_KEYS = {
  manifest: new Set(['kind', 'ts', 'manifest', 'manifestHash']),
  fence: new Set(['kind', 'ts', 'fenceId', 'version', 'action', 'prevVersion', 'detail']),
  segment: new Set(['kind', 'ts', 'fenceId', 'fenceVersion', 'segSeq', 'entries']),
  checkpoint: new Set(['kind', 'ts', 'fenceId', 'fenceVersion', 'lastSeq', 'counts']),
};
const MANIFEST_KEYS = new Set(['entries', 'issuedAt', 'validUntil']);
const MANIFEST_ENTRY_KEYS = new Set(['seq', 'deviceId']);
const SEGMENT_ENTRY_KEYS = new Set(['seq', 'deviceId', 'outcome', 'note']);
const COUNT_KEYS = new Set(OUTCOMES);

function checkKeys(obj, allowed, where) {
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) reject('RECORD_MALFORMED', `${where} 含未知字段: ${k}`);
  }
}

export function validPackageId(id) {
  return typeof id === 'string' && PKG_ID_RE.test(id) && !id.includes('..');
}

function reject(code, message, details = {}) {
  throw Object.assign(new Error(message), { code, status: 422, details });
}

// 单条记录的结构校验（规范化不通过即整包拒绝；归档端不接受“猜测性修复”）。
function validateRecordShape(rec, manifestSeqs) {
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) {
    reject('RECORD_MALFORMED', '记录必须是对象');
  }
  if (!KINDS.includes(rec.kind)) reject('RECORD_MALFORMED', `未知记录类型: ${rec.kind}`);
  checkKeys(rec, RECORD_KEYS[rec.kind], rec.kind);
  if (typeof rec.ts !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(rec.ts)) {
    reject('RECORD_MALFORMED', `${rec.kind}: ts 必须是 UTC ISO8601 字符串`);
  }
  switch (rec.kind) {
    case 'manifest': {
      const m = rec.manifest;
      if (!m || typeof m !== 'object') reject('RECORD_MALFORMED', 'manifest 记录缺少 manifest 对象');
      checkKeys(m, MANIFEST_KEYS, 'manifest');
      if (!Array.isArray(m.entries) || !m.entries.length) reject('RECORD_MALFORMED', 'manifest.entries 必须是非空数组');
      const seqs = new Set();
      for (const e of m.entries) {
        if (!e || typeof e !== 'object') reject('RECORD_MALFORMED', 'manifest.entries 项必须是对象');
        checkKeys(e, MANIFEST_ENTRY_KEYS, 'manifest.entries[]');
        if (!Number.isInteger(e.seq) || e.seq < 0) {
          reject('RECORD_MALFORMED', 'manifest.entries[].seq 必须是非负整数');
        }
        if (typeof e.deviceId !== 'string' || !e.deviceId) reject('RECORD_MALFORMED', 'manifest.entries[].deviceId 必填');
        if (seqs.has(e.seq)) reject('RECORD_MALFORMED', `manifest 序号重复: ${e.seq}`);
        seqs.add(e.seq);
      }
      if (typeof rec.manifestHash !== 'string' || !HEX64.test(rec.manifestHash)) {
        reject('RECORD_MALFORMED', 'manifestHash 必须是 64 位 hex');
      }
      if (manifestHashOf(m) !== rec.manifestHash) {
        reject('MANIFEST_HASH_MISMATCH', 'manifest 内容与 manifestHash 不符（清单被改写）');
      }
      if (m.issuedAt != null && typeof m.issuedAt !== 'string') reject('RECORD_MALFORMED', 'manifest.issuedAt 必须是字符串或 null');
      if (m.validUntil != null && typeof m.validUntil !== 'string') reject('RECORD_MALFORMED', 'manifest.validUntil 必须是字符串或 null');
      return;
    }
    case 'fence': {
      if (typeof rec.fenceId !== 'string' || !rec.fenceId) reject('RECORD_MALFORMED', 'fence.fenceId 必填');
      if (!Number.isInteger(rec.version) || rec.version < 1) reject('RECORD_MALFORMED', 'fence.version 必须是 ≥1 的整数');
      if (!FENCE_ACTIONS.includes(rec.action)) reject('RECORD_MALFORMED', `fence.action 非法: ${rec.action}`);
      // prevVersion：v1 的 CREATED 为 null；其余 CREATED/CLOSED 指向相邻上一版本。
      if (rec.prevVersion != null && (!Number.isInteger(rec.prevVersion) || rec.prevVersion < 0)) {
        reject('RECORD_MALFORMED', 'fence.prevVersion 必须是 ≥0 的整数或 null');
      }
      return;
    }
    case 'segment': {
      if (typeof rec.fenceId !== 'string' || !rec.fenceId) reject('RECORD_MALFORMED', 'segment.fenceId 必填');
      if (!Number.isInteger(rec.fenceVersion) || rec.fenceVersion < 1) reject('RECORD_MALFORMED', 'segment.fenceVersion 非法');
      if (!Number.isInteger(rec.segSeq) || rec.segSeq < 1) reject('RECORD_MALFORMED', 'segment.segSeq 必须是 ≥1 的整数');
      if (!Array.isArray(rec.entries) || !rec.entries.length) reject('RECORD_MALFORMED', 'segment.entries 必须是非空数组');
      const local = new Map();
      for (const e of rec.entries) {
        if (!e || typeof e !== 'object') reject('RECORD_MALFORMED', `分段 ${rec.segSeq}: entry 必须是对象`);
        checkKeys(e, SEGMENT_ENTRY_KEYS, `segment#${rec.segSeq}.entries[]`);
        if (!Number.isInteger(e.seq) || e.seq < 0) {
          reject('RECORD_MALFORMED', `分段 ${rec.segSeq}: entry.seq 必须是非负整数`);
        }
        if (typeof e.deviceId !== 'string' || !e.deviceId) reject('RECORD_MALFORMED', `分段 ${rec.segSeq}: entry.deviceId 必填`);
        if (!OUTCOMES.includes(e.outcome)) reject('RECORD_MALFORMED', `分段 ${rec.segSeq}: outcome 非法: ${e.outcome}`);
        if (e.note != null && typeof e.note !== 'string') reject('RECORD_MALFORMED', `分段 ${rec.segSeq}: note 必须是字符串或 null`);
        if (manifestSeqs && !manifestSeqs.has(e.seq)) reject('SEQ_OUT_OF_RANGE', `分段 ${rec.segSeq}: 序号 ${e.seq} 不在清单范围内`);
        if (manifestSeqs) {
          const dev = manifestSeqs.get(e.seq);
          if (dev && dev !== e.deviceId) reject('DEVICE_NOT_IN_PACKAGE', `分段 ${rec.segSeq}: 序号 ${e.seq} 的设备应为 ${dev}，实际 ${e.deviceId}`);
        }
        const fp = `${e.seq}|${e.deviceId}|${e.outcome}|${e.note ?? ''}`;
        if (local.has(e.seq)) {
          if (local.get(e.seq) !== fp) reject('ENTRY_CONTENT_CONFLICT', `分段 ${rec.segSeq}: 同序号 ${e.seq} 出现不同内容`);
        } else local.set(e.seq, fp);
      }
      return;
    }
    case 'checkpoint': {
      if (typeof rec.fenceId !== 'string' || !rec.fenceId) reject('RECORD_MALFORMED', 'checkpoint.fenceId 必填');
      if (!Number.isInteger(rec.fenceVersion) || rec.fenceVersion < 1) reject('RECORD_MALFORMED', 'checkpoint.fenceVersion 非法');
      if (!Number.isInteger(rec.lastSeq) || rec.lastSeq < 0) reject('RECORD_MALFORMED', 'checkpoint.lastSeq 必须是非负整数');
      const c = rec.counts;
      if (!c || typeof c !== 'object') reject('RECORD_MALFORMED', 'checkpoint.counts 必填');
      for (const k of OUTCOMES) {
        if (!Number.isInteger(c[k]) || c[k] < 0) reject('RECORD_MALFORMED', `checkpoint.counts.${k} 必须是非负整数`);
      }
      checkKeys(c, COUNT_KEYS, 'checkpoint.counts');
      return;
    }
    default:
      reject('RECORD_MALFORMED', `未实现的记录类型: ${rec.kind}`);
  }
}

export class EvidenceArchive {
  constructor(rootDir, packageId) {
    if (!validPackageId(packageId)) reject('PACKAGE_ID_INVALID', `非法 packageId: ${packageId}`);
    this.rootDir = rootDir;
    this.packageId = packageId;
    this.dir = join(rootDir, 'packages', packageId);
    mkdirSync(this.dir, { recursive: true });
    const qdir = join(rootDir, 'packages', packageId);
    this.ledger = new ChainLog(join(this.dir, 'ledger.jsonl'),
      { chainName: 'ledger', packageId, quarantineDir: qdir, label: `${packageId}/ledger` });
    this.quarantine = new ChainLog(join(this.dir, 'quarantine.jsonl'),
      { chainName: 'quarantine', packageId, quarantineDir: qdir, label: `${packageId}/quarantine` });
    this.audit = new ChainLog(join(this.dir, 'audit.jsonl'),
      { chainName: 'audit', packageId, quarantineDir: qdir, label: `${packageId}/audit` });
    // 内存投影索引（全部可由链重放重建）
    this.slotIndex = new Map(); // slot -> { fingerprint, seq }
    this.fenceVersions = new Map(); // version -> ledger seq（围栏版本号 -> 已接受记录）
    this.maxFenceVersion = 0;
    this.auditByEnvelope = new Map(); // envelopeHash -> 首次裁决快照
    this.manifest = null;
    this.#load();
  }

  #load() {
    this.ledger.load();
    this.quarantine.load();
    this.audit.load();
    for (const rec of this.ledger.records) {
      this.#indexAccepted(rec);
    }
    for (const rec of this.audit.records) {
      if (rec.envelopeHash && rec.disposition) this.auditByEnvelope.set(rec.envelopeHash, rec);
    }
  }

  #indexAccepted(rec) {
    const slot = slotKey(rec);
    this.slotIndex.set(slot, { fingerprint: rec.fingerprint, seq: rec.seq });
    if (rec.kind === 'fence') {
      this.fenceVersions.set(rec.version, rec.seq);
      if (rec.version > this.maxFenceVersion) this.maxFenceVersion = rec.version;
    }
    if (rec.kind === 'manifest' && !this.manifest) this.manifest = rec;
  }

  get writable() {
    return this.ledger.writable && this.quarantine.writable && this.audit.writable;
  }

  verify() {
    return {
      packageId: this.packageId,
      writable: this.writable,
      chains: {
        ledger: this.ledger.verify(),
        quarantine: this.quarantine.verify(),
        audit: this.audit.verify(),
      },
    };
  }

  // 校验并导入一个证据信封。返回裁决快照（重复导入返回【完全相同】的首次快照）。
  importEnvelope(envelope, { registry, nowIso }) {
    if (!this.writable) throw new ChainQuarantineError(this.ledger.recovery || this.quarantine.recovery);

    // ---- 阶段 1：信封结构 ----
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      reject('ENVELOPE_MALFORMED', '证据包必须是 JSON 对象');
    }
    checkKeys(envelope, ENVELOPE_KEYS, 'envelope');
    if (envelope.schema !== SCHEMA) reject('ENVELOPE_MALFORMED', `schema 不符（期望 ${SCHEMA}）`);
    if (!validPackageId(envelope.packageId)) reject('ENVELOPE_MALFORMED', '信封缺少合法 packageId');
    if (envelope.packageId !== this.packageId) {
      reject('PACKAGE_MISMATCH', `信封 packageId(${envelope.packageId}) 与归档目标(${this.packageId})不一致`);
    }
    if (typeof envelope.gatewayId !== 'string' || !envelope.gatewayId) reject('ENVELOPE_MALFORMED', '信封缺少 gatewayId');
    if (typeof envelope.keyId !== 'string' || !envelope.keyId) reject('ENVELOPE_MALFORMED', '信封缺少 keyId');
    if (!Array.isArray(envelope.records) || !envelope.records.length) reject('ENVELOPE_MALFORMED', '信封 records 必须是非空数组');
    if (typeof envelope.envelopeHash !== 'string' || !HEX64.test(envelope.envelopeHash)) {
      reject('ENVELOPE_MALFORMED', '信封缺少合法 envelopeHash');
    }
    if (typeof envelope.signature !== 'string' || !/^[0-9a-f]{128}$/.test(envelope.signature)) {
      reject('ENVELOPE_MALFORMED', '信封缺少合法 Ed25519 signature（128 hex）');
    }

    // ---- 阶段 2：信封哈希（规范化复算；任何字节被改即拒）----
    if (envelopeHashOf(envelope) !== envelope.envelopeHash) {
      reject('ENVELOPE_HASH_MISMATCH', '信封内容与 envelopeHash 不符（证据被改写或规范化不一致）');
    }

    // ---- 阶段 3：网关注册表 + Ed25519 签名（必须先于重复判定：
    //      未通过签名的信封，哪怕字节与历史信封相同，也不能借“重复”放行）----
    const gw = registry.get(envelope.gatewayId);
    if (!gw) reject('GATEWAY_UNKNOWN', `网关 ${envelope.gatewayId} 未登记公钥`);
    if (gw.keyId !== envelope.keyId) {
      reject('SIGNATURE_KEY_MISMATCH', `信封 keyId(${envelope.keyId}) 与网关注册 keyId(${gw.keyId}) 不一致`);
    }
    if (!verifyEnvelope(gw.publicKeyPem, envelope.envelopeHash, envelope.signature)) {
      reject('SIGNATURE_INVALID', 'Ed25519 签名验证失败');
    }

    // ---- 阶段 4：重复导入 → 返回首次裁决原结果（已验签，原裁决结论安全可复用）----
    const prior = this.auditByEnvelope.get(envelope.envelopeHash);
    if (prior) {
      return {
        duplicate: true,
        importId: prior.importId,
        firstImportedAt: prior.at,
        result: prior.result,
        disposition: prior.disposition,
        envelopeHash: envelope.envelopeHash,
        packageId: this.packageId,
      };
    }

    // ---- 阶段 5：逐条结构 + 哈希校验（带 manifest 序号表）----
    let manifestRecord = this.manifest;
    const envelopeManifestIdx = envelope.records.findIndex((r) => r?.kind === 'manifest');
    if (envelopeManifestIdx > 0) reject('RECORD_ORDER_INVALID', 'manifest 记录必须位于信封 records 首位');
    if (envelopeManifestIdx === 0) {
      validateRecordShape(envelope.records[0], null);
      manifestRecord = envelope.records[0];
    }
    if (!manifestRecord) {
      reject('MANIFEST_REQUIRED', '该包尚未归档清单，首封证据必须包含 manifest 记录');
    }
    // 清单已存在且不同：硬拒绝（绝不覆盖已归档清单；若要仲裁请走独立变更流程）。
    if (envelopeManifestIdx === 0 && this.manifest &&
        fingerprintRecord(envelope.records[0]) !== fingerprintRecord(this.manifest)) {
      reject('MANIFEST_CONTENT_CONFLICT', '该 packageId 已归档内容不同的清单，拒绝覆盖');
    }
    const seqDevices = new Map(manifestRecord.manifest.entries.map((e) => [e.seq, e.deviceId]));

    for (let i = envelopeManifestIdx === 0 ? 1 : 0; i < envelope.records.length; i++) {
      validateRecordShape(envelope.records[i], seqDevices);
    }

    // ---- 阶段 6：信封内次序/围栏连续性规则 ----
    const seenFenceVersion = new Set();
    let lastFenceVersionInEnv = 0;
    const segMaxByVersion = new Map(); // 仅统计信封内
    let lastCheckpointVersion = 0;
    for (const r of envelope.records) {
      if (r.kind === 'fence') {
        if (seenFenceVersion.has(r.version)) {
          reject('FENCE_VERSION_CONFLICT', `信封内围栏版本重复: v${r.version}`);
        }
        if (r.version <= lastFenceVersionInEnv) {
          reject('FENCE_VERSION_ORDER', `围栏版本必须严格递增（v${lastFenceVersionInEnv} → v${r.version}）`);
        }
        seenFenceVersion.add(r.version);
        lastFenceVersionInEnv = r.version;
      } else if (r.kind === 'segment') {
        const last = segMaxByVersion.get(r.fenceVersion) || 0;
        if (r.segSeq <= last) {
          reject('SEGMENT_SEQ_ORDER', `围栏 v${r.fenceVersion} 的分段号必须严格递增（seg${r.segSeq}）`);
        }
        segMaxByVersion.set(r.fenceVersion, r.segSeq);
      } else if (r.kind === 'checkpoint') {
        if (r.fenceVersion < lastCheckpointVersion) {
          reject('CHECKPOINT_ORDER', `检查点围栏版本必须不递减（v${r.fenceVersion}）`);
        }
        lastCheckpointVersion = r.fenceVersion;
      }
    }

    // 围栏版本号必须与已归档历史连续衔接（gap 拒绝；先导入旧围栏证据即可）。
    // 历史已存在的版本在槽位阶段裁决（同指纹跳过/异指纹冲突），不参与续号。
    let nextExpected = this.maxFenceVersion + 1;
    for (const r of envelope.records) {
      if (r.kind !== 'fence') continue;
      if (this.fenceVersions.has(r.version)) continue;
      if (r.version !== nextExpected) {
        reject('FENCE_VERSION_GAP', `围栏版本不连续：期望 v${nextExpected}，收到 v${r.version}（请先补导缺失的围栏变更证据）`);
      }
      nextExpected = r.version + 1;
    }

    // 非围栏记录引用的围栏版本必须存在（历史已接受 或 本信封前面已提供）。
    const envFence = new Map();
    for (const r of envelope.records) {
      if (r.kind === 'fence') envFence.set(r.version, r);
    }
    const fenceKnown = (v) => this.fenceVersions.has(v) || envFence.has(v);
    const fenceClosedVersion = new Set();
    for (const rec of this.ledger.records) {
      if (rec.kind === 'fence' && rec.action === 'CLOSED') fenceClosedVersion.add(rec.version);
    }
    for (const r of envelope.records) {
      if (r.kind === 'manifest') continue;
      if (r.kind === 'fence') {
        // v1 关闭时没有上一版本（prevVersion 可为 null/0）；其余变更必须指向相邻版本。
        if (!(r.action === 'CLOSED' && r.version === 1 && (r.prevVersion == null || r.prevVersion === 0))
            && r.action !== 'CREATED' && r.prevVersion !== r.version - 1) {
          reject('FENCE_PREV_VERSION', `围栏 v${r.version} 的 prevVersion 必须是 ${r.version - 1}`);
        }
        if (r.action === 'CLOSED' && !fenceKnown(r.version)) {
          reject('FENCE_UNKNOWN', `CLOSED 围栏 v${r.version} 在证据中不存在`);
        }
        continue;
      }
      if (!fenceKnown(r.fenceVersion)) {
        reject('FENCE_UNKNOWN', `${r.kind} 引用了不存在的围栏版本 v${r.fenceVersion}（请先导入该围栏变更证据）`);
      }
    }

    // ---- 阶段 7：逐记录裁决 —— 接受 / 幂等重复 / 冲突隔离 ----
    const accepted = [];
    const duplicates = [];
    const conflicts = [];
    const localSlots = new Map(); // 本信封已占槽 -> fingerprint
    const knownVersion = new Set(this.fenceVersions.keys());
    for (const r of envelope.records) if (r.kind === 'fence') knownVersion.add(r.version);

    // 已归档各围栏版本的最大检查点 lastSeq（倒退判定）。
    const cpLastSeqByVersion = new Map();
    for (const rec of this.ledger.records) {
      if (rec.kind === 'checkpoint') cpLastSeqByVersion.set(rec.fenceVersion, rec.lastSeq);
    }
    // 已关闭版本（CLOSED 是生命周期推进，独立槽位，不与 CREATED 互踩）。
    const closedVersions = new Set();
    for (const rec of this.ledger.records) {
      if (rec.kind === 'fence' && rec.action === 'CLOSED') closedVersions.add(rec.version);
    }

    const at = nowIso || new Date().toISOString();
    const importId = `imp_${envelope.envelopeHash.slice(0, 16)}`;

    for (const rec0 of envelope.records) {
      // 归档时附加来源元数据（进入证据链）。
      const fingerprint = fingerprintRecord(rec0);
      const slot = slotKey(rec0);

      // 围栏 CLOSED：关闭的是【版本】而非某条 CREATED 记录，用独立生命周期槽。
      if (rec0.kind === 'fence' && rec0.action === 'CLOSED') {
        if (closedVersions.has(rec0.version)) {
          duplicates.push({ slot, kind: rec0.kind, fingerprint });
          continue;
        }
        closedVersions.add(rec0.version);
        const storedClose = this.ledger.append({
          ...rec0,
          gatewayId: envelope.gatewayId,
          keyId: envelope.keyId,
          envelopeHash: envelope.envelopeHash,
          importId,
          receivedAt: at,
          fingerprint,
          slot,
        });
        accepted.push({ slot, kind: storedClose.kind, fingerprint, seq: storedClose.seq });
        continue;
      }

      // 检查点跨围栏不倒退（新版本 lastSeq 不得低于任一旧版本已声明水位）。
      if (rec0.kind === 'checkpoint') {
        const priorMax = Math.max(-1, ...[...cpLastSeqByVersion.entries()]
          .filter(([v]) => v < rec0.fenceVersion).map(([, s]) => s));
        if (priorMax >= 0 && rec0.lastSeq < priorMax) {
          conflicts.push(this.#conflictEntry({
            slot, reason: 'CHECKPOINT_REGRESSED', rec: rec0, fingerprint, envelope, importId, at,
            extra: { priorMaxLastSeq: priorMax },
          }));
          continue;
        }
      }

      const existing = this.slotIndex.get(slot) || localSlots.get(slot) || null;
      if (existing) {
        const existingFp = existing.fingerprint;
        if (existingFp === fingerprint) {
          duplicates.push({ slot, kind: rec0.kind, fingerprint });
        } else {
          conflicts.push(this.#conflictEntry({
            slot, reason: this.#conflictReason(rec0.kind), rec: rec0, fingerprint,
            envelope, importId, at, extra: { existingFingerprint: existingFp, existingSeq: existing.seq ?? null },
          }));
        }
        continue;
      }

      const stored = this.ledger.append({
        ...rec0,
        gatewayId: envelope.gatewayId,
        keyId: envelope.keyId,
        envelopeHash: envelope.envelopeHash,
        importId,
        receivedAt: at,
        fingerprint,
        slot,
      });
      const view = { slot, kind: stored.kind, fingerprint, seq: stored.seq };
      accepted.push(view);
      localSlots.set(slot, { fingerprint, seq: stored.seq });
      this.#indexAccepted(stored);
      if (stored.kind === 'checkpoint') cpLastSeqByVersion.set(stored.fenceVersion, stored.lastSeq);
    }

    // ---- 阶段 8：冲突链 + 裁决审计落账 ----
    const conflictViews = [];
    for (const c of conflicts) {
      const q = this.quarantine.append(c);
      conflictViews.push({
        slot: c.slot, reason: c.reason, fingerprint: c.fingerprint,
        existingFingerprint: c.existingFingerprint ?? null, seq: q.seq, at: c.at,
        gatewayId: c.gatewayId, kind: c.record.kind,
      });
    }

    const result = conflicts.length ? 'CONFLICTS' : 'ACCEPTED';
    const disposition = {
      result,
      recordsTotal: envelope.records.length,
      recordsAccepted: accepted.length,
      recordsDuplicate: duplicates.length,
      recordsConflicted: conflicts.length,
      accepted: accepted.map(({ slot, kind, fingerprint, seq }) => ({ slot, kind, fingerprint, seq })),
      duplicates: duplicates.map(({ slot, kind, fingerprint }) => ({ slot, kind, fingerprint })),
      conflicts: conflictViews.map(({ slot, reason, fingerprint, existingFingerprint, seq }) => ({
        slot, reason, fingerprint, existingFingerprint, seq,
      })),
      ledgerTipSeq: this.ledger.seq,
      quarantineTipSeq: this.quarantine.seq,
    };
    this.audit.append({
      kind: 'IMPORT',
      at,
      importId,
      envelopeHash: envelope.envelopeHash,
      gatewayId: envelope.gatewayId,
      keyId: envelope.keyId,
      result,
      disposition,
    });
    this.auditByEnvelope.set(envelope.envelopeHash, {
      kind: 'IMPORT', at, importId, envelopeHash: envelope.envelopeHash,
      gatewayId: envelope.gatewayId, result, disposition,
    });

    return {
      duplicate: false,
      importedAt: at,
      importId,
      result,
      disposition,
      envelopeHash: envelope.envelopeHash,
      packageId: this.packageId,
    };
  }

  #conflictReason(kind) {
    if (kind === 'manifest') return 'MANIFEST_CONTENT_CONFLICT';
    if (kind === 'fence') return 'FENCE_CONTENT_CONFLICT';
    if (kind === 'segment') return 'SEGMENT_CONTENT_CONFLICT';
    return 'CHECKPOINT_CONTENT_CONFLICT';
  }

  #conflictEntry({ slot, reason, rec, fingerprint, envelope, importId, at, extra = {} }) {
    return {
      kind: 'CONFLICT',
      at,
      importId,
      envelopeHash: envelope.envelopeHash,
      gatewayId: envelope.gatewayId,
      keyId: envelope.keyId,
      slot,
      reason,
      fingerprint,
      existingFingerprint: extra.existingFingerprint ?? null,
      existingSeq: extra.existingSeq ?? null,
      ...extra,
      record: rec,
    };
  }

  // 原始已拒绝信封落盘（0600），供事后审计；任何对外读取都必须先脱敏。
  persistRejected(rejectedDir, envelope, code, message, at) {
    mkdirSync(rejectedDir, { recursive: true });
    const stamp = at.replace(/[:.]/g, '-');
    const hashPart = typeof envelope?.envelopeHash === 'string' ? envelope.envelopeHash.slice(0, 12) : 'nohash';
    const file = join(rejectedDir, `${stamp}-${hashPart}.json`);
    writeFileSync(file, JSON.stringify({
      at, targetPackageId: this.packageId, code, message, envelope: envelope ?? null,
    }, null, 2) + '\n', { mode: 0o600 });
    return file;
  }
}

// 归档根目录管理：惰性打开/缓存各包，扫描包列表。
export class ArchiveManager {
  constructor(rootDir) {
    this.rootDir = rootDir;
    mkdirSync(rootDir, { recursive: true, mode: 0o700 });
    try { chmodSync(rootDir, 0o700); } catch { /* 忽略 */ }
    mkdirSync(join(rootDir, 'packages'), { recursive: true, mode: 0o700 });
    this.cache = new Map();
  }

  get rejectedDir() {
    return join(this.rootDir, 'rejected');
  }

  open(packageId) {
    if (!validPackageId(packageId)) reject('PACKAGE_ID_INVALID', `非法 packageId: ${packageId}`);
    if (!this.cache.has(packageId)) {
      this.cache.set(packageId, new EvidenceArchive(this.rootDir, packageId));
    }
    return this.cache.get(packageId);
  }

  list() {
    const dir = join(this.rootDir, 'packages');
    if (!existsSync(dir)) return [];
    return readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory() && validPackageId(d.name))
      .map((d) => d.name)
      .sort();
  }
}

export { canonicalJSON, sha256Hex };
