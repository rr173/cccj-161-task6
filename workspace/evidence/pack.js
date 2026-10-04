// 网关侧证据包封装工具（SDK 参考实现）：
// 把离线期间保存的清单/围栏变更/分段回执/检查点组装成带签名的证据信封。
//
// 信封结构（JSON）：
//   { schema, packageId, gatewayId, keyId, records:[...], envelopeHash, signature }
// 信封哈希 = sha256(canonicalJSON({schema,packageId,gatewayId,keyId,records}))
// 签名     = Ed25519(网关私钥, envelopeHash 的 hex 文本)
// 归档服务按同样规则独立复算：先校 envelopeHash（任一记录被改即不符），再用注册表公钥验签。
//
// 记录（records）四类，字段固定、无多余包裹：
//   manifest   { kind:'manifest', ts, manifest:{entries:[{seq,deviceId}], issuedAt, validUntil?}, manifestHash }
//   fence      { kind:'fence', ts, fenceId, version, action, prevVersion, detail? }
//   segment    { kind:'segment', ts, fenceId, fenceVersion, segSeq, entries:[{seq,deviceId,outcome,note?}] }
//   checkpoint { kind:'checkpoint', ts, fenceId, fenceVersion, lastSeq, counts:{EXECUTED,SKIPPED,FAILED} }
import { createHash } from 'node:crypto';
import {
  canonicalJSON,
  sha256Hex,
  SCHEMA,
  KINDS,
  OUTCOMES,
  FENCE_ACTIONS,
} from './hashing.js';
import { signEnvelope, generateGatewayKeyPair } from './crypto.js';

export { generateGatewayKeyPair };

export function manifestHashOf(manifest) {
  return sha256Hex(canonicalJSON({
    entries: [...(manifest.entries || [])]
      .map((e) => ({ seq: Number(e.seq), deviceId: String(e.deviceId) }))
      .sort((a, b) => (a.seq - b.seq) || (a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0)),
    issuedAt: manifest.issuedAt == null ? null : String(manifest.issuedAt),
    validUntil: manifest.validUntil == null ? null : String(manifest.validUntil),
  }));
}

// 规范化单条记录（制包侧与归档侧共用同一形状，避免键序/类型差异）。
export function normalizeRecord(input) {
  if (!input || typeof input !== 'object') throw new Error('记录必须是对象');
  const kind = String(input.kind || '');
  if (!KINDS.includes(kind)) throw new Error(`未知记录类型: ${kind}`);
  const ts = String(input.ts);
  if (!/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(ts)) throw new Error(`${kind}: ts 必须是 ISO8601 字符串`);
  const base = { kind, ts };
  if (kind === 'manifest') {
    const entries = [...(input.manifest?.entries || [])].map((e) => ({
      seq: Number(e.seq), deviceId: String(e.deviceId),
    }));
    const manifest = {
      entries,
      issuedAt: input.manifest.issuedAt == null ? null : String(input.manifest.issuedAt),
      validUntil: input.manifest.validUntil == null ? null : String(input.manifest.validUntil),
    };
    const manifestHash = input.manifestHash ? String(input.manifestHash) : manifestHashOf(manifest);
    return { ...base, manifest, manifestHash };
  }
  if (kind === 'fence') {
    return {
      ...base,
      fenceId: String(input.fenceId),
      version: Number(input.version),
      action: String(input.action),
      prevVersion: input.prevVersion == null ? null : Number(input.prevVersion),
      detail: input.detail == null ? null : String(input.detail),
    };
  }
  if (kind === 'segment') {
    return {
      ...base,
      fenceId: String(input.fenceId),
      fenceVersion: Number(input.fenceVersion),
      segSeq: Number(input.segSeq),
      entries: [...input.entries || []].map((e) => ({
        seq: Number(e.seq),
        deviceId: String(e.deviceId),
        outcome: String(e.outcome),
        note: e.note == null ? null : String(e.note),
      })),
    };
  }
  // checkpoint
  const counts = input.counts || {};
  return {
    ...base,
    fenceId: String(input.fenceId),
    fenceVersion: Number(input.fenceVersion),
    lastSeq: Number(input.lastSeq),
    counts: {
      EXECUTED: Number(counts.EXECUTED || 0),
      SKIPPED: Number(counts.SKIPPED || 0),
      FAILED: Number(counts.FAILED || 0),
    },
  };
}

export function envelopeCanonical(envelope) {
  return canonicalJSON({
    schema: envelope.schema,
    packageId: envelope.packageId,
    gatewayId: envelope.gatewayId,
    keyId: envelope.keyId,
    records: envelope.records,
  });
}

export function envelopeHashOf(envelope) {
  return sha256Hex(envelopeCanonical(envelope));
}

// 组装并签名一个证据信封。records 会被规范化；不做跨记录业务校验
// （围栏次序/分段引用等由归档服务在导入时裁决，制包端可离线自由生成）。
export function buildEnvelope({ packageId, gatewayId, keyId, records, privateKeyPem }) {
  const envelope = {
    schema: SCHEMA,
    packageId: String(packageId),
    gatewayId: String(gatewayId),
    keyId: String(keyId || 'default'),
    records: records.map(normalizeRecord),
  };
  envelope.envelopeHash = envelopeHashOf(envelope);
  envelope.signature = signEnvelope(privateKeyPem, envelope.envelopeHash);
  return envelope;
}

// 便捷构造器
export const R = {
  manifest: (ts, manifest, manifestHash) => ({ kind: 'manifest', ts, manifest, manifestHash }),
  fence: (ts, fenceId, version, action, prevVersion = null, detail = null) =>
    ({ kind: 'fence', ts, fenceId, version, action, prevVersion, detail }),
  segment: (ts, fenceId, fenceVersion, segSeq, entries) =>
    ({ kind: 'segment', ts, fenceId, fenceVersion, segSeq, entries }),
  checkpoint: (ts, fenceId, fenceVersion, lastSeq, counts) =>
    ({ kind: 'checkpoint', ts, fenceId, fenceVersion, lastSeq, counts }),
};

export { createHash, OUTCOMES, FENCE_ACTIONS };
