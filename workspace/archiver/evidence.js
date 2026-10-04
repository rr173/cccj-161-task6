// 证据归档与冲突核验（独立模块的领域核心）。
//
// 背景：断网期间多个现场网关可能各自保存同一作业包（packageId）的证据——
// 清单 manifest、围栏变更、分段回执、检查点。运营人员把网关导出的【带签名证据包】
// 通过网页 / HTTP 导入，本模块先校验再归档，并生成可阅读、可下载的核验报告。
//
// 校验管线（任一失败即整体拒绝，不归档任何内容，只留 EVIDENCE_REJECTED 审计）：
//   1) 结构：格式版本 / 必填字段 / 链条目结构；
//   2) 签名：keyId 已登记 + Ed25519 验签（规范化 JSON，键名排序）；
//   3) 哈希链：seq 从 1 连续、prevHash 衔接、逐条重算 hash；
//   4) 清单：manifestHash 重算、manifestSignature 用包签发公钥验签、packageId 一致；
//   5) 分段：逐条序号/设备/结果校验 + HMAC 摘要重算（uploadSecret 只用于核验，归档前脱敏）；
//   6) 检查点：checkpointToken 重算；
//   7) 围栏：FENCE_CHANGE 单调递增，分段/检查点引用的围栏必须已声明。
//
// 归档与合并规则（确定性，重放结果逐字节一致）：
//   - 幂等：bundleHash = sha256(规范化签名正文)；同一证据包重复导入返回【原归档回执】；
//   - 同一 (fence, segSeq) 只接受第一段内容：同哈希 → 幂等；不同内容 → 冲突隔离
//     （SEGMENT_SEQ_CONFLICT），先归档的证据永不覆盖，后来的进隔离区；
//   - 回执按包内序号合并：同序号同内容幂等；同序号不同内容 → SEQ_CONTENT_CONFLICT 隔离；
//     同一序号被更新围栏以相同内容再次回报时，归属转移到最新围栏（移交继承），
//     旧围栏分段在时间线中仍可查询，但不计入当前进度；
//   - 当前围栏 = 有已接受分段的最大围栏号；当前进度只统计当前围栏自己的回执，
//     旧围栏证据保留可查（HISTORICAL）但不计入当前进度；
//   - 合并检查点 = 全部已接受回执的并集（每序号计一次）归因到当前围栏，
//     证据只增不改 → 检查点单调不倒退（多围栏合并不倒退）。
//
// 脱敏：归档前对证据包做白名单规范化重建，uploadSecret 一律替换为
// {redacted:true, secretHash}；私钥/主密钥从不进入本模块；报告与日志只含脱敏证据。
import { canonicalJSON, sha256Hex } from '../src/util.js';
import { segmentDigest, verifyCanonical } from '../src/package-crypto.js';
import { ZERO_HASH } from '../src/store.js';

export class EvidenceError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

export const BUNDLE_FORMAT = 'dr-package-evidence/v1';
export const MANIFEST_FORMAT = 'dr-offline-package/v1';
export const EVIDENCE_OUTCOMES = ['EXECUTED', 'SKIPPED', 'FAILED'];
const HASH_RE = /^[0-9a-f]{64}$/;
const SIG_RE = /^[0-9a-f]{128}$/; // Ed25519 签名 64 字节
const CHAIN_TYPES = ['FENCE_CHANGE', 'SEGMENT', 'CHECKPOINT'];

// ---------- 规范化（与编排内核/网关 SDK 完全一致的约定） ----------

export function normalizeItems(items) {
  return (items || []).map((it) => ({
    seq: Number(it.seq),
    deviceId: String(it.deviceId),
    outcome: String(it.outcome),
    detail: it.detail == null ? null : String(it.detail),
  }));
}

export function segmentHashOf(segSeq, items) {
  return sha256Hex(canonicalJSON({ segSeq, items: normalizeItems(items) }));
}

export function receiptContentHash(it) {
  return sha256Hex(canonicalJSON({ outcome: it.outcome, detail: it.detail }));
}

export function checkpointTokenOf(packageId, fence, appliedSeqs, counts) {
  return sha256Hex(canonicalJSON({ packageId, fence, appliedSeqs, counts }));
}

// 签名正文：证据包除 signature 字段外的全部内容（规范化 JSON，键名排序）。
export function bundleSignedBody(bundle) {
  const { signature, ...body } = bundle || {};
  void signature;
  return body;
}

export function bundleHashOf(bundle) {
  return sha256Hex(canonicalJSON(bundleSignedBody(bundle)));
}

function chainEntryHash(entry) {
  const { hash, ...rest } = entry;
  void hash;
  return sha256Hex(canonicalJSON(rest));
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function bad(message, details = {}) {
  return new EvidenceError('EVIDENCE_STRUCTURE_INVALID', message, details);
}

// ---------- 归档引擎 ----------

export class EvidenceArchive {
  constructor({ store, keys }) {
    this.store = store;
    this.keys = keys;
    this.reset();
  }

  reset() {
    this.packages = new Map(); // packageId -> 投影
    this.receipts = new Map(); // bundleHash -> 导入回执（幂等）
    this.trustedIssuers = new Map(); // issuerKeyId -> publicKeyPem
    this.rejectedCounts = new Map(); // packageId -> 被拒绝导入次数（投影计数，重放确定）
    this.secretRegistry = new Set(); // 本次进程内见过的原始 uploadSecret（仅内存，用于脱敏自检）
  }

  // ---------- 投影（重放） ----------

  apply(rec) {
    const p = rec.payload;
    switch (rec.type) {
      case 'EVIDENCE_KEY_PUBLISHED':
        this.keys.reconcile(p);
        return;
      case 'ISSUER_TRUSTED':
        this.trustedIssuers.set(p.keyId, p.publicKeyPem);
        return;
      case 'EVIDENCE_BUNDLE_ARCHIVED':
        this.#applyArchived(rec);
        return;
      case 'EVIDENCE_REJECTED': {
        // 审计记录：只累计投影计数（按日志顺序应用，重放结果与在线一致）
        const key = p.packageId || '(unknown)';
        this.rejectedCounts.set(key, (this.rejectedCounts.get(key) || 0) + 1);
        return;
      }
      default:
        return;
    }
  }

  #append(type, payload, now) {
    const rec = this.store.append(type, payload, now ?? Date.now());
    if (type !== 'EVIDENCE_BUNDLE_ARCHIVED') this.apply(rec);
    return rec;
  }

  // ---------- 密钥与信任 ----------

  rotateKey(nowIso) {
    const pub = this.keys.rotate(nowIso);
    this.#append('EVIDENCE_KEY_PUBLISHED', pub);
    return pub;
  }

  trustIssuer({ keyId, publicKeyPem }) {
    if (!keyId || !publicKeyPem) throw new EvidenceError('BAD_REQUEST', 'keyId 与 publicKeyPem 必填');
    const existing = this.trustedIssuers.get(keyId);
    if (existing) {
      if (existing !== publicKeyPem) {
        throw new EvidenceError('ISSUER_KEY_MISMATCH', `签发方 ${keyId} 已登记不同公钥`, { keyId });
      }
      return { keyId, publicKeyPem, idempotent: true };
    }
    this.#append('ISSUER_TRUSTED', { keyId, publicKeyPem, via: 'MANUAL' });
    return { keyId, publicKeyPem, idempotent: false };
  }

  // 演示/网关 SDK 小工具：对未签名证据包正文计算签名（私钥不出服务进程）。
  signBundle(unsignedBundle) {
    const keyId = this.keys.currentKeyId;
    if (!keyId) throw new EvidenceError('EVIDENCE_KEY_UNAVAILABLE', '证据签名密钥尚未就绪，请先轮换生成');
    const body = bundleSignedBody(unsignedBundle);
    const canonical = canonicalJSON(body);
    return {
      keyId,
      bundleHash: sha256Hex(canonical),
      signature: this.keys.sign(keyId, canonical),
    };
  }

  // ---------- 校验管线 ----------

  // 纯校验：不触碰投影与日志。通过则返回规范化视图与派生数据；失败抛 EvidenceError。
  verifyBundle(bundle) {
    // 1) 结构
    if (!isPlainObject(bundle)) throw bad('证据包必须是 JSON 对象');
    if (bundle.format !== BUNDLE_FORMAT) {
      throw bad(`证据包格式必须是 ${BUNDLE_FORMAT}`, { format: bundle.format ?? null });
    }
    for (const field of ['bundleId', 'packageId', 'gatewayId', 'keyId', 'signature']) {
      if (typeof bundle[field] !== 'string' || !bundle[field]) throw bad(`证据包缺少字段 ${field}`);
    }
    if (!SIG_RE.test(bundle.signature)) throw bad('signature 必须是 Ed25519 签名（128 位十六进制）');
    if (!isPlainObject(bundle.issuer) || typeof bundle.issuer.keyId !== 'string'
      || typeof bundle.issuer.publicKeyPem !== 'string' || !bundle.issuer.publicKeyPem.includes('BEGIN PUBLIC KEY')) {
      throw bad('证据包缺少合法的 issuer {keyId, publicKeyPem}');
    }
    if (!isPlainObject(bundle.manifest)) throw bad('证据包缺少 manifest');
    if (!HASH_RE.test(bundle.manifestHash || '')) throw bad('manifestHash 必须是 64 位十六进制');
    if (!SIG_RE.test(bundle.manifestSignature || '')) throw bad('manifestSignature 必须是 Ed25519 签名（128 位十六进制）');
    if (!Array.isArray(bundle.chain) || !bundle.chain.length) throw bad('证据链 chain 必须是非空数组');
    if (!isPlainObject(bundle.uploadSecrets)) throw bad('uploadSecrets 必须是 {围栏号: 上传密钥} 对象');

    // 2) 签名（规范化 JSON + Ed25519）
    if (!this.keys.has(bundle.keyId)) {
      throw new EvidenceError('EVIDENCE_KEY_UNKNOWN', `证据签名密钥 ${bundle.keyId} 未登记`, { keyId: bundle.keyId });
    }
    const canonical = canonicalJSON(bundleSignedBody(bundle));
    const bundleHash = sha256Hex(canonical);
    if (!this.keys.verify(bundle.keyId, canonical, bundle.signature)) {
      throw new EvidenceError('EVIDENCE_SIGNATURE_INVALID', '证据包签名验签失败（内容被篡改或密钥不符）', {
        bundleId: bundle.bundleId, keyId: bundle.keyId,
      });
    }

    // 3) 哈希链：seq 从 1 连续、prevHash 衔接、逐条重算
    let prev = ZERO_HASH;
    bundle.chain.forEach((entry, i) => {
      const at = `第 ${i + 1} 条链记录`;
      if (!isPlainObject(entry)) throw new EvidenceError('EVIDENCE_CHAIN_BROKEN', `${at}：不是合法 JSON 对象`, { index: i });
      if (entry.seq !== i + 1) {
        throw new EvidenceError('EVIDENCE_CHAIN_BROKEN', `${at}：序号异常，期望 ${i + 1}，实际 ${JSON.stringify(entry.seq)}`, { index: i, seq: entry.seq });
      }
      if (!CHAIN_TYPES.includes(entry.type)) {
        throw new EvidenceError('EVIDENCE_CHAIN_BROKEN', `${at}：未知记录类型 ${JSON.stringify(entry.type)}`, { index: i, type: entry.type });
      }
      if (!isPlainObject(entry.payload)) throw new EvidenceError('EVIDENCE_CHAIN_BROKEN', `${at}：缺少 payload`, { index: i });
      if (!HASH_RE.test(entry.prevHash || '') || !HASH_RE.test(entry.hash || '')) {
        throw new EvidenceError('EVIDENCE_CHAIN_BROKEN', `${at}：缺少合法 prevHash/hash`, { index: i });
      }
      if (entry.prevHash !== prev) {
        throw new EvidenceError('EVIDENCE_CHAIN_BROKEN', `${at}：prevHash 不衔接（证据链断裂）`, { index: i, seq: entry.seq });
      }
      if (chainEntryHash(entry) !== entry.hash) {
        throw new EvidenceError('EVIDENCE_CHAIN_BROKEN', `${at}：内容与哈希不符（记录被改写）`, { index: i, seq: entry.seq });
      }
      prev = entry.hash;
    });

    // 4) 清单：哈希重算 + 签发方验签 + packageId 一致
    const m = bundle.manifest;
    if (m.format !== MANIFEST_FORMAT) {
      throw new EvidenceError('MANIFEST_HASH_MISMATCH', `清单格式必须是 ${MANIFEST_FORMAT}`, { format: m.format ?? null });
    }
    if (m.packageId !== bundle.packageId) {
      throw new EvidenceError('PACKAGE_ID_MISMATCH', '清单 packageId 与证据包不一致', {
        bundlePackageId: bundle.packageId, manifestPackageId: m.packageId ?? null,
      });
    }
    if (!Array.isArray(m.instructions) || !m.instructions.length) {
      throw bad('清单缺少指令序列 instructions');
    }
    const recomputedManifestHash = sha256Hex(canonicalJSON(m));
    if (recomputedManifestHash !== bundle.manifestHash) {
      throw new EvidenceError('MANIFEST_HASH_MISMATCH', '清单内容哈希与 manifestHash 不符', {
        stored: bundle.manifestHash, recomputed: recomputedManifestHash,
      });
    }
    if (!verifyCanonical(bundle.issuer.publicKeyPem, canonicalJSON(m), bundle.manifestSignature)) {
      throw new EvidenceError('MANIFEST_SIGNATURE_INVALID', '清单签发签名验签失败', { issuerKeyId: bundle.issuer.keyId });
    }
    const trusted = this.trustedIssuers.get(bundle.issuer.keyId);
    if (trusted && trusted !== bundle.issuer.publicKeyPem) {
      throw new EvidenceError('ISSUER_KEY_MISMATCH', `签发方 ${bundle.issuer.keyId} 的公钥与已登记信任不符`, {
        issuerKeyId: bundle.issuer.keyId,
      });
    }
    const issuerTrust = trusted ? 'TRUSTED' : 'TOFU';

    // 5) 分段：结构 + 序号/设备/结果 + HMAC 摘要
    const secrets = new Map(); // fence -> uploadSecret（仅内存使用，归档前脱敏）
    for (const [fenceKey, secret] of Object.entries(bundle.uploadSecrets)) {
      if (!/^\d+$/.test(fenceKey) || typeof secret !== 'string' || !HASH_RE.test(secret)) {
        throw bad(`uploadSecrets 的键必须是围栏号、值必须是 64 位十六进制密钥`, { fenceKey });
      }
      secrets.set(Number(fenceKey), secret);
    }
    const fenceChanges = [];
    const segments = [];
    const checkpoints = [];
    for (const entry of bundle.chain) {
      const p = entry.payload;
      if (entry.type === 'FENCE_CHANGE') {
        if (!Number.isInteger(p.fence) || p.fence < 1) throw bad('FENCE_CHANGE 的 fence 必须是从 1 开始的正整数', { fence: p.fence });
        if (typeof p.gatewayId !== 'string' || !p.gatewayId) throw bad('FENCE_CHANGE 缺少 gatewayId');
        fenceChanges.push({
          fence: p.fence,
          kind: typeof p.kind === 'string' ? p.kind : 'CLAIM',
          gatewayId: p.gatewayId,
          fromGatewayId: p.fromGatewayId == null ? null : String(p.fromGatewayId),
          toGatewayId: p.toGatewayId == null ? null : String(p.toGatewayId),
          at: Number.isFinite(p.at) ? p.at : null,
        });
      } else if (entry.type === 'SEGMENT') {
        const fence = Number(p.fence);
        const segSeq = Number(p.segSeq);
        if (!Number.isInteger(fence) || fence < 1) throw bad('SEGMENT 的 fence 必须是正整数', { fence: p.fence });
        if (!Number.isInteger(segSeq) || segSeq < 1) throw bad('SEGMENT 的 segSeq 必须是从 1 开始的正整数', { segSeq: p.segSeq });
        if (!Array.isArray(p.items) || !p.items.length) throw bad('SEGMENT 的 items 必须是非空数组', { segSeq });
        const items = normalizeItems(p.items);
        for (const it of items) {
          if (!Number.isInteger(it.seq) || it.seq < 1 || it.seq > m.instructions.length) {
            throw new EvidenceError('SEQ_OUT_OF_RANGE', `包内序号 ${it.seq} 越界（合法范围 1..${m.instructions.length}）`, {
              seq: it.seq, maxSeq: m.instructions.length,
            });
          }
          const expected = m.instructions[it.seq - 1];
          if (expected.deviceId !== it.deviceId) {
            throw new EvidenceError('DEVICE_NOT_IN_PACKAGE', `序号 ${it.seq} 对应的设备应为 ${expected.deviceId}，实际 ${it.deviceId}`, {
              seq: it.seq, expectedDevice: expected.deviceId, providedDevice: it.deviceId,
            });
          }
          if (!EVIDENCE_OUTCOMES.includes(it.outcome)) {
            throw bad(`回执结果必须是 ${EVIDENCE_OUTCOMES.join('/')}`, { seq: it.seq, outcome: it.outcome });
          }
        }
        const secret = secrets.get(fence);
        if (!secret) {
          throw new EvidenceError('UPLOAD_SECRET_MISSING', `证据包未携带围栏 ${fence} 的上传密钥，无法核验分段摘要`, { fence });
        }
        const expectedDigest = segmentDigest(secret, canonicalJSON({
          packageId: bundle.packageId, fence, segSeq, items,
        }));
        if (p.digest !== expectedDigest) {
          throw new EvidenceError('DIGEST_MISMATCH', `分段 ${segSeq}（围栏 ${fence}）摘要不匹配（HMAC-SHA256 校验失败）`, {
            fence, segSeq, providedDigest: p.digest ?? null,
          });
        }
        segments.push({
          fence, segSeq, items,
          digest: p.digest,
          segmentHash: segmentHashOf(segSeq, items),
          at: Number.isFinite(p.at) ? p.at : null,
        });
      } else if (entry.type === 'CHECKPOINT') {
        const fence = Number(p.fence);
        if (!Number.isInteger(fence) || fence < 1) throw bad('CHECKPOINT 的 fence 必须是正整数', { fence: p.fence });
        const appliedSeqs = p.appliedSeqs;
        if (!Array.isArray(appliedSeqs) || appliedSeqs.some((s) => !Number.isInteger(s) || s < 1)) {
          throw bad('CHECKPOINT 的 appliedSeqs 必须是正整数数组');
        }
        const sorted = [...appliedSeqs].sort((a, b) => a - b);
        if (sorted.some((s, i) => s !== appliedSeqs[i]) || new Set(appliedSeqs).size !== appliedSeqs.length) {
          throw bad('CHECKPOINT 的 appliedSeqs 必须升序且无重复');
        }
        const counts = p.counts;
        if (!isPlainObject(counts) || !['total', 'merged', 'executed', 'skipped', 'failed', 'remaining'].every((k) => Number.isInteger(counts[k]) && counts[k] >= 0)) {
          throw bad('CHECKPOINT 的 counts 必须包含 total/merged/executed/skipped/failed/remaining 非负整数');
        }
        const token = checkpointTokenOf(bundle.packageId, fence, appliedSeqs, counts);
        if (p.checkpointToken !== token) {
          throw new EvidenceError('CHECKPOINT_TOKEN_MISMATCH', `检查点令牌重算不符（围栏 ${fence}）`, {
            fence, provided: p.checkpointToken ?? null, recomputed: token,
          });
        }
        checkpoints.push({ fence, appliedSeqs, counts, checkpointToken: p.checkpointToken, at: Number.isFinite(p.at) ? p.at : null });
      }
    }

    // 7) 围栏：FENCE_CHANGE 严格递增；分段/检查点引用的围栏必须已声明
    let lastFence = 0;
    const declared = new Set();
    for (const fc of fenceChanges) {
      if (fc.fence <= lastFence) {
        throw new EvidenceError('FENCE_REGRESSION', `围栏变更必须严格递增：${lastFence} 之后又出现 ${fc.fence}`, {
          previousFence: lastFence, fence: fc.fence,
        });
      }
      lastFence = fc.fence;
      declared.add(fc.fence);
    }
    for (const seg of segments) {
      if (!declared.has(seg.fence)) {
        throw new EvidenceError('FENCE_UNDECLARED', `分段引用了未声明的围栏 ${seg.fence}`, { fence: seg.fence, segSeq: seg.segSeq });
      }
    }
    for (const cp of checkpoints) {
      if (!declared.has(cp.fence)) {
        throw new EvidenceError('FENCE_UNDECLARED', `检查点引用了未声明的围栏 ${cp.fence}`, { fence: cp.fence });
      }
    }

    return {
      bundleHash,
      canonical,
      packageId: bundle.packageId,
      gatewayId: bundle.gatewayId,
      keyId: bundle.keyId,
      issuerTrust,
      fenceChanges,
      segments,
      checkpoints,
      secrets,
      verification: {
        signatureValid: true,
        chainLength: bundle.chain.length,
        chainTipHash: prev,
        manifestHashValid: true,
        manifestSignatureValid: true,
        segmentsVerified: segments.length,
        checkpointsVerified: checkpoints.length,
        issuerTrust,
      },
    };
  }

  // ---------- 命令：导入证据包 ----------

  importBundle(bundle, now = Date.now()) {
    // 结构外的元信息（用于拒绝审计；绝不记录证据包正文，避免泄露 uploadSecret）
    const meta = {
      packageId: typeof bundle?.packageId === 'string' ? bundle.packageId : null,
      gatewayId: typeof bundle?.gatewayId === 'string' ? bundle.gatewayId : null,
      keyId: typeof bundle?.keyId === 'string' ? bundle.keyId : null,
      bundleHash: null,
    };
    try {
      meta.bundleHash = bundleHashOf(bundle);
    } catch { /* 结构不合法时无法计算 */ }

    let v;
    try {
      v = this.verifyBundle(bundle);
    } catch (err) {
      if (err instanceof EvidenceError) {
        this.#append('EVIDENCE_REJECTED', {
          code: err.code, reason: err.message, ...meta, details: err.details || {},
        }, now);
      }
      throw err;
    }

    // 幂等：同一证据包（规范化签名正文哈希一致）重复导入 → 返回原归档回执
    const existing = this.receipts.get(v.bundleHash);
    if (existing) return { duplicate: true, ...existing };

    // 同一 packageId 的清单锚定首次归档版本：后续证据包清单哈希必须一致
    const pkg = this.packages.get(v.packageId);
    if (pkg && pkg.manifestHash !== bundle.manifestHash) {
      const err = new EvidenceError('MANIFEST_CONFLICT', '证据包清单与已归档清单不一致（同一 packageId 锚定固定版本）', {
        packageId: v.packageId, archivedManifestHash: pkg.manifestHash, providedManifestHash: bundle.manifestHash,
      });
      this.#append('EVIDENCE_REJECTED', { code: err.code, reason: err.message, ...meta, details: err.details }, now);
      throw err;
    }

    // 签发方信任：首次见到的签发公钥按 TOFU 登记上链（之后不符即拒，见 verifyBundle）
    if (v.issuerTrust === 'TOFU') {
      this.#append('ISSUER_TRUSTED', {
        keyId: bundle.issuer.keyId, publicKeyPem: bundle.issuer.publicKeyPem, via: 'TOFU',
      }, now);
    }

    // 登记原始密钥（仅内存，用于脱敏自检），随后脱敏归档
    for (const secret of v.secrets.values()) this.secretRegistry.add(secret);
    const redactedBundle = this.#redactBundle(bundle, v);

    const rec = this.#append('EVIDENCE_BUNDLE_ARCHIVED', {
      bundleHash: v.bundleHash,
      bundleId: bundle.bundleId,
      packageId: v.packageId,
      gatewayId: v.gatewayId,
      keyId: v.keyId,
      exportedAt: Number.isFinite(bundle.exportedAt) ? bundle.exportedAt : null,
      bundle: redactedBundle,
      verification: v.verification,
    }, now);
    const receipt = this.#applyArchived(rec);
    return { duplicate: false, ...receipt };
  }

  // 白名单规范化重建 + 脱敏：只保留约定字段，uploadSecret 替换为 secretHash。
  // 即使恶意证据包在多余字段里夹带凭据，也不会落盘。
  #redactBundle(bundle, v) {
    const redactedSecrets = {};
    for (const [fence, secret] of v.secrets.entries()) {
      redactedSecrets[String(fence)] = {
        redacted: true,
        algorithm: 'HMAC-SHA256',
        secretHash: sha256Hex(secret),
      };
    }
    const chain = bundle.chain.map((entry) => {
      const p = entry.payload;
      let payload;
      if (entry.type === 'FENCE_CHANGE') {
        payload = {
          fence: p.fence, kind: p.kind ?? 'CLAIM', gatewayId: p.gatewayId,
          fromGatewayId: p.fromGatewayId ?? null, toGatewayId: p.toGatewayId ?? null,
          at: Number.isFinite(p.at) ? p.at : null,
        };
      } else if (entry.type === 'SEGMENT') {
        payload = {
          fence: p.fence, segSeq: p.segSeq, items: normalizeItems(p.items), digest: p.digest,
          at: Number.isFinite(p.at) ? p.at : null,
        };
      } else {
        payload = {
          fence: p.fence, appliedSeqs: [...p.appliedSeqs], counts: { ...p.counts },
          checkpointToken: p.checkpointToken, at: Number.isFinite(p.at) ? p.at : null,
        };
      }
      return {
        seq: entry.seq, ts: Number.isFinite(entry.ts) ? entry.ts : null,
        type: entry.type, payload, prevHash: entry.prevHash, hash: entry.hash,
      };
    });
    return {
      format: bundle.format,
      bundleId: bundle.bundleId,
      packageId: bundle.packageId,
      gatewayId: bundle.gatewayId,
      keyId: bundle.keyId,
      exportedAt: Number.isFinite(bundle.exportedAt) ? bundle.exportedAt : null,
      issuer: { keyId: bundle.issuer.keyId, publicKeyPem: bundle.issuer.publicKeyPem },
      manifest: bundle.manifest,
      manifestHash: bundle.manifestHash,
      manifestSignature: bundle.manifestSignature,
      uploadSecrets: redactedSecrets,
      chain,
      signature: bundle.signature,
    };
  }

  // 归档投影合并（命令与重放共用，确定性）。返回导入回执。
  #applyArchived(rec) {
    const p = rec.payload;
    let pkg = this.packages.get(p.packageId);
    if (!pkg) {
      pkg = {
        packageId: p.packageId,
        manifest: p.bundle.manifest,
        manifestHash: p.bundle.manifestHash,
        manifestSignature: p.bundle.manifestSignature,
        issuer: p.bundle.issuer,
        bundles: new Map(), // bundleHash -> {bundleId, gatewayId, keyId, archiveSeq, exportedAt}
        fences: new Map(), // fence -> {fence, gatewayIds:Set, changes:[], declaredAtSeq}
        segments: new Map(), // `${fence}:${segSeq}` -> 已接受分段
        receipts: new Map(), // seq -> 已合并回执
        checkpoints: [], // 已核验的网关检查点（按归档顺序）
        entryOutcomes: new Map(), // bundleHash -> Map(chainSeq -> {status, conflictId?})
        conflicts: [],
        conflictSeq: 0,
      };
      this.packages.set(p.packageId, pkg);
    }

    const outcomes = new Map();
    const stats = { accepted: 0, duplicates: 0, quarantined: 0 };
    const conflictIds = [];
    const b = p.bundle;

    const quarantine = (kind, detail) => {
      pkg.conflictSeq += 1;
      const conflict = {
        conflictId: `${p.packageId}#C${pkg.conflictSeq}`,
        kind,
        packageId: p.packageId,
        detectedAtSeq: rec.seq,
        ...detail,
      };
      pkg.conflicts.push(conflict);
      conflictIds.push(conflict.conflictId);
      stats.quarantined += 1;
      return conflict;
    };

    b.chain.forEach((entry, idx) => {
      const chainSeq = entry.seq ?? idx + 1;
      const ep = entry.payload;
      if (entry.type === 'FENCE_CHANGE') {
        let f = pkg.fences.get(ep.fence);
        if (!f) {
          f = { fence: ep.fence, gatewayIds: new Set(), changes: [], declaredAtSeq: rec.seq };
          pkg.fences.set(ep.fence, f);
        }
        f.gatewayIds.add(ep.gatewayId);
        f.changes.push({
          kind: ep.kind, gatewayId: ep.gatewayId, fromGatewayId: ep.fromGatewayId ?? null,
          toGatewayId: ep.toGatewayId ?? null, at: ep.at ?? null, bundleHash: p.bundleHash, archiveSeq: rec.seq,
        });
        outcomes.set(chainSeq, { status: 'RECORDED' });
        return;
      }
      if (entry.type === 'CHECKPOINT') {
        pkg.checkpoints.push({
          fence: ep.fence, appliedSeqs: [...ep.appliedSeqs], counts: { ...ep.counts },
          checkpointToken: ep.checkpointToken, gatewayId: b.gatewayId,
          bundleHash: p.bundleHash, archiveSeq: rec.seq, at: ep.at ?? null,
        });
        outcomes.set(chainSeq, { status: 'RECORDED' });
        return;
      }
      // SEGMENT
      const segKey = `${ep.fence}:${ep.segSeq}`;
      const segmentHash = segmentHashOf(ep.segSeq, ep.items);
      const prior = pkg.segments.get(segKey);
      if (prior) {
        if (prior.segmentHash === segmentHash) {
          // 完全相同的分段重传：幂等，不重复计数
          stats.duplicates += 1;
          outcomes.set(chainSeq, { status: 'DUPLICATE', segmentHash });
        } else {
          // 同围栏同分段号不同内容：冲突隔离，已保存证据不覆盖
          const c = quarantine('SEGMENT_SEQ_CONFLICT', {
            fence: ep.fence,
            segSeq: ep.segSeq,
            reason: `围栏 ${ep.fence} 分段 ${ep.segSeq} 已归档不同内容，新证据进入隔离区`,
            kept: {
              segmentHash: prior.segmentHash, bundleHash: prior.bundleHash,
              gatewayId: prior.gatewayId, archiveSeq: prior.archiveSeq, items: prior.items,
            },
            rejected: {
              segmentHash, bundleHash: p.bundleHash,
              gatewayId: b.gatewayId, archiveSeq: rec.seq, items: normalizeItems(ep.items),
            },
          });
          outcomes.set(chainSeq, { status: 'QUARANTINED', segmentHash, conflictId: c.conflictId });
        }
        return;
      }
      // 新分段：逐条合并回执；同序号不同内容的条目单独隔离（不覆盖既有证据）
      const accepted = {
        fence: ep.fence, segSeq: ep.segSeq, segmentHash,
        bundleHash: p.bundleHash, gatewayId: b.gatewayId, archiveSeq: rec.seq,
        items: normalizeItems(ep.items), at: ep.at ?? null,
      };
      pkg.segments.set(segKey, accepted);
      let itemConflicts = 0;
      for (const it of accepted.items) {
        const existing = pkg.receipts.get(it.seq);
        if (existing) {
          if (receiptContentHash(existing) !== receiptContentHash(it) || existing.deviceId !== it.deviceId) {
            itemConflicts += 1;
            quarantine('SEQ_CONTENT_CONFLICT', {
              fence: ep.fence,
              segSeq: ep.segSeq,
              seq: it.seq,
              reason: `序号 ${it.seq} 已有不同回执（${existing.outcome}），新内容进入隔离区，既有证据不覆盖`,
              kept: {
                contentHash: receiptContentHash(existing), outcome: existing.outcome, detail: existing.detail,
                fence: existing.fence, segSeq: existing.segSeq,
                bundleHash: existing.bundleHash, gatewayId: existing.gatewayId, archiveSeq: existing.archiveSeq,
              },
              rejected: {
                contentHash: receiptContentHash(it), outcome: it.outcome, detail: it.detail,
                fence: ep.fence, segSeq: ep.segSeq,
                bundleHash: p.bundleHash, gatewayId: b.gatewayId, archiveSeq: rec.seq,
              },
            });
          } else if (ep.fence > existing.fence) {
            // 同一序号被更新围栏以【相同内容】再次回报：归属转移到最新围栏
            // （移交后新网关继承并确认进度）；旧围栏分段在时间线中仍可查询。
            existing.priorFences = [...(existing.priorFences || []), {
              fence: existing.fence, segSeq: existing.segSeq,
              gatewayId: existing.gatewayId, bundleHash: existing.bundleHash, archiveSeq: existing.archiveSeq,
            }];
            existing.fence = ep.fence;
            existing.segSeq = ep.segSeq;
            existing.gatewayId = b.gatewayId;
            existing.bundleHash = p.bundleHash;
            existing.archiveSeq = rec.seq;
            existing.at = ep.at ?? null;
          }
          continue; // 同内容同围栏：幂等
        }
        pkg.receipts.set(it.seq, {
          seq: it.seq, deviceId: it.deviceId, outcome: it.outcome, detail: it.detail,
          fence: ep.fence, segSeq: ep.segSeq,
          bundleHash: p.bundleHash, gatewayId: b.gatewayId, archiveSeq: rec.seq, at: ep.at ?? null,
        });
      }
      stats.accepted += 1;
      outcomes.set(chainSeq, { status: 'MERGED', segmentHash, ...(itemConflicts ? { itemConflicts } : {}) });
    });

    pkg.bundles.set(p.bundleHash, {
      bundleHash: p.bundleHash,
      bundleId: p.bundleId, gatewayId: p.gatewayId, keyId: p.keyId,
      archiveSeq: rec.seq, exportedAt: p.exportedAt ?? null,
    });
    pkg.entryOutcomes.set(p.bundleHash, outcomes);

    const receipt = {
      bundleHash: p.bundleHash,
      bundleId: p.bundleId,
      packageId: p.packageId,
      gatewayId: p.gatewayId,
      archiveSeq: rec.seq,
      segments: stats,
      conflicts: conflictIds,
      reportDigest: this.buildReport(p.packageId).reportDigest,
    };
    this.receipts.set(p.bundleHash, receipt);
    return receipt;
  }

  // ---------- 视图 ----------

  #checkpointOf(pkg, seqs) {
    const appliedSeqs = [...seqs].sort((a, b) => a - b);
    let watermark = 0;
    const receiptSet = new Set(appliedSeqs);
    while (receiptSet.has(watermark + 1)) watermark += 1;
    let executed = 0, skipped = 0, failed = 0;
    for (const seq of appliedSeqs) {
      const r = pkg.receipts.get(seq);
      if (r.outcome === 'EXECUTED') executed += 1;
      else if (r.outcome === 'SKIPPED') skipped += 1;
      else if (r.outcome === 'FAILED') failed += 1;
    }
    const total = pkg.manifest.instructions.length;
    return {
      appliedSeqs,
      watermark,
      counts: {
        total, merged: appliedSeqs.length, executed, skipped, failed,
        remaining: total - appliedSeqs.length,
      },
    };
  }

  #currentFence(pkg) {
    let current = 0;
    for (const seg of pkg.segments.values()) {
      if (seg.fence > current) current = seg.fence;
    }
    return current;
  }

  buildReport(packageId) {
    const pkg = this.packages.get(packageId);
    if (!pkg) return null;
    const currentFence = this.#currentFence(pkg);
    const allSeqs = [...pkg.receipts.keys()];
    const merged = this.#checkpointOf(pkg, allSeqs);
    const mergedCheckpoint = {
      fence: currentFence,
      ...merged,
      checkpointToken: checkpointTokenOf(packageId, currentFence, merged.appliedSeqs, merged.counts),
    };
    // 当前进度：只统计当前围栏自己的回执（旧围栏证据不计入当前进度）
    const currentSeqs = allSeqs.filter((s) => pkg.receipts.get(s).fence === currentFence);
    const currentProgress = { fence: currentFence, ...this.#checkpointOf(pkg, currentSeqs) };
    // 继承进度：旧围栏仍计入合并检查点的历史回执（可查询，不算当前进度）
    const inheritedSeqs = allSeqs.filter((s) => pkg.receipts.get(s).fence !== currentFence);

    const fences = [...pkg.fences.values()]
      .sort((a, b) => a.fence - b.fence)
      .map((f) => {
        const fenceSeqs = allSeqs.filter((s) => pkg.receipts.get(s).fence === f.fence);
        return {
          fence: f.fence,
          status: f.fence === currentFence ? 'CURRENT' : 'HISTORICAL',
          gatewayIds: [...f.gatewayIds].sort(),
          declaredAtSeq: f.declaredAtSeq,
          changes: f.changes.map((c) => ({ ...c })),
          segmentsAccepted: [...pkg.segments.values()].filter((s) => s.fence === f.fence).length,
          ...this.#checkpointOf(pkg, fenceSeqs),
        };
      });

    // 时间线：按 (归档序号, 链内序号) 确定排序
    const timeline = [];
    const archived = [...pkg.bundles.values()].sort((a, b) => a.archiveSeq - b.archiveSeq);
    for (const meta of archived) {
      const rec = this.store.all().find((r) => r.seq === meta.archiveSeq);
      const chain = rec?.payload?.bundle?.chain || [];
      const outcomes = pkg.entryOutcomes.get(meta.bundleHash) || new Map();
      chain.forEach((entry, idx) => {
        const chainSeq = entry.seq ?? idx + 1;
        const outcome = outcomes.get(chainSeq) || { status: 'RECORDED' };
        const ep = entry.payload;
        timeline.push({
          order: timeline.length + 1,
          archiveSeq: meta.archiveSeq,
          chainSeq,
          bundleHash: meta.bundleHash,
          bundleId: meta.bundleId,
          gatewayId: meta.gatewayId,
          type: entry.type,
          fence: ep.fence ?? null,
          segSeq: ep.segSeq ?? null,
          status: outcome.status,
          ...(outcome.segmentHash ? { segmentHash: outcome.segmentHash } : {}),
          ...(outcome.conflictId ? { conflictId: outcome.conflictId } : {}),
          ...(outcome.itemConflicts ? { itemConflicts: outcome.itemConflicts } : {}),
          at: ep.at ?? null,
        });
      });
    }

    // 检查点交叉核验（告警，不阻断）：网关声明的 appliedSeqs 必须有已归档回执支撑
    const checkpointWarnings = [];
    const backedSeqs = new Set(allSeqs);
    for (const cp of pkg.checkpoints) {
      const unbacked = cp.appliedSeqs.filter((s) => !backedSeqs.has(s));
      if (unbacked.length) {
        checkpointWarnings.push({
          fence: cp.fence, bundleHash: cp.bundleHash, archiveSeq: cp.archiveSeq,
          warning: 'CHECKPOINT_UNBACKED',
          reason: `检查点声明的序号缺少已归档回执支撑：${unbacked.join(', ')}`,
          unbackedSeqs: unbacked,
        });
      }
    }

    const report = {
      format: 'dr-evidence-report/v1',
      packageId,
      generatedFrom: { bundles: pkg.bundles.size, archiveSeqHigh: Math.max(0, ...archived.map((x) => x.archiveSeq), 0) },
      manifest: {
        manifestHash: pkg.manifestHash,
        issuerKeyId: pkg.issuer.keyId,
        eventId: pkg.manifest.eventId ?? null,
        deviceCount: pkg.manifest.instructions.length,
        validUntil: pkg.manifest.validUntil ?? null,
      },
      currentFence,
      currentProgress,
      inheritedProgress: { seqs: inheritedSeqs.sort((a, b) => a - b), count: inheritedSeqs.length },
      mergedCheckpoint,
      fences,
      timeline,
      conflicts: pkg.conflicts.map((c) => ({ ...c })),
      checkpointWarnings,
      verification: {
        bundlesVerified: pkg.bundles.size,
        allSignaturesValid: true,
        allChainsValid: true,
        rejectedImports: this.rejectedCounts.get(packageId) || 0,
      },
      redaction: {
        uploadSecrets: 'REDACTED',
        note: '上传密钥/私钥/凭据从不落盘；证据仅保留 secretHash 供比对',
      },
    };
    const reportDigest = sha256Hex(canonicalJSON(report));
    return { report, reportDigest };
  }

  packageView(packageId) {
    const built = this.buildReport(packageId);
    if (!built) return null;
    const pkg = this.packages.get(packageId);
    return {
      ...built.report,
      reportDigest: built.reportDigest,
      receipts: [...pkg.receipts.values()]
        .sort((a, b) => a.seq - b.seq)
        .map((r) => ({ ...r })),
      quarantine: pkg.conflicts.map((c) => ({ ...c })),
    };
  }

  listPackages() {
    return [...this.packages.keys()].sort().map((id) => {
      const built = this.buildReport(id);
      return {
        packageId: id,
        currentFence: built.report.currentFence,
        bundles: built.report.generatedFrom.bundles,
        merged: built.report.mergedCheckpoint.counts.merged,
        total: built.report.mergedCheckpoint.counts.total,
        conflicts: built.report.conflicts.length,
        reportDigest: built.reportDigest,
      };
    });
  }

  listConflicts(packageId = null) {
    const out = [];
    for (const [id, pkg] of [...this.packages.entries()].sort()) {
      if (packageId && id !== packageId) continue;
      for (const c of pkg.conflicts) out.push({ ...c });
    }
    return out;
  }

  // 脱敏自检：序列化输出中不得出现任何本次进程见过的原始 uploadSecret。
  assertRedacted(jsonText) {
    for (const secret of this.secretRegistry) {
      if (jsonText.includes(secret)) {
        throw new EvidenceError('REDACTION_BREACH', '输出包含未脱敏的上传密钥，已阻断');
      }
    }
    return jsonText;
  }
}
