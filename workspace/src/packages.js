// 离线作业包领域模块（事件溯源投影 + 命令）。
//
// 与编排内核同一套只增哈希链：制包 / 领取 / 释放 / 强制移交 / 分段回执合并 /
// 拒绝 / 关闭 / 过期全部是不可变记录，重启重放后领取关系、围栏号、检查点与
// 回执次序逐字节一致，不会倒退。
//
// 核心不变量：
//  - 同一事件下一台设备至多进入一个作业包（释放/关闭/过期都不解锁，防重复切批）；
//  - 事件撤销或开始后不得再制新包，未被领取的包在开始时刻确定过期；
//  - 每次领取/移交围栏号 fence 只增，上传密钥按 fence 派生，旧围栏回执一律 FENCE_STALE；
//  - 分段全量校验通过才整体合并（原子），完全相同的分段重传按 segmentHash 幂等；
//  - 序号内容变化 / 越界序号 / 设备不在包内 / 摘要不匹配 / 包已关闭 都给明确拒绝码；
//  - 首条回执（执行/跳过/失败任一）合并后即锁进度，只能运营方强制移交（保留证据并轮换围栏）。
import { canonicalJSON, iso, sha256Hex, uid, round3 } from './util.js';
import { segmentDigest } from './package-crypto.js';
import { DomainError } from './kernel.js';

export const PACKAGE_OUTCOMES = ['EXECUTED', 'SKIPPED', 'FAILED'];
const PACKAGE_STATUSES = ['OPEN', 'CLAIMED', 'RELEASED', 'CLOSED', 'EXPIRED'];

// 上传分段摘要的签名范围：只含约定字段（键名排序规范化 JSON），命令其余字段不参与。
// 条目先经 normalizeItems，服务端与网关 SDK 必须对同一规范化字节计算 HMAC。
function digestBody(packageId, fence, segSeq, items) {
  return canonicalJSON({ packageId, fence, segSeq, items: normalizeItems(items) });
}

// 归一化条目：只保留约定字段，避免客户端多传字段导致摘要不稳定。
function normalizeItems(items) {
  return (items || []).map((it) => ({
    seq: Number(it.seq),
    deviceId: String(it.deviceId),
    outcome: String(it.outcome),
    detail: it.detail == null ? null : String(it.detail),
  }));
}

function receiptContentHash(it) {
  return sha256Hex(canonicalJSON({ outcome: it.outcome, detail: it.detail }));
}

export class PackageRegistry {
  constructor({ store, keys, clockNow, getEvent, getDevice }) {
    this.store = store;
    this.keys = keyStoreGuard(keys);
    this.clockNow = clockNow; // () => number
    this.getEvent = getEvent; // (eventId) => event projection
    this.getDevice = getDevice; // (deviceId) => device seed
    this.reset();
  }

  bind(deps) {
    this.store = deps.store;
    this.clockNow = deps.clockNow;
    this.getEvent = deps.getEvent;
    this.getDevice = deps.getDevice;
    if (deps.keys) this.keys = keyStoreGuard(deps.keys);
  }

  reset() {
    this.packages = new Map(); // packageId -> 投影
    this.eventDevices = new Map(); // eventId -> Map(deviceId -> packageId)
  }

  // ---------- 投影（重放） ----------

  apply(rec) {
    const p = rec.payload;
    switch (rec.type) {
      case 'PACKAGE_KEY_PUBLISHED':
        this.keys.reconcile(p);
        return;
      case 'PACKAGE_ISSUED': {
        const pkg = {
          packageId: p.packageId,
          eventId: p.eventId,
          eventVersion: p.eventVersion,
          anchorSeq: p.anchorSeq,
          anchorHash: p.anchorHash,
          keyId: p.keyId,
          manifestHash: p.manifestHash,
          entriesHash: p.entriesHash,
          manifest: p.manifest,
          signature: p.signature,
          instructions: p.instructions,
          deviceIds: p.deviceIds,
          validUntil: p.validUntil,
          issuedAt: p.issuedAt,
          createdBy: p.createdBy,
          status: 'OPEN',
          gatewayId: null,
          lastGatewayId: null,
          fence: 0,
          claimCount: 0,
          receipts: new Map(), // seq -> receipt 投影（按序号合并，永不覆盖）
          segments: new Map(), // segmentHash -> { segSeq, fence, recordSeq }
          segSeqIndex: new Map(), // `${fence}:${segSeq}` -> segmentHash（同围栏内同序号必须同内容）
          mergedCount: 0,
          executedCount: 0,
          skippedCount: 0,
          failedCount: 0,
          closedAt: null,
          closeReason: null,
          history: [{ type: 'ISSUED', at: p.issuedAt, recordSeq: rec.seq }],
        };
        this.packages.set(p.packageId, pkg);
        if (!this.eventDevices.has(p.eventId)) this.eventDevices.set(p.eventId, new Map());
        for (const deviceId of p.deviceIds) this.eventDevices.get(p.eventId).set(deviceId, p.packageId);
        return;
      }
      case 'PACKAGE_CLAIMED': {
        const pkg = this.packages.get(p.packageId);
        if (!pkg) return;
        pkg.status = 'CLAIMED';
        pkg.gatewayId = p.gatewayId;
        pkg.lastGatewayId = p.gatewayId;
        pkg.fence = p.fence;
        pkg.claimCount += 1;
        pkg.history.push({ type: 'CLAIMED', at: p.at, gatewayId: p.gatewayId, fence: p.fence, recordSeq: rec.seq });
        return;
      }
      case 'PACKAGE_RELEASED': {
        const pkg = this.packages.get(p.packageId);
        if (!pkg) return;
        pkg.status = 'RELEASED';
        pkg.gatewayId = null;
        pkg.history.push({ type: 'RELEASED', at: p.at, gatewayId: p.gatewayId, fence: p.fence, reason: p.reason, recordSeq: rec.seq });
        return;
      }
      case 'PACKAGE_HANDOVER': {
        const pkg = this.packages.get(p.packageId);
        if (!pkg) return;
        pkg.status = 'CLAIMED';
        pkg.gatewayId = p.toGatewayId;
        pkg.lastGatewayId = p.fromGatewayId;
        pkg.fence = p.newFence;
        pkg.claimCount += 1;
        pkg.history.push({
          type: 'HANDOVER', at: p.at, fromGatewayId: p.fromGatewayId, toGatewayId: p.toGatewayId,
          oldFence: p.oldFence, newFence: p.newFence, reason: p.reason, by: p.by, recordSeq: rec.seq,
        });
        return;
      }
      case 'PACKAGE_SEGMENT_ACCEPTED': {
        const pkg = this.packages.get(p.packageId);
        if (!pkg) return;
        pkg.segments.set(p.segmentHash, { segSeq: p.segSeq, fence: p.fence, recordSeq: rec.seq });
        pkg.segSeqIndex.set(`${p.fence}:${p.segSeq}`, p.segmentHash);
        for (const it of p.items) {
          // 重放幂等：链上不会有重复合并（命令层保证），这里仍按序号只增保护
          if (pkg.receipts.has(it.seq)) continue;
          pkg.receipts.set(it.seq, {
            seq: it.seq,
            deviceId: it.deviceId,
            outcome: it.outcome,
            detail: it.detail,
            fence: p.fence,
            segSeq: p.segSeq,
            gatewayId: p.gatewayId,
            at: p.at,
            recordSeq: rec.seq,
          });
        }
        this.#recomputeCounts(pkg);
        pkg.history.push({
          type: 'SEGMENT_ACCEPTED', at: p.at, fence: p.fence, segSeq: p.segSeq,
          merged: p.items.length, mergedCount: pkg.mergedCount, recordSeq: rec.seq,
        });
        return;
      }
      case 'PACKAGE_REJECTED': {
        const pkg = this.packages.get(p.packageId);
        if (!pkg) return;
        pkg.history.push({
          type: 'REJECTED', at: p.at, code: p.code, reason: p.reason,
          fence: p.fence ?? null, segSeq: p.segSeq ?? null,
          gatewayId: p.gatewayId ?? null, details: p.details ?? {}, recordSeq: rec.seq,
        });
        return;
      }
      case 'PACKAGE_CLOSED': {
        const pkg = this.packages.get(p.packageId);
        if (!pkg) return;
        pkg.status = 'CLOSED';
        pkg.closedAt = p.at;
        pkg.closeReason = p.reason;
        pkg.history.push({ type: 'CLOSED', at: p.at, reason: p.reason, recordSeq: rec.seq });
        return;
      }
      case 'PACKAGE_EXPIRED': {
        const pkg = this.packages.get(p.packageId);
        if (!pkg) return;
        pkg.status = 'EXPIRED';
        pkg.history.push({ type: 'EXPIRED', at: p.at, validUntil: pkg.validUntil, recordSeq: rec.seq });
        return;
      }
      default:
        return;
    }
  }

  #recomputeCounts(pkg) {
    let executed = 0, skipped = 0, failed = 0;
    for (const r of pkg.receipts.values()) {
      if (r.outcome === 'EXECUTED') executed++;
      else if (r.outcome === 'SKIPPED') skipped++;
      else if (r.outcome === 'FAILED') failed++;
    }
    pkg.executedCount = executed;
    pkg.skippedCount = skipped;
    pkg.failedCount = failed;
    pkg.mergedCount = pkg.receipts.size;
  }

  // ---------- 内部工具 ----------

  #append(type, payload, ts) {
    this.store.append(type, payload, ts);
    const rec = this.store.all().at(-1);
    this.apply(rec);
    return rec;
  }

  requirePackage(packageId) {
    const pkg = this.packages.get(packageId);
    if (!pkg) throw new DomainError('PACKAGE_NOT_FOUND', `作业包 ${packageId} 不存在`, { packageId });
    return pkg;
  }

  // 检查点：按包内序号合并后的稳定摘要。令牌只依赖 {包,围栏,序号集合,计数}，
  // 重传 / 重启 / 重放都得到同一个令牌。
  checkpoint(pkg) {
    const appliedSeqs = [...pkg.receipts.keys()].sort((a, b) => a - b);
    let watermark = 0; // 自 seq=1 起的连续前缀
    while (pkg.receipts.has(watermark + 1)) watermark++;
    const counts = {
      total: pkg.instructions.length,
      merged: pkg.mergedCount,
      executed: pkg.executedCount,
      skipped: pkg.skippedCount,
      failed: pkg.failedCount,
      remaining: pkg.instructions.length - pkg.mergedCount,
    };
    const token = sha256Hex(canonicalJSON({ packageId: pkg.packageId, fence: pkg.fence, appliedSeqs, counts }));
    return { fence: pkg.fence, watermark, appliedSeqs, counts, checkpointToken: token };
  }

  #recordRejection(pkg, code, reason, now, extra = {}) {
    this.#append('PACKAGE_REJECTED', {
      packageId: pkg.packageId,
      code,
      reason,
      at: now,
      ...extra,
    }, now);
  }

  // ---------- 命令 ----------

  // 运营制包：按事件的【固定已发布版本】切一批设备，生成只读包。
  issuePackage(cmd, now) {
    const ev = this.getEvent(cmd.eventId);
    if (!ev) throw new DomainError('NOT_FOUND', `事件 ${cmd.eventId} 不存在`, { eventId: cmd.eventId });
    if (ev.status !== 'SCHEDULED') {
      // 事件被撤销或开始后不再允许制新包
      throw new DomainError('PACKAGE_EVENT_NOT_CLAIMABLE',
        `事件已处于 ${ev.status}，开始或撤销后不得再制作业包`, { eventStatus: ev.status });
    }

    const deviceIds = [...new Set((cmd.deviceIds || []).map(String))].sort();
    if (!deviceIds.length) throw new DomainError('BAD_REQUEST', 'deviceIds 至少包含一台设备');

    let bound = this.eventDevices.get(ev.id);
    if (!bound) {
      bound = new Map();
      this.eventDevices.set(ev.id, bound);
    }
    for (const deviceId of deviceIds) {
      const dev = this.getDevice(deviceId);
      if (!dev) throw new DomainError('NOT_FOUND', `设备 ${deviceId} 不存在`, { deviceId });
      if (dev.meterId !== ev.meterId) {
        throw new DomainError('METER_MISMATCH', '设备不属于该事件的计量点，不能进入此作业包', {
          deviceId, deviceMeter: dev.meterId, eventMeter: ev.meterId,
        });
      }
      // 不同包不得重复包含同一设备（即便旧包已释放/关闭/过期，也永不解锁）
      if (bound.has(deviceId)) {
        throw new DomainError('DEVICE_ALREADY_PACKAGED', '该设备已被同一事件的另一个作业包包含，不可重复切批', {
          deviceId, existingPackageId: bound.get(deviceId),
        });
      }
    }

    // 有效期：默认到事件开始时刻；显式指定时不得早于当前、不得晚于事件开始
    let validUntil;
    if (Number.isFinite(Number(cmd.validUntilMs))) validUntil = Number(cmd.validUntilMs);
    else if (Number.isFinite(Number(cmd.validForMinutes))) validUntil = now + Number(cmd.validForMinutes) * 60000;
    else validUntil = ev.startMs;
    if (validUntil <= now) throw new DomainError('BAD_REQUEST', '有效期必须晚于当前仿真时间');
    if (validUntil > ev.startMs) throw new DomainError('BAD_REQUEST', '作业包有效期不得晚于事件开始时刻');

    // 锚定已发布事件的固定版本（EVENT_PUBLISHED 记录序号 + 哈希），包只读
    const anchorRec = [...this.store.all()].reverse().find(
      (r) => r.type === 'EVENT_PUBLISHED' && r.payload.id === ev.id,
    );
    if (!anchorRec) throw new DomainError('BAD_REQUEST', '事件缺少发布锚点记录');

    const keyId = this.keys.currentKeyId;
    if (!keyId) throw new DomainError('PACKAGE_KEY_UNAVAILABLE', '包签发密钥尚未就绪');
    const keyEntry = this.keys.current;
    if (!keyEntry?.privateKeyPem) {
      throw new DomainError('PACKAGE_KEY_UNAVAILABLE',
        `包签发密钥 ${keyId} 仅有公钥（sidecar 缺失或在新机器上重放），无法签发新包；历史包仍可验签`,
        { keyId });
    }

    // 包内序号按设备号字典序稳定分配；指令内容由已发布事件参数决定
    const instructions = deviceIds.map((deviceId, i) => {
      const dev = this.getDevice(deviceId);
      return {
        seq: i + 1,
        deviceId,
        deviceName: dev.name,
        action: 'SET_SHED_KW',
        targetKw: round3(Math.min(ev.targetKw, dev.maxKw)),
        startMs: ev.startMs,
        endMs: ev.endMs,
      };
    });
    const entriesHash = sha256Hex(canonicalJSON(instructions));

    const packageId = cmd.packageId || uid('PKG');
    const manifest = {
      format: 'dr-offline-package/v1',
      packageId,
      eventId: ev.id,
      eventVersion: 1,
      eventSpec: {
        meterId: ev.meterId,
        meterName: ev.meterName,
        algorithm: ev.algorithm,
        targetKw: ev.targetKw,
        startMs: ev.startMs,
        endMs: ev.endMs,
      },
      manifestSummary: {
        deviceCount: deviceIds.length,
        devices: deviceIds,
        entriesHash,
      },
      instructions,
      issuedAt: now,
      validUntil,
      keyId,
    };
    const manifestHash = sha256Hex(canonicalJSON(manifest));
    const signature = this.keys.signManifest(keyId, canonicalJSON(manifest));

    this.#append('PACKAGE_ISSUED', {
      packageId,
      eventId: ev.id,
      eventVersion: 1,
      anchorSeq: anchorRec.seq,
      anchorHash: anchorRec.hash,
      keyId,
      manifestHash,
      entriesHash,
      manifest,
      signature,
      instructions,
      deviceIds,
      validUntil,
      issuedAt: now,
      createdBy: cmd.createdBy || '运营方',
    }, now);

    return { package: this.view(packageId), manifest, signature };
  }

  // 网关领取：OPEN / RELEASED 可领；围栏号递增并派生本次上传密钥。
  claimPackage(cmd, now) {
    const pkg = this.requirePackage(cmd.packageId);
    const gatewayId = String(cmd.gatewayId || '');
    if (!gatewayId.trim()) throw new DomainError('BAD_REQUEST', 'gatewayId 必填');

    const ev = this.getEvent(pkg.eventId);
    if (pkg.status === 'CLAIMED') {
      if (pkg.gatewayId === gatewayId) {
        // 同一网关超时重领：幂等返回既有围栏，不轮换、不重复计数
        return this.#claimResponse(pkg, { idempotent: true });
      }
      throw new DomainError('PACKAGE_ALREADY_CLAIMED',
        `作业包已被网关 ${pkg.gatewayId} 领取（fence ${pkg.fence}）；如需改派请由运营方强制移交`, {
          ownerGatewayId: pkg.gatewayId, fence: pkg.fence,
        });
    }
    if (pkg.status === 'CLOSED') {
      throw new DomainError('PACKAGE_CLOSED', `作业包已关闭（${pkg.closeReason}），不可领取`, { reason: pkg.closeReason });
    }
    if (pkg.status === 'EXPIRED' || now >= pkg.validUntil) {
      if (pkg.status !== 'EXPIRED') this.#append('PACKAGE_EXPIRED', { packageId: pkg.packageId, at: now }, now);
      throw new DomainError('PACKAGE_EXPIRED', '作业包已过领取有效期', { validUntil: pkg.validUntil });
    }
    if (ev.status !== 'SCHEDULED') {
      // 事件撤销/开始后不再允许领取（含释放后的重新领取）
      throw new DomainError('PACKAGE_EVENT_NOT_CLAIMABLE',
        `事件已处于 ${ev.status}，不再允许领取作业包`, { eventStatus: ev.status });
    }

    const fence = pkg.fence + 1;
    this.#append('PACKAGE_CLAIMED', {
      packageId: pkg.packageId,
      gatewayId,
      fence,
      at: now,
    }, now);
    return this.#claimResponse(pkg, { idempotent: false });
  }

  #claimResponse(pkg, { idempotent }) {
    const uploadSecret = this.keys.uploadSecretFor(pkg.keyId, pkg.packageId, pkg.fence);
    return {
      idempotent,
      packageId: pkg.packageId,
      gatewayId: pkg.gatewayId,
      fence: pkg.fence,
      keyId: pkg.keyId,
      manifestHash: pkg.manifestHash,
      validUntil: pkg.validUntil,
      validUntilIso: iso(pkg.validUntil),
      upload: {
        algorithm: 'HMAC-SHA256',
        // 演示/网关 SDK：digest = HMAC-SHA256(uploadSecret, canonicalJSON({packageId,fence,segSeq,items}))
        secret: uploadSecret,
        signedFields: ['packageId', 'fence', 'segSeq', 'items'],
      },
      checkpoint: this.checkpoint(pkg),
    };
  }

  // 网关在首条回执前主动释放（零进度）；之后他人可重新领取。
  releasePackage(cmd, now) {
    const pkg = this.requirePackage(cmd.packageId);
    const gatewayId = String(cmd.gatewayId || '');
    if (pkg.status !== 'CLAIMED') {
      throw new DomainError('PACKAGE_NOT_CLAIMED', `作业包当前状态 ${pkg.status}，不能释放`, { status: pkg.status });
    }
    if (pkg.gatewayId !== gatewayId) {
      throw new DomainError('PACKAGE_FENCE_STALE', '只有当前领取网关可以释放作业包', {
        ownerGatewayId: pkg.gatewayId, providedGatewayId: gatewayId, fence: pkg.fence,
      });
    }
    if (pkg.mergedCount > 0) {
      throw new DomainError('PACKAGE_PROGRESS_LOCKED',
        `作业包已有 ${pkg.mergedCount} 条回执进度，不能自行释放；只能由运营方强制移交`, {
          mergedCount: pkg.mergedCount,
        });
    }
    this.#append('PACKAGE_RELEASED', {
      packageId: pkg.packageId,
      gatewayId,
      fence: pkg.fence,
      reason: cmd.reason || '网关释放',
      at: now,
    }, now);
    return { packageId: pkg.packageId, status: 'RELEASED', fence: pkg.fence };
  }

  // 运营强制移交：任意进度都可执行；证据（既有回执/历史）原样保留，围栏号轮换。
  handoverPackage(cmd, now) {
    const pkg = this.requirePackage(cmd.packageId);
    const toGatewayId = String(cmd.toGatewayId || '');
    if (!toGatewayId.trim()) throw new DomainError('BAD_REQUEST', 'toGatewayId 必填');
    if (pkg.status !== 'CLAIMED') {
      throw new DomainError('PACKAGE_NOT_CLAIMED', `作业包当前状态 ${pkg.status}，不能移交`, { status: pkg.status });
    }
    if (pkg.gatewayId === toGatewayId) {
      throw new DomainError('BAD_REQUEST', '目标网关与当前领取网关相同，无需移交');
    }
    const oldFence = pkg.fence;
    const fromGatewayId = pkg.gatewayId;
    const newFence = oldFence + 1;
    this.#append('PACKAGE_HANDOVER', {
      packageId: pkg.packageId,
      fromGatewayId,
      toGatewayId,
      oldFence,
      newFence,
      reason: cmd.reason || '运营强制移交',
      by: cmd.by || '运营方',
      at: now,
    }, now);
    // 投影此刻已指向新网关；#claimResponse 按新围栏派生新上传密钥，旧围栏 secret 失效
    return {
      packageId: pkg.packageId,
      ...this.#claimResponse(pkg, { idempotent: false }),
      handover: { fromGatewayId, toGatewayId, oldFence, newFence, preservedReceipts: pkg.mergedCount },
    };
  }

  // 网关分段上传执行/跳过/失败回执。原子校验 + 按包内序号合并 + 稳定检查点。
  uploadSegment(cmd, now) {
    const pkg = this.packages.get(cmd.packageId);
    if (!pkg) {
      throw new DomainError('PACKAGE_NOT_FOUND', `作业包 ${cmd.packageId} 不存在`, { packageId: cmd.packageId });
    }

    const reject = (code, reason, extra = {}) => {
      // 所有拒绝都留痕（含旧围栏重试），审计可查“失效回执被识别”的证据
      this.#recordRejection(pkg, code, reason, now, {
        fence: cmd.fence ?? null, segSeq: cmd.segSeq ?? null, gatewayId: cmd.gatewayId ?? null, details: extra,
      });
      throw new DomainError(code, reason, { packageId: pkg.packageId, ...extra });
    };

    // 0) 结构先解析，使得“完全相同的分段重传”能在任何状态闸之前被幂等识别
    //    （上传超时重试可能发生在包恰好完成关闭之后；已接受内容不重复计数）。
    const segSeq = Number(cmd.segSeq);
    if (!Number.isInteger(segSeq) || segSeq < 1) {
      return reject('BAD_REQUEST', 'segSeq 必须是从 1 开始的正整数');
    }
    if (!Array.isArray(cmd.items) || !cmd.items.length) {
      return reject('BAD_REQUEST', 'items 必须是非空回执数组');
    }
    const items = normalizeItems(cmd.items);
    const segmentHash = sha256Hex(canonicalJSON({ segSeq, items }));

    // 1) 围栏先于状态闸：旧领取者（含释放/移交前拿到的旧 secret）恢复联网后的
    //    任何重传都必须先被识别为“围栏失效”，而不是被关闭/过期语义掩盖。
    if (Number(cmd.fence) !== pkg.fence) {
      return reject('PACKAGE_FENCE_STALE',
        `围栏号 ${cmd.fence} 已失效，当前围栏为 ${pkg.fence}（作业包已被重新领取或移交）`, {
          providedFence: Number(cmd.fence), currentFence: pkg.fence, ownerGatewayId: pkg.gatewayId,
        });
    }
    if (cmd.gatewayId && pkg.gatewayId !== String(cmd.gatewayId)) {
      return reject('PACKAGE_FENCE_STALE', '上传网关与当前领取网关不一致', {
        providedGatewayId: cmd.gatewayId, ownerGatewayId: pkg.gatewayId,
      });
    }

    if (pkg.status === 'CLOSED') {
      // 当前围栏下已接受分段的逐字节重传（上传超时重试）幂等放行；任何新内容明确拒绝。
      if (pkg.segments.has(segmentHash)) {
        return { duplicate: true, segmentHash, segSeq, fence: pkg.fence, checkpoint: this.checkpoint(pkg) };
      }
      return reject('PACKAGE_CLOSED', `作业包已关闭（${pkg.closeReason}），拒绝任何回执分段`, { reason: pkg.closeReason });
    }
    if (pkg.status === 'EXPIRED') {
      return reject('PACKAGE_EXPIRED', '作业包已过期且未被领取，拒绝回执分段', { validUntil: pkg.validUntil });
    }
    if (pkg.status !== 'CLAIMED') {
      return reject('PACKAGE_NOT_CLAIMED', `作业包当前状态 ${pkg.status}，未被领取，拒绝回执分段`, { status: pkg.status });
    }

    // 2) 完全相同的分段重传：按规范化内容哈希幂等，不重复计数，返回同一检查点
    if (pkg.segments.has(segmentHash)) {
      return { duplicate: true, segmentHash, segSeq, fence: pkg.fence, checkpoint: this.checkpoint(pkg) };
    }

    // 3) 逐条校验（越界序号 / 越界设备 / 非法结果 / 同序号内容变化）；任一条失败整段拒绝
    for (const it of items) {
      if (!Number.isInteger(it.seq) || it.seq < 1 || it.seq > pkg.instructions.length) {
        return reject('SEQ_OUT_OF_RANGE', `包内序号 ${it.seq} 越界（合法范围 1..${pkg.instructions.length}）`, {
          seq: it.seq, maxSeq: pkg.instructions.length,
        });
      }
      const entry = pkg.instructions[it.seq - 1];
      if (entry.deviceId !== it.deviceId) {
        return reject('DEVICE_NOT_IN_PACKAGE', `序号 ${it.seq} 对应的设备应为 ${entry.deviceId}，实际 ${it.deviceId}`, {
          seq: it.seq, expectedDevice: entry.deviceId, providedDevice: it.deviceId,
        });
      }
      if (!PACKAGE_OUTCOMES.includes(it.outcome)) {
        return reject('BAD_REQUEST', `回执结果必须是 ${PACKAGE_OUTCOMES.join('/')}`, { seq: it.seq, outcome: it.outcome });
      }
      const existing = pkg.receipts.get(it.seq);
      if (existing) {
        // 同序号内容相同 -> 跨分段幂等，不重复计数；内容变化 -> 明确拒绝（永不覆盖）
        if (existing.deviceId !== it.deviceId || receiptContentHash(existing) !== receiptContentHash(it)) {
          return reject('SEQ_CONTENT_CONFLICT',
            `序号 ${it.seq} 已有不同回执（${existing.outcome}），序号内容变化被拒绝，既有证据不可覆盖`, {
              seq: it.seq, existing: { outcome: existing.outcome, detail: existing.detail },
              attempted: { outcome: it.outcome, detail: it.detail },
            });
        }
      }
    }

    // 4) 分段序号冲突：同一围栏上传会话中，同 segSeq 之前必须是同一段内容
    const segKey = `${pkg.fence}:${segSeq}`;
    const priorHash = pkg.segSeqIndex.get(segKey);
    if (priorHash && priorHash !== segmentHash) {
      return reject('SEGMENT_SEQ_CONFLICT', `分段序号 ${segSeq} 在围栏 ${pkg.fence} 下已对应另一段不同内容，重传必须保持内容一致`, { segSeq, fence: pkg.fence });
    }

    // 5) 摘要（HMAC）：防篡改；不匹配则整段拒绝，不产生任何合并
    const expectedDigest = segmentDigest(
      this.keys.uploadSecretFor(pkg.keyId, pkg.packageId, pkg.fence),
      digestBody(pkg.packageId, pkg.fence, segSeq, items),
    );
    if (!cmd.digest || String(cmd.digest) !== expectedDigest) {
      return reject('DIGEST_MISMATCH', '分段摘要不匹配（HMAC-SHA256 校验失败，或使用了旧围栏的上传密钥）', {
        segSeq, expectedDigest, providedDigest: cmd.digest ?? null,
      });
    }

    // 6) 原子合并：只落新增序号（相同内容序号视为幂等重放）
    const merged = [];
    const idempotentSeqs = [];
    for (const it of items) {
      if (pkg.receipts.has(it.seq)) {
        idempotentSeqs.push(it.seq);
        continue;
      }
      merged.push(it);
    }

    this.#append('PACKAGE_SEGMENT_ACCEPTED', {
      packageId: pkg.packageId,
      fence: pkg.fence,
      gatewayId: pkg.gatewayId,
      segSeq,
      segmentHash,
      items,
      mergedSeqs: merged.map((it) => it.seq),
      idempotentSeqs,
      at: now,
    }, now);

    // 全部序号合并完成 -> 自动关闭（只读），此后任何上传得到 PACKAGE_CLOSED
    let autoClosed = false;
    if (pkg.mergedCount === pkg.instructions.length && pkg.status !== 'CLOSED') {
      this.#append('PACKAGE_CLOSED', {
        packageId: pkg.packageId,
        at: now,
        reason: 'COMPLETED',
      }, now);
      autoClosed = true;
    }

    return {
      accepted: true,
      segmentHash,
      segSeq,
      fence: pkg.fence,
      merged: merged.map((it) => ({ seq: it.seq, deviceId: it.deviceId, outcome: it.outcome })),
      idempotentSeqs,
      autoClosed,
      status: pkg.status,
      checkpoint: this.checkpoint(pkg),
    };
  }

  // 时钟推进：过期但从未领取（OPEN）的包确定过期；已领取包靠围栏继续收敛。
  expireDue(now) {
    // 到达或超过有效期即确定过期（validUntil 是领取窗口的端点；时钟恰好走到
    // 事件开始时刻的同一次推进中，未领取包立即失去领取资格）
    const expired = [];
    for (const pkg of this.packages.values()) {
      if (pkg.status === 'OPEN' && now >= pkg.validUntil) {
        this.#append('PACKAGE_EXPIRED', { packageId: pkg.packageId, at: now }, now);
        expired.push(pkg.packageId);
      }
    }
    return expired;
  }

  // 事件撤销：其下所有仍开放/已领取的作业包强制关闭（证据保留），上传得到明确拒绝。
  closeForEvent(eventId, reason, now) {
    const closed = [];
    for (const pkg of this.packages.values()) {
      if (pkg.eventId !== eventId) continue;
      if (pkg.status === 'CLOSED' || pkg.status === 'EXPIRED') continue;
      this.#append('PACKAGE_CLOSED', { packageId: pkg.packageId, at: now, reason }, now);
      closed.push(pkg.packageId);
    }
    return closed;
  }

  // ---------- 视图 ----------

  view(packageId) {
    const pkg = this.packages.get(packageId);
    if (!pkg) return null;
    const receipts = [...pkg.receipts.values()]
      .sort((a, b) => a.seq - b.seq)
      .map((r) => ({ ...r }));
    return {
      packageId: pkg.packageId,
      eventId: pkg.eventId,
      eventVersion: pkg.eventVersion,
      anchorSeq: pkg.anchorSeq,
      anchorHash: pkg.anchorHash,
      keyId: pkg.keyId,
      manifestHash: pkg.manifestHash,
      entriesHash: pkg.entriesHash,
      status: pkg.status,
      gatewayId: pkg.gatewayId,
      lastGatewayId: pkg.lastGatewayId,
      fence: pkg.fence,
      claimCount: pkg.claimCount,
      deviceCount: pkg.deviceIds.length,
      deviceIds: [...pkg.deviceIds],
      instructions: pkg.instructions.map((i) => ({ ...i })),
      issuedAt: pkg.issuedAt,
      issuedAtIso: iso(pkg.issuedAt),
      validUntil: pkg.validUntil,
      validUntilIso: iso(pkg.validUntil),
      createdBy: pkg.createdBy,
      receipts,
      checkpoint: this.checkpoint(pkg),
      closedAt: pkg.closedAt,
      closeReason: pkg.closeReason,
      history: pkg.history.map((h) => ({ ...h })),
    };
  }

  list() {
    return [...this.packages.keys()].map((id) => this.view(id));
  }

  // 独立验签：重算 manifest 规范哈希与 Ed25519 签名
  verify(packageId) {
    const pkg = this.packages.get(packageId);
    if (!pkg) return null;
    const manifestCanonical = canonicalJSON(pkg.manifest);
    const recomputedManifestHash = sha256Hex(manifestCanonical);
    const signatureValid = this.keys.verifyManifest(pkg.keyId, manifestCanonical, pkg.signature);
    const entriesRecomputed = sha256Hex(canonicalJSON(pkg.instructions));
    return {
      packageId: pkg.packageId,
      keyId: pkg.keyId,
      manifestHashMatches: recomputedManifestHash === pkg.manifestHash,
      storedManifestHash: pkg.manifestHash,
      recomputedManifestHash,
      entriesHashMatches: entriesRecomputed === pkg.entriesHash,
      signatureValid,
      anchored: { anchorSeq: pkg.anchorSeq, anchorHash: pkg.anchorHash },
      readOnly: true,
    };
  }
}

// 允许内核尚未注入密钥库时构造投影（重放 PACKAGE_KEY_PUBLISHED 前不应有包命令）。
function keyStoreGuard(keys) {
  return keys || {
    reconcile() {
      throw new Error('PackageKeyStore 尚未初始化');
    },
  };
}

export { PACKAGE_STATUSES };
