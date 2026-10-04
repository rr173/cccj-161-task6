// 离线作业包领域契约（node:test）：
// 制包只读验签 / 设备不可跨包 / 撤销与开始后的领取闸门 / 围栏轮换与旧围栏失效 /
// 分段乱序合并与稳定检查点 / 幂等重传 / 序号冲突 / 越界设备与序号 / 摘要不匹配 /
// 已关闭包拒绝 / 零进度释放与再领 / 强制移交保留证据 / 过期 / 重启重放不倒退。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Kernel } from '../src/kernel.js';
import { BASE_NOW } from '../src/seed.js';
import { EventStore } from '../src/store.js';
import { PackageKeyStore, segmentDigest, deriveUploadSecret } from '../src/package-crypto.js';
import { canonicalJSON } from '../src/util.js';

const I = 15 * 60 * 1000;
const START = Date.UTC(2026, 8, 16, 2, 0, 0);
const END = START + 16 * I;

function newKernel() {
  return Kernel.freshMemory(BASE_NOW);
}

function publish(k, { meterId = 'MP-1', targetKw = 40, start = START, end = END } = {}) {
  return k.dispatch({ type: 'PUBLISH_EVENT', meterId, targetKw, startMs: start, endMs: end }).event.id;
}

// 规范化分段条目（与服务端 normalizeItems 完全一致）
export function normItems(items) {
  return items.map((it) => ({
    seq: Number(it.seq),
    deviceId: String(it.deviceId),
    outcome: String(it.outcome),
    detail: it.detail == null ? null : String(it.detail),
  }));
}

// 用领取/移交响应中的 uploadSecret 为分段计算 HMAC 摘要
export function digestFor(claim, packageId, segSeq, items) {
  return segmentDigest(claim.upload.secret, canonicalJSON({
    packageId,
    fence: claim.fence,
    segSeq,
    items: normItems(items),
  }));
}

function issue(k, eventId, deviceIds, extra = {}) {
  return k.dispatch({ type: 'ISSUE_PACKAGE', eventId, deviceIds, ...extra }).package.packageId;
}

function claim(k, packageId, gatewayId) {
  return k.dispatch({ type: 'CLAIM_PACKAGE', packageId, gatewayId });
}

function upload(k, claim, packageId, segSeq, items, { gatewayId, fence, digest } = {}) {
  return k.dispatch({
    type: 'UPLOAD_PACKAGE_SEGMENT',
    packageId,
    fence: fence ?? claim.fence,
    segSeq,
    gatewayId: gatewayId ?? claim.gatewayId,
    items,
    digest: digest ?? digestFor(claim, packageId, segSeq, items),
  });
}

function expectCode(fn, code) {
  try {
    fn();
  } catch (e) {
    assert.equal(e.code, code, `期望 ${code}，实际 ${e.code}：${e.message}`);
    return e;
  }
  assert.fail(`应当抛出 ${code}`);
}

test('制包：只读清单锚定已发布事件固定版本，Ed25519 签名与条目摘要可独立复验', () => {
  const k = newKernel();
  const ev = publish(k);
  const out = k.dispatch({ type: 'ISSUE_PACKAGE', eventId: ev, deviceIds: ['DEV-2', 'DEV-1'] });
  const p = out.package;
  assert.equal(p.eventVersion, 1);
  assert.equal(p.anchorSeq > 0, true);
  // 序号按设备字典序稳定分配
  assert.deepEqual(p.instructions.map((x) => [x.seq, x.deviceId]), [[1, 'DEV-1'], [2, 'DEV-2']]);
  const v = k.packages.verify(p.packageId);
  assert.equal(v.manifestHashMatches, true);
  assert.equal(v.entriesHashMatches, true);
  assert.equal(v.signatureValid, true);
  assert.equal(v.anchored.anchorHash.length, 64);
});

test('同一事件下不同包不得重复包含同一设备（释放/关闭后也不解锁）', () => {
  const k = newKernel();
  const ev = publish(k);
  issue(k, ev, ['DEV-1']);
  expectCode(() => issue(k, ev, ['DEV-1']), 'DEVICE_ALREADY_PACKAGED');
  // 不同事件可以使用同一设备
  const ev2 = publish(k, {
    meterId: 'MP-1',
    start: START + 40 * I,
    end: START + 48 * I,
  });
  assert.doesNotThrow(() => issue(k, ev2, ['DEV-1', 'DEV-2']));
});

test('非本计量点设备不能进包', () => {
  const k = newKernel();
  const ev = publish(k, { meterId: 'MP-1' });
  expectCode(() => issue(k, ev, ['DEV-3']), 'METER_MISMATCH'); // DEV-3 属于 MP-2
});

test('事件撤销后不得再制新包；撤销级联强制关闭在途包，之后上传被明确拒绝', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1']);
  const c = claim(k, pkg, 'GW-A');
  const r = k.dispatch({ type: 'CANCEL_EVENT', eventId: ev, reason: '弃用' });
  assert.deepEqual(r.packagesClosed, [pkg]);
  assert.equal(k.packages.view(pkg).status, 'CLOSED');
  assert.equal(k.packages.view(pkg).closeReason, 'EVENT_RECALLED');
  expectCode(() => issue(k, ev, ['DEV-2']), 'PACKAGE_EVENT_NOT_CLAIMABLE');
  expectCode(
    () => upload(k, c, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }]),
    'PACKAGE_CLOSED',
  );
});

test('事件开始后不得领取新包（未领取包确定过期）', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1']);
  k.dispatch({ type: 'TICK', minutes: (START - k.now()) / 60000 });
  const view = k.packages.view(pkg);
  assert.equal(view.status, 'EXPIRED');
  expectCode(() => claim(k, pkg, 'GW-A'), 'PACKAGE_EXPIRED');
});

test('领取：递增围栏号 + 派生上传密钥；同网关重领幂等不轮换，异网关抢占被拒', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1']);
  const c1 = claim(k, pkg, 'GW-A');
  assert.equal(c1.fence, 1);
  assert.match(c1.upload.secret, /^[0-9a-f]{64}$/);
  const c1b = claim(k, pkg, 'GW-A');
  assert.equal(c1b.fence, 1);
  assert.equal(c1b.idempotent, true);
  expectCode(() => claim(k, pkg, 'GW-B'), 'PACKAGE_ALREADY_CLAIMED');
});

test('旧围栏回执在移交后失效，不能覆盖新领取者进度；新围栏可续传并完成', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1', 'DEV-2']);
  const c1 = claim(k, pkg, 'GW-A');
  upload(k, c1, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED', detail: 'a' }]);

  const h = k.dispatch({ type: 'HANDOVER_PACKAGE', packageId: pkg, toGatewayId: 'GW-B', reason: '失联' });
  assert.equal(h.fence, 2);
  assert.equal(h.handover.preservedReceipts, 1);
  // 旧网关拿旧 fence/旧 secret 重传 -> 围栏先拒绝
  const err = expectCode(
    () => upload(k, c1, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED', detail: 'a' }],
      { gatewayId: 'GW-A', fence: 1 }),
    'PACKAGE_FENCE_STALE',
  );
  assert.equal(err.details.currentFence, 2);

  // 旧 fence 数字 + 伪造摘要同样在围栏闸被拒（根本不进摘要校验）
  expectCode(
    () => upload(k, c1, pkg, 2, [{ seq: 2, deviceId: 'DEV-2', outcome: 'SKIPPED' }],
      { gatewayId: 'GW-A', fence: 1, digest: '00'.repeat(32) }),
    'PACKAGE_FENCE_STALE',
  );

  // 新网关补齐序号 2，旧证据保留，包自动关闭
  const r2 = upload(k, h, pkg, 1, [{ seq: 2, deviceId: 'DEV-2', outcome: 'SKIPPED', detail: 'b' }],
    { gatewayId: 'GW-B', fence: 2 });
  assert.equal(r2.autoClosed, true);
  assert.equal(r2.status, 'CLOSED');
  const view = k.packages.view(pkg);
  assert.equal(view.receipts[0].fence, 1); // 旧领取者证据保留
  assert.equal(view.receipts[1].fence, 2);
});

test('分段：乱序到达按包内序号合并，检查点令牌稳定且只依赖内容', () => {
  const k = newKernel();
  const ev = publish(k);
  // MP-1 只有 DEV-1/DEV-2；跨计量点的第三台用同事件的第二批次无法同包，
  // 这里用 DEV-1/DEV-2 两台 + 同设备不同分段覆盖乱序合并。
  const pkg = issue(k, ev, ['DEV-1', 'DEV-2']);
  const c = claim(k, pkg, 'GW-A');
  // 先传序号 2（乱序）
  const r1 = upload(k, c, pkg, 1, [{ seq: 2, deviceId: 'DEV-2', outcome: 'FAILED', detail: 'x' }]);
  assert.deepEqual(r1.checkpoint.appliedSeqs, [2]);
  assert.equal(r1.checkpoint.watermark, 0, '序号 2 先到，连续水位仍为 0');
  // 再传 1，水位推进到 2
  const r2 = upload(k, c, pkg, 2, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }]);
  assert.equal(r2.checkpoint.watermark, 2);
  assert.deepEqual(r2.checkpoint.appliedSeqs, [1, 2]);
  // 同一分段重传得到同一令牌
  const r2b = upload(k, c, pkg, 2, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }]);
  assert.equal(r2b.duplicate, true);
  assert.equal(r2b.checkpoint.checkpointToken, r2.checkpoint.checkpointToken);
});

test('完全相同的分段重传不重复计数；不同分段中相同序号相同内容幂等、不同内容冲突', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1', 'DEV-2']);
  const c = claim(k, pkg, 'GW-A');
  const seg = [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED', detail: 'kw=40' }];
  upload(k, c, pkg, 7, seg);
  // 同 segSeq + 同内容 -> duplicate
  const dup = upload(k, c, pkg, 7, seg);
  assert.equal(dup.duplicate, true);
  // 另一个分段号携带同序号同内容 -> 幂等序号，不新增计数
  const r3 = upload(k, c, pkg, 8, seg);
  assert.deepEqual(r3.idempotentSeqs, [1]);
  assert.equal(r3.checkpoint.counts.merged, 1);
  // 同序号不同内容 -> 明确拒绝，原证据不变
  expectCode(
    () => upload(k, c, pkg, 9, [{ seq: 1, deviceId: 'DEV-1', outcome: 'FAILED', detail: 'kw=99' }]),
    'SEQ_CONTENT_CONFLICT',
  );
  assert.equal(k.packages.view(pkg).receipts[0].outcome, 'EXECUTED');
  // 同分段号不同内容 -> 分段序号冲突
  expectCode(
    () => upload(k, c, pkg, 7, [{ seq: 2, deviceId: 'DEV-2', outcome: 'EXECUTED' }]),
    'SEGMENT_SEQ_CONFLICT',
  );
});

test('越界序号 / 越界设备 / 摘要不匹配：整段原子拒绝，不产生任何合并', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1', 'DEV-2']);
  const c = claim(k, pkg, 'GW-A');
  // 合法序号 + 越界序号同时出现 -> 全段拒绝，合法的也不合并
  expectCode(
    () => upload(k, c, pkg, 1, [
      { seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' },
      { seq: 9, deviceId: 'DEV-2', outcome: 'EXECUTED' },
    ]),
    'SEQ_OUT_OF_RANGE',
  );
  assert.equal(k.packages.view(pkg).checkpoint.counts.merged, 0);
  // 序号与设备不对应
  expectCode(
    () => upload(k, c, pkg, 2, [{ seq: 2, deviceId: 'DEV-1', outcome: 'EXECUTED' }]),
    'DEVICE_NOT_IN_PACKAGE',
  );
  // 篡改摘要（构造一个合法摘要再破坏它）
  const good = digestFor(c, pkg, 3, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }]);
  const bad = good.slice(0, -1) + (good.endsWith('0') ? '1' : '0');
  expectCode(
    () => upload(k, c, pkg, 3, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }], { digest: bad }),
    'DIGEST_MISMATCH',
  );
  assert.equal(k.packages.view(pkg).checkpoint.counts.merged, 0);
});

test('用旧围栏上传密钥算出的摘要无法通过（HMAC 主密钥按围栏派生）', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1', 'DEV-2']);
  const c1 = claim(k, pkg, 'GW-A');
  upload(k, c1, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }]);
  const h = k.dispatch({ type: 'HANDOVER_PACKAGE', packageId: pkg, toGatewayId: 'GW-B' });
  // 旧网关直接拿 c1 的 secret，但伪造 fence=2（绕过围栏闸）-> 摘要必不匹配
  const items = [{ seq: 2, deviceId: 'DEV-2', outcome: 'SKIPPED' }];
  const oldSecretDigest = digestFor(c1, pkg, 2, items);
  expectCode(
    () => upload(k, c1, pkg, 2, items, { gatewayId: 'GW-A', fence: 2, digest: oldSecretDigest }),
    'PACKAGE_FENCE_STALE', // 网关不匹配先拦
  );
  // 即便伪造网关，旧 secret 对 fence=2 的 HMAC 也不同：用正确网关 + 旧 secret 直接验摘要
  const view = k.packages.view(pkg);
  const oldSecretForFence2 = deriveUploadSecret(
    k.packageKeys.require(view.keyId).masterSecretHex, pkg, 1, // 显式旧 fence
  );
  const tampered = segmentDigest(oldSecretForFence2, canonicalJSON({
    packageId: pkg, fence: 2, segSeq: 2, items: normItems(items),
  }));
  // 网关一致、fence=2，但摘要是 fence=1 的密钥算的 -> DIGEST_MISMATCH
  const err = expectCode(
    () => k.dispatch({
      type: 'UPLOAD_PACKAGE_SEGMENT', packageId: pkg, fence: 2, segSeq: 2,
      gatewayId: 'GW-B', items, digest: tampered,
    }),
    'DIGEST_MISMATCH',
  );
  assert.notEqual(err.details.expectedDigest, tampered);
});

test('零进度可由领取网关释放并被他人重新领取（围栏递增）；已有进度只能强制移交', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1', 'DEV-2']);
  const c1 = claim(k, pkg, 'GW-A');
  // 非领取网关不能释放
  expectCode(
    () => k.dispatch({ type: 'RELEASE_PACKAGE', packageId: pkg, gatewayId: 'GW-B' }),
    'PACKAGE_FENCE_STALE',
  );
  k.dispatch({ type: 'RELEASE_PACKAGE', packageId: pkg, gatewayId: 'GW-A', reason: '换班' });
  assert.equal(k.packages.view(pkg).status, 'RELEASED');
  const c2 = claim(k, pkg, 'GW-B');
  assert.equal(c2.fence, 2, '重新领取围栏递增');

  upload(k, c2, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }], { gatewayId: 'GW-B', fence: 2 });
  // 有进度后自行释放被拒
  expectCode(
    () => k.dispatch({ type: 'RELEASE_PACKAGE', packageId: pkg, gatewayId: 'GW-B' }),
    'PACKAGE_PROGRESS_LOCKED',
  );
  // 运营强制移交：证据保留 + 围栏轮换
  const h = k.dispatch({ type: 'HANDOVER_PACKAGE', packageId: pkg, toGatewayId: 'GW-C', reason: '人工' });
  assert.equal(h.fence, 3);
  assert.equal(h.handover.preservedReceipts, 1);
  assert.equal(k.packages.view(pkg).receipts[0].fence, 2, '此前回执证据原样保留');
  assert.equal(k.packages.view(pkg).gatewayId, 'GW-C');
});

test('显式有效期：过期的 OPEN 包拒绝领取；有效期不得晚于事件开始', () => {
  const k = newKernel();
  const ev = publish(k);
  expectCode(() => issue(k, ev, ['DEV-1'], { validForMinutes: 999999 }), 'BAD_REQUEST');
  const pkg = issue(k, ev, ['DEV-1'], { validForMinutes: 30 });
  k.dispatch({ type: 'TICK', minutes: 45 });
  assert.equal(k.packages.view(pkg).status, 'EXPIRED');
  expectCode(() => claim(k, pkg, 'GW-A'), 'PACKAGE_EXPIRED');
});

test('包完成自动关闭后：已接受分段的完全重传（超时重试）幂等；新内容明确拒绝', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1']);
  const c = claim(k, pkg, 'GW-A');
  const seg = [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }];
  const r = upload(k, c, pkg, 1, seg);
  assert.equal(r.autoClosed, true);
  // 完全相同的分段重传 -> 幂等，不重复计数，返回同一检查点
  const dup = upload(k, c, pkg, 1, seg);
  assert.equal(dup.duplicate, true);
  assert.equal(dup.checkpoint.counts.merged, 1);
  // 旧围栏重传（内容相同但 fence 旧）-> 仍先被围栏闸拒绝
  expectCode(
    () => upload(k, c, pkg, 1, seg, { gatewayId: 'GW-A', fence: 99 }),
    'PACKAGE_FENCE_STALE',
  );
  // 不同分段号 + 不同内容（哪怕序号内容相同的跨段）对已关闭包 -> PACKAGE_CLOSED
  expectCode(() => upload(k, c, pkg, 2, seg), 'PACKAGE_CLOSED');
});

test('审计历史：制包/领取/合并/拒绝/移交/关闭全程留痕', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1']);
  const c = claim(k, pkg, 'GW-A');
  try { upload(k, c, pkg, 1, [{ seq: 9, deviceId: 'DEV-1', outcome: 'EXECUTED' }]); } catch { /* reject */ }
  upload(k, c, pkg, 2, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }]);
  const types = k.packages.view(pkg).history.map((h) => h.type);
  assert.deepEqual(types, ['ISSUED', 'CLAIMED', 'REJECTED', 'SEGMENT_ACCEPTED', 'CLOSED']);
  const rej = k.packages.view(pkg).history.find((h) => h.type === 'REJECTED');
  assert.equal(rej.code, 'SEQ_OUT_OF_RANGE');
  assert.equal(rej.fence, 1);
});

test('重启重放：领取关系、围栏、检查点令牌、回执次序逐字节一致（不倒退）', () => {
  const keys = new PackageKeyStore(null);
  const store1 = new EventStore(null);
  const k1 = new Kernel(store1, { packageKeys: keys });
  const ev = publish(k1);
  const pkg = issue(k1, ev, ['DEV-1', 'DEV-2']);
  const c1 = claim(k1, pkg, 'GW-A');
  upload(k1, c1, pkg, 2, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED', detail: 'r' }]);
  upload(k1, c1, pkg, 1, [{ seq: 2, deviceId: 'DEV-2', outcome: 'SKIPPED' }]);
  const before = k1.packages.view(pkg);
  const token = before.checkpoint.checkpointToken;

  // 用同一 store 重放（模拟重启）：上传密钥仍可由同一主密钥派生
  k1.replay();
  const after = k1.packages.view(pkg);
  assert.equal(after.gatewayId, 'GW-A');
  assert.equal(after.fence, 1);
  assert.equal(after.checkpoint.checkpointToken, token);
  assert.deepEqual(after.receipts.map((r) => [r.seq, r.deviceId, r.outcome, r.fence]),
    [[1, 'DEV-1', 'EXECUTED', 1], [2, 'DEV-2', 'SKIPPED', 1]]);
  assert.equal(after.status, 'CLOSED', '完成状态重放后保持');
});

test('重启重放 + 强制移交：进行中包的围栏轮换、证据保留与新上传密钥一致', () => {
  const keys = new PackageKeyStore(null);
  const store1 = new EventStore(null);
  const k1 = new Kernel(store1, { packageKeys: keys });
  const ev = publish(k1);
  const pkg = issue(k1, ev, ['DEV-1', 'DEV-2']);
  const c1 = claim(k1, pkg, 'GW-A');
  upload(k1, c1, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED', detail: 'r' }]);
  // 模拟“带进度重启”
  k1.replay();
  assert.equal(k1.packages.view(pkg).fence, 1);
  assert.equal(k1.packages.view(pkg).checkpoint.counts.merged, 1);
  // 运营强制移交
  const h = k1.dispatch({ type: 'HANDOVER_PACKAGE', packageId: pkg, toGatewayId: 'GW-B', reason: '网关失联' });
  assert.equal(h.fence, 2);
  assert.equal(h.handover.preservedReceipts, 1);
  // 再次重放，围栏 2 与新网关关系保持，围栏 2 的上传密钥仍可派生
  k1.replay();
  const view = k1.packages.view(pkg);
  assert.equal(view.fence, 2);
  assert.equal(view.gatewayId, 'GW-B');
  assert.equal(view.receipts[0].fence, 1, '旧证据保留');
  const secretAfter = k1.packageKeys.uploadSecretFor(view.keyId, pkg, 2);
  assert.equal(secretAfter, h.upload.secret);
  // 新网关用围栏 2 续传，检查点持续前进
  const r = upload(k1, h, pkg, 1, [{ seq: 2, deviceId: 'DEV-2', outcome: 'SKIPPED' }],
    { gatewayId: 'GW-B', fence: 2 });
  assert.equal(r.autoClosed, true);
  assert.equal(r.checkpoint.counts.merged, 2);
});

test('过期演示默认有效期=事件开始时刻；已领取包不会被到期任务误关闭（靠围栏收敛）', () => {
  const k = newKernel();
  const ev = publish(k);
  const pkg = issue(k, ev, ['DEV-1']);
  const c = claim(k, pkg, 'GW-A');
  // 越过开始时刻：事件激活，未领取包会过期，已领取的这个包仍 CLAIMED
  k.dispatch({ type: 'TICK', minutes: (START - k.now()) / 60000 });
  assert.equal(k.packages.view(pkg).status, 'CLAIMED');
  // 事件开始后仍不能换网关重领（只能移交）
  expectCode(() => claim(k, pkg, 'GW-B'), 'PACKAGE_ALREADY_CLAIMED');
  // 已领取者按围栏继续上传成功
  const r = upload(k, c, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }]);
  assert.equal(r.accepted, true);
});
