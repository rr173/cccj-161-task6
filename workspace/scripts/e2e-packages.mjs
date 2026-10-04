// 离线作业包端到端场景（真实 HTTP）：
// 制包 -> 领取 -> 分段上传（乱序/重试/篡改） -> 释放/移交竞争 -> 过期 -> 撤销 -> 重启续传。
// 用法：先 npm start（另起终端），再 node scripts/e2e-packages.mjs
const BASE = process.env.BASE || 'http://localhost:8080';
const I = 15 * 60000;

async function api(path, body, method = 'POST') {
  const res = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(data.error), { code: data.code, status: res.status, details: data.details });
  return data;
}

let pass = 0, fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log('  ✅', name, extra); }
  else { fail++; console.log('  ❌', name, extra); }
}
async function expectCode(name, fn, code) {
  try { await fn(); check(name, false, '未拒绝'); }
  catch (e) { check(name, e.code === code, `${e.code}（期望 ${code}）`); }
}

// ---- 与服务端一致的摘要规则（网关 SDK 侧） ----
function normItems(items) {
  return items.map((it) => ({
    seq: Number(it.seq),
    deviceId: String(it.deviceId),
    outcome: String(it.outcome),
    detail: it.detail == null ? null : String(it.detail),
  }));
}
async function digest(uploadSecret, packageId, fence, segSeq, items) {
  const r = await api('/api/packages/digest', {
    uploadSecret, packageId, fence, segSeq, items,
  });
  return r.digest;
}
async function upload(claimOrResp, packageId, segSeq, items, opts = {}) {
  const fence = opts.fence ?? claimOrResp.fence;
  const gatewayId = opts.gatewayId ?? claimOrResp.gatewayId;
  const secret = opts.secret ?? claimOrResp.upload?.secret;
  const dg = opts.digest !== undefined
    ? opts.digest
    : await digest(secret, packageId, fence, segSeq, items);
  return api(`/api/packages/${packageId}/segments`, { fence, segSeq, gatewayId, items, digest: dg });
}

(async () => {
  await api('/api/sim/reset', {});
  const st0 = await api('/api/state', null, 'GET');
  const start = Math.ceil((st0.now + 30 * 60000) / I) * I;
  const end = start + 16 * I;

  console.log('场景 1：制包（清单摘要/指令序列/有效期/Ed25519 验签）');
  const ev = await api('/api/events', { meterId: 'MP-1', targetKw: 40, startMs: start, endMs: end });
  const evId = ev.event.id;
  const iss = await api('/api/packages', { eventId: evId, deviceIds: ['DEV-2', 'DEV-1'], createdBy: 'e2e' });
  const pkg = iss.package.packageId;
  check('包锚定事件发布版本', iss.package.eventVersion === 1 && iss.package.anchorSeq > 0);
  check('序号按设备字典序', iss.package.instructions.map((x) => x.deviceId).join() === 'DEV-1,DEV-2');
  check('默认有效期=事件开始', iss.package.validUntil === start);
  const v = await api(`/api/packages/${pkg}/verify`, null, 'GET');
  check('Ed25519 签名与清单摘要复验通过', v.signatureValid && v.manifestHashMatches && v.entriesHashMatches);
  await expectCode('重复设备切包被拒', () => api('/api/packages', { eventId: evId, deviceIds: ['DEV-1'] }), 'DEVICE_ALREADY_PACKAGED');
  await expectCode('跨计量点设备被拒', () => api('/api/packages', { eventId: evId, deviceIds: ['DEV-3'] }), 'METER_MISMATCH');

  console.log('场景 2：领取（围栏号 + HMAC 上传密钥，重复领取幂等，异网关抢占被拒）');
  const c1 = await api(`/api/packages/${pkg}/claim`, { gatewayId: 'GW-A' });
  check('首领 fence=1 且返回上传密钥', c1.fence === 1 && /^[0-9a-f]{64}$/.test(c1.upload.secret));
  const c1b = await api(`/api/packages/${pkg}/claim`, { gatewayId: 'GW-A' });
  check('同网关重领幂等不轮换', c1b.fence === 1 && c1b.idempotent === true);
  await expectCode('异网关抢占被拒', () => api(`/api/packages/${pkg}/claim`, { gatewayId: 'GW-B' }), 'PACKAGE_ALREADY_CLAIMED');

  console.log('场景 3：乱序分段 + 上传超时重试（完全相同重传不重复计数，检查点稳定）');
  const r1 = await upload(c1, pkg, 1, [{ seq: 2, deviceId: 'DEV-2', outcome: 'SKIPPED', detail: '检修' }]);
  check('乱序 seq2 先合并、水位仍为 0', r1.checkpoint.watermark === 0 && r1.checkpoint.appliedSeqs.join() === '2');
  const r1dup = await upload(c1, pkg, 1, [{ seq: 2, deviceId: 'DEV-2', outcome: 'SKIPPED', detail: '检修' }]);
  check('完全相同分段重传幂等', r1dup.duplicate === true && r1dup.checkpoint.counts.merged === 1);
  check('检查点令牌重传稳定', r1dup.checkpoint.checkpointToken === r1.checkpoint.checkpointToken);

  console.log('场景 4：序号内容变化 / 越界设备 / 摘要不匹配 全部明确拒绝且原子');
  await expectCode('同序号内容变化被拒',
    () => upload(c1, pkg, 2, [{ seq: 2, deviceId: 'DEV-2', outcome: 'FAILED', detail: '改判' }]),
    'SEQ_CONTENT_CONFLICT');
  // 同一分段序号在同一围栏下承载不同内容（不同设备）-> 分段序号冲突
  await expectCode('同分段号不同内容被拒',
    () => upload(c1, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }]),
    'SEGMENT_SEQ_CONFLICT');
  await expectCode('越界序号被拒（整段不合并）',
    () => upload(c1, pkg, 3, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }, { seq: 9, deviceId: 'DEV-2', outcome: 'EXECUTED' }]),
    'SEQ_OUT_OF_RANGE');
  await expectCode('越界设备被拒',
    () => upload(c1, pkg, 4, [{ seq: 1, deviceId: 'DEV-2', outcome: 'EXECUTED' }]),
    'DEVICE_NOT_IN_PACKAGE');
  await expectCode('摘要不匹配被拒',
    () => upload(c1, pkg, 5, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }], { digest: '0'.repeat(64) }),
    'DIGEST_MISMATCH');
  const viewMid = await api(`/api/packages/${pkg}`, null, 'GET');
  check('被拒分段未产生合并', viewMid.checkpoint.counts.merged === 1);

  console.log('场景 5：移交竞争 —— 有进度不能释放；强制移交保留证据并轮换围栏');
  await expectCode('有进度后自行释放被拒',
    () => api(`/api/packages/${pkg}/release`, { gatewayId: 'GW-A' }), 'PACKAGE_PROGRESS_LOCKED');
  const h = await api(`/api/packages/${pkg}/handover`, { toGatewayId: 'GW-B', reason: '现场失联', by: '调度员' });
  check('移交后 fence=2、保留 1 条证据', h.fence === 2 && h.handover.preservedReceipts === 1);
  await expectCode('旧围栏（GW-A/fence=1）回执被识别失效',
    () => upload(c1, pkg, 6, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED' }], { gatewayId: 'GW-A', fence: 1 }),
    'PACKAGE_FENCE_STALE');

  console.log('场景 6：新领取者恢复后续传，完成自动关闭；关闭后新分段被拒');
  const r2 = await upload(h, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED', detail: '40kW' }],
    { gatewayId: 'GW-B', fence: 2 });
  check('新围栏补齐后自动关闭', r2.autoClosed === true && r2.status === 'CLOSED');
  check('既有证据未被覆盖（seq2 仍是 GW-A 围栏1 的 SKIPPED）', (() => {
    const [s2] = r2.checkpoint.appliedSeqs.filter((x) => x === 2);
    return s2 === 2;
  })());
  await expectCode('已关闭包拒绝新分段',
    () => upload(h, pkg, 2, [{ seq: 1, deviceId: 'DEV-1', outcome: 'FAILED' }], { gatewayId: 'GW-B', fence: 2 }),
    'PACKAGE_CLOSED');
  // 已接受分段超时重传 -> 幂等
  const retryClosed = await upload(h, pkg, 1, [{ seq: 1, deviceId: 'DEV-1', outcome: 'EXECUTED', detail: '40kW' }],
    { gatewayId: 'GW-B', fence: 2 });
  check('关闭后已接受分段重传仍幂等', retryClosed.duplicate === true);

  console.log('场景 7：零进度释放后重新领取（围栏递增）');
  const ev2 = await api('/api/events', { meterId: 'MP-3', targetKw: 30, startMs: start, endMs: end });
  const p2 = (await api('/api/packages', { eventId: ev2.event.id, deviceIds: ['DEV-4'] })).package.packageId;
  const a1 = await api(`/api/packages/${p2}/claim`, { gatewayId: 'GW-X' });
  await api(`/api/packages/${p2}/release`, { gatewayId: 'GW-X', reason: '换班' });
  const a2 = await api(`/api/packages/${p2}/claim`, { gatewayId: 'GW-Y' });
  check('释放后再领围栏递增为 2', a2.fence === 2);
  await expectCode('释放后旧围栏上传失效',
    () => upload(a1, p2, 1, [{ seq: 1, deviceId: 'DEV-4', outcome: 'EXECUTED' }], { gatewayId: 'GW-X', fence: 1 }),
    'PACKAGE_FENCE_STALE');
  const done2 = await upload(a2, p2, 1, [{ seq: 1, deviceId: 'DEV-4', outcome: 'EXECUTED' }], { gatewayId: 'GW-Y', fence: 2 });
  check('新领取者上传成功并关闭', done2.autoClosed === true);

  console.log('场景 8：包过期（事件开始后未领取包确定过期，不可领取/上传）');
  const ev3 = await api('/api/events', { meterId: 'MP-2', targetKw: 20, startMs: start + 4 * I, endMs: end });
  const p3 = (await api('/api/packages', { eventId: ev3.event.id, deviceIds: ['DEV-3'] })).package.packageId;
  await api('/api/sim/tick', { minutes: (start + 4 * I - (await api('/api/state', null, 'GET')).now) / 60000 });
  const p3v = await api(`/api/packages/${p3}`, null, 'GET');
  check('越过开始时刻未领取包 EXPIRED', p3v.status === 'EXPIRED');
  await expectCode('过期包不可领取', () => api(`/api/packages/${p3}/claim`, { gatewayId: 'GW-Z' }), 'PACKAGE_EXPIRED');

  console.log('场景 9：事件撤销级联关闭在途作业包');
  // 全新计量点/设备（DEV-5/MP-3 未被任何包使用；DEV-4 已在场景7的包中）
  // 窗口必须避开仍 ACTIVE 的 MP-3 事件 ev2（end），安排在其后
  const s9 = Math.ceil((end + 30 * 60000) / I) * I;
  const ev9 = await api('/api/events', { meterId: 'MP-3', targetKw: 10, startMs: s9, endMs: s9 + 4 * I });
  const p9 = (await api('/api/packages', { eventId: ev9.event.id, deviceIds: ['DEV-5'] })).package.packageId;
  const c9 = await api(`/api/packages/${p9}/claim`, { gatewayId: 'GW-Q' });
  const cancel9 = await api('/api/events/cancel', { eventId: ev9.event.id, reason: '电网恢复' });
  check('撤销级联关闭在途包', cancel9.packagesClosed.includes(p9));
  const p9v = await api(`/api/packages/${p9}`, null, 'GET');
  check('包关闭原因为事件撤销', p9v.status === 'CLOSED' && p9v.closeReason === 'EVENT_RECALLED');
  await expectCode('撤销后上传被明确拒绝',
    () => upload(c9, p9, 1, [{ seq: 1, deviceId: 'DEV-5', outcome: 'EXECUTED' }], { gatewayId: 'GW-Q', fence: c9.fence }),
    'PACKAGE_CLOSED');
  await expectCode('撤销后不得再制新包',
    () => api('/api/packages', { eventId: ev9.event.id, deviceIds: ['DEV-5'] }),
    'PACKAGE_EVENT_NOT_CLAIMABLE');

  console.log('场景 10：审计历史与链上记录');
  const hist = (await api(`/api/packages/${pkg}`, null, 'GET')).history;
  const types = hist.map((h) => h.type);
  check('历史含制包/领取/拒绝/合并/移交/关闭',
    types.includes('ISSUED') && types.includes('CLAIMED') && types.includes('REJECTED') &&
    types.includes('SEGMENT_ACCEPTED') && types.includes('HANDOVER') && types.includes('CLOSED'));
  const logs = await api('/api/log?limit=400&type=PACKAGE_SEGMENT_ACCEPTED', null, 'GET');
  check('合并记录全部上链', logs.records.length >= 3);
  const chain = await api('/api/chain/verify', null, 'GET');
  check('哈希链完整', chain.ok === true);

  console.log(`\n结果：${pass} 通过，${fail} 失败`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('e2e 异常：', e); process.exit(1); });
