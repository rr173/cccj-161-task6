// 证据归档与冲突核验 · 真实 HTTP 端到端断言（含真实重启）。
// 覆盖：有效导入生成报告 / 签名·哈希链·摘要·清单·检查点错误拒绝 / 重复导入幂等 /
// 同分段不同内容冲突隔离 / 多围栏合并不倒退 / 重启后摘要与冲突列表不变 / 导出报告全脱敏。
// 用法：node archiver/e2e.mjs（自拉起服务，无需先启动）
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { createApp } = await import('./server.js');
const { generateIssuer, buildManifest, GatewayEvidenceBuilder, rehashChain } = await import('./gateway-sdk.js');
const { signCanonical } = await import('../src/package-crypto.js');
const { canonicalJSON } = await import('../src/util.js');

const dir = mkdtempSync(join(tmpdir(), 'ev-e2e-'));
const issuer = generateIssuer('pkg-key-demo');
const PKG = 'PKG-E2E-1';
const DEVICES = ['D-1', 'D-2', 'D-3', 'D-4'];

let pass = 0, fail = 0;
const check = (name, cond, extra = '') => {
  if (cond) { pass++; console.log('  ✅', name, extra); }
  else { fail++; console.log('  ❌', name, extra); }
};

async function freePort() {
  const { createServer } = await import('node:http');
  const s = createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const port = s.address().port;
  await new Promise((r) => s.close(r));
  return port;
}

let base;
const call = async (p, opts) => {
  const res = await fetch(base + p, opts);
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
};
const J = (body) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

// ---- 网关侧：构造证据包（SDK），经 HTTP /api/evidence/sign 演示签名 ----
function builderFor(gatewayId, deviceIds = DEVICES) {
  const { manifest, manifestHash, manifestSignature } = buildManifest(issuer, { packageId: PKG, deviceIds });
  return new GatewayEvidenceBuilder({
    packageId: PKG, gatewayId, manifest, manifestHash, manifestSignature,
    issuer: { keyId: issuer.keyId, publicKeyPem: issuer.publicKeyPem },
  });
}
const itemsFor = (b, seqs, outcome = 'EXECUTED') => seqs.map((seq) => ({
  seq, deviceId: b.manifest.instructions[seq - 1].deviceId, outcome, detail: null,
}));
const countsFor = (seqs, extra = {}) => ({
  total: DEVICES.length, merged: seqs.length, executed: seqs.length, skipped: 0, failed: 0,
  remaining: DEVICES.length - seqs.length, ...extra,
});
async function signViaApi(body) {
  const r = await call('/api/evidence/sign', J(body));
  return { ...body, signature: r.json.signature };
}
async function exportBundle(builder) {
  const body = builder.unsignedBody({ keyId: 'ev-key-1' });
  return signViaApi(body);
}
async function importBundle(bundle) {
  return call('/api/evidence/import', J({ bundle }));
}

async function startApp() {
  const port = await freePort();
  const app = await createApp({ logFile: join(dir, 'evidence.log'), keyFile: join(dir, 'keys.json') });
  await new Promise((r) => app.server.listen(port, '127.0.0.1', r));
  base = `http://127.0.0.1:${port}`;
  return app;
}

// ================= 第一次启动 =================
let app = await startApp();
console.log('场景 1：密钥与有效证据包导入 → 生成报告');
{
  const st = await call('/api/evidence/state');
  check('初始状态正常（OK，可写）', st.json.mode === 'OK' && st.json.readOnly === false);

  const key = await call('/api/evidence/keys/rotate', J({}));
  check('轮换证据签名密钥返回公钥', key.status === 201 && key.json.keyId === 'ev-key-1' && key.json.publicKeyPem.includes('BEGIN PUBLIC KEY'));
  const keys = await call('/api/evidence/keys');
  check('公钥列表不含私钥材料', keys.status === 200 && !JSON.stringify(keys.json).includes('PRIVATE KEY'));

  // gw-alpha：fence 1，分段1（序号1-2）+ 分段2（序号3-4）+ 检查点
  const b1 = builderFor('gw-alpha');
  b1.fenceChange({ fence: 1, kind: 'CLAIM' });
  b1.segment({ fence: 1, segSeq: 1, items: itemsFor(b1, [1, 2]) });
  b1.segment({ fence: 1, segSeq: 2, items: itemsFor(b1, [3, 4]) });
  b1.checkpoint({ fence: 1, appliedSeqs: [1, 2, 3, 4], counts: countsFor([1, 2, 3, 4]) });
  const bundle1 = await exportBundle(b1);
  const imp1 = await importBundle(bundle1);
  check('有效证据包导入 201', imp1.status === 201 && imp1.json.duplicate === false, JSON.stringify(imp1.json));
  check('回执含报告摘要与归档序号', /^[0-9a-f]{64}$/.test(imp1.json.reportDigest) && imp1.json.archiveSeq > 0);

  const rep = await call(`/api/evidence/packages/${PKG}/report`);
  check('报告已生成且摘要与回执一致', rep.status === 200 && rep.json.reportDigest === imp1.json.reportDigest);
  check('合并检查点覆盖全部序号', JSON.stringify(rep.json.report.mergedCheckpoint.appliedSeqs) === '[1,2,3,4]');
  check('当前围栏=1 且当前进度完整', rep.json.report.currentFence === 1 && rep.json.report.currentProgress.appliedSeqs.length === 4);

  globalThis.__bundle1 = bundle1;
  globalThis.__imp1 = imp1.json;
}

console.log('场景 2：签名 / 哈希链 / 摘要 / 清单 / 检查点错误被拒绝');
{
  const good = globalThis.__bundle1;
  // 签名错误
  const badSig = { ...good, signature: '0'.repeat(128) };
  const r1 = await importBundle(badSig);
  check('签名错误 → 422 EVIDENCE_SIGNATURE_INVALID', r1.status === 422 && r1.json.code === 'EVIDENCE_SIGNATURE_INVALID');

  // 哈希链内容被改写（重签名但链 hash 未更新）
  const tampered = JSON.parse(JSON.stringify(good));
  tampered.chain.find((e) => e.type === 'SEGMENT').payload.items[0].outcome = 'FAILED';
  const r2 = await importBundle(await signViaApi(tampered));
  check('链内容改写 → 422 EVIDENCE_CHAIN_BROKEN', r2.status === 422 && r2.json.code === 'EVIDENCE_CHAIN_BROKEN');

  // 分段摘要错误（链自洽）
  const badDigest = JSON.parse(JSON.stringify(good));
  badDigest.chain.find((e) => e.type === 'SEGMENT').payload.digest = 'f'.repeat(64);
  rehashChain(badDigest);
  const r3 = await importBundle(await signViaApi(badDigest));
  check('摘要错误 → 422 DIGEST_MISMATCH', r3.status === 422 && r3.json.code === 'DIGEST_MISMATCH');

  // 清单哈希错误
  const badManifest = JSON.parse(JSON.stringify(good));
  badManifest.manifestHash = 'e'.repeat(64);
  const r4 = await importBundle(await signViaApi(badManifest));
  check('清单哈希错误 → 422 MANIFEST_HASH_MISMATCH', r4.status === 422 && r4.json.code === 'MANIFEST_HASH_MISMATCH');

  // 检查点令牌错误
  const badCp = JSON.parse(JSON.stringify(good));
  badCp.chain.find((e) => e.type === 'CHECKPOINT').payload.checkpointToken = 'b'.repeat(64);
  rehashChain(badCp);
  const r5 = await importBundle(await signViaApi(badCp));
  check('检查点令牌错误 → 422 CHECKPOINT_TOKEN_MISMATCH', r5.status === 422 && r5.json.code === 'CHECKPOINT_TOKEN_MISMATCH');

  // 未登记密钥
  const rogue = generateIssuer('ev-rogue');
  const body = JSON.parse(JSON.stringify(good));
  delete body.signature;
  body.keyId = rogue.keyId;
  const r6 = await call('/api/evidence/import', J({
    bundle: { ...body, signature: signCanonical(rogue.privateKeyPem, canonicalJSON(body)) },
  }));
  check('未登记密钥 → 422 EVIDENCE_KEY_UNKNOWN', r6.status === 422 && r6.json.code === 'EVIDENCE_KEY_UNKNOWN');

  // 拒绝次数进入审计，且审计不含证据正文
  const log = await call('/api/evidence/log?type=EVIDENCE_REJECTED');
  check('拒绝审计已留痕（≥6 次）', log.json.count >= 6, `实际 ${log.json.count}`);
  check('审计记录不含 uploadSecret', !JSON.stringify(log.json).includes('uploadSecrets'));
}

console.log('场景 3：重复导入返回原归档结果');
{
  const again = await importBundle(globalThis.__bundle1);
  check('重复导入 200 且 duplicate=true', again.status === 200 && again.json.duplicate === true);
  check('回执与原归档结果一致', again.json.reportDigest === globalThis.__imp1.reportDigest
    && again.json.archiveSeq === globalThis.__imp1.archiveSeq);
  const list = await call('/api/evidence/packages');
  check('归档包数仍为 1（未重复计数）', list.json.packages.find((p) => p.packageId === PKG).bundles === 1);
}

console.log('场景 4：同围栏同分段号不同内容 → 冲突隔离，不覆盖已保存证据');
{
  const rival = builderFor('gw-beta');
  rival.fenceChange({ fence: 1, kind: 'CLAIM' });
  rival.segment({ fence: 1, segSeq: 1, items: itemsFor(rival, [1, 2], 'FAILED') });
  const imp = await importBundle(await exportBundle(rival));
  check('冲突证据包归档且报告 1 起冲突', imp.status === 201 && imp.json.conflicts.length === 1);
  check('该分段被隔离（quarantined=1）', imp.json.segments.quarantined === 1 && imp.json.segments.accepted === 0);

  const view = await call(`/api/evidence/packages/${PKG}`);
  const c = view.json.conflicts[0];
  check('冲突类型 SEGMENT_SEQ_CONFLICT', c.kind === 'SEGMENT_SEQ_CONFLICT' && c.fence === 1 && c.segSeq === 1);
  check('保留先归档证据（gw-alpha）', c.kept.gatewayId === 'gw-alpha' && c.kept.items[0].outcome === 'EXECUTED');
  check('隔离后到证据（gw-beta）', c.rejected.gatewayId === 'gw-beta' && c.rejected.items[0].outcome === 'FAILED');
  check('已保存回执未被覆盖', view.json.receipts.find((r) => r.seq === 1).outcome === 'EXECUTED');
  check('时间线可查询被隔离证据', view.json.timeline.some((t) => t.status === 'QUARANTINED' && t.conflictId === c.conflictId));
}

console.log('场景 5：多围栏按规则合并，当前检查点不倒退，旧围栏不计入当前进度');
{
  // gw-beta 经移交取得 fence 2，续传序号 3-4（内容与既有一致 → 归属转移）
  const b2 = builderFor('gw-beta');
  b2.fenceChange({ fence: 1, kind: 'CLAIM' });
  b2.fenceChange({ fence: 2, kind: 'HANDOVER', fromGatewayId: 'gw-alpha', toGatewayId: 'gw-beta' });
  b2.segment({ fence: 2, segSeq: 1, items: itemsFor(b2, [3, 4]) });
  b2.checkpoint({ fence: 2, appliedSeqs: [1, 2, 3, 4], counts: countsFor([1, 2, 3, 4]) });
  const before = (await call(`/api/evidence/packages/${PKG}/report`)).json;
  const imp = await importBundle(await exportBundle(b2));
  check('第二围栏证据包归档', imp.status === 201 && imp.json.segments.accepted === 1);

  const rep = (await call(`/api/evidence/packages/${PKG}/report`)).json.report;
  check('当前围栏升至 2', rep.currentFence === 2);
  check('当前进度只含当前围栏序号 [3,4]', JSON.stringify(rep.currentProgress.appliedSeqs) === '[3,4]');
  check('旧围栏回执作为继承证据可查', JSON.stringify(rep.inheritedProgress.seqs) === '[1,2]');
  check('合并检查点不倒退（仍覆盖 1-4）', JSON.stringify(rep.mergedCheckpoint.appliedSeqs) === '[1,2,3,4]'
    && rep.mergedCheckpoint.watermark === 4);
  check('旧围栏标记 HISTORICAL', rep.fences.find((f) => f.fence === 1).status === 'HISTORICAL');

  // 旧围栏迟到证据（fence 1 新分段号，序号 3-4 同内容）→ 幂等合并且检查点不倒退
  const late = builderFor('gw-alpha');
  late.fenceChange({ fence: 1, kind: 'CLAIM' });
  late.segment({ fence: 1, segSeq: 2, items: itemsFor(late, [3, 4]) });
  const impLate = await importBundle(await exportBundle(late));
  check('旧围栏迟到证据幂等（duplicate 分段）', impLate.status === 201 && impLate.json.segments.duplicates === 1);
  const after = (await call(`/api/evidence/packages/${PKG}/report`)).json.report;
  check('检查点仍未倒退', JSON.stringify(after.mergedCheckpoint.appliedSeqs) === '[1,2,3,4]' && after.currentFence === 2);
  globalThis.__digestBeforeRestart = (await call(`/api/evidence/packages/${PKG}/report`)).json.reportDigest;
  globalThis.__conflictsBeforeRestart = JSON.stringify((await call('/api/evidence/conflicts')).json.conflicts);
  void before;
}

console.log('场景 6：导出报告只包含脱敏后的证据');
{
  const res = await fetch(`${base}/api/evidence/packages/${PKG}/report/download?format=text`);
  const text = await res.text();
  check('文本报告可下载（attachment）', res.status === 200 && /attachment/.test(res.headers.get('content-disposition') || ''));
  check('报告含确定时间线与冲突章节', text.includes('证据时间线') && text.includes('冲突隔离区'));
  const resJson = await fetch(`${base}/api/evidence/packages/${PKG}/report/download?format=json`);
  const jsonText = await resJson.text();
  const secrets = Object.values(globalThis.__bundle1.uploadSecrets);
  check('导出报告不含任何原始 uploadSecret', secrets.every((s) => !text.includes(s) && !jsonText.includes(s)));
  check('导出报告不含私钥', !text.includes('PRIVATE KEY') && !jsonText.includes('PRIVATE KEY'));
  check('导出报告含脱敏声明', jsonText.includes('REDACTED'));
  const logRes = await fetch(`${base}/api/evidence/log?limit=500`);
  const logText = await logRes.text();
  check('归档日志不含任何原始 uploadSecret', secrets.every((s) => !logText.includes(s)));
}

// ================= 真实重启（同一数据目录新进程实例） =================
console.log('场景 7：进程重启后报告摘要与冲突列表不变');
{
  await new Promise((r) => app.server.close(r));
  app = await startApp(); // 同一 dir，从磁盘重放
  const st = await call('/api/evidence/state');
  check('重启后服务正常且链完整', st.json.mode === 'OK' && st.json.chain.ok === true);
  const rep = await call(`/api/evidence/packages/${PKG}/report`);
  check('报告摘要与重启前一致', rep.json.reportDigest === globalThis.__digestBeforeRestart,
    `${rep.json.reportDigest?.slice(0, 12)} vs ${globalThis.__digestBeforeRestart?.slice(0, 12)}`);
  const conflicts = await call('/api/evidence/conflicts');
  check('冲突列表与重启前一致', JSON.stringify(conflicts.json.conflicts) === globalThis.__conflictsBeforeRestart);
  const again = await importBundle(globalThis.__bundle1);
  check('重启后重复导入仍返回原回执', again.status === 200 && again.json.duplicate === true
    && again.json.reportDigest === globalThis.__imp1.reportDigest);
  const verify = await call('/api/evidence/verify');
  check('独立复验通过（链 + 报告摘要重算）', verify.json.ok === true
    && verify.json.reportChecks.find((x) => x.packageId === PKG).reportDigest === globalThis.__digestBeforeRestart);
}

await new Promise((r) => app.server.close(r));
console.log(`\n${pass} 项通过，${fail} 项失败`);
process.exit(fail ? 1 : 0);
