// 证据归档模块端到端场景（真实 HTTP，零依赖）：
//   有效导入出报告 → 哈希/签名错误被拒 → 重复导入返原结果 → 同分段异内容冲突隔离
//   → 多围栏合并不倒退检查点 → 旧围栏可查不充当进度 → 真实进程重启摘要/冲突不变
//   → 导出仅含脱敏证据（upload secret/私钥不泄露）。
//
// 用法：
//   node scripts/evidence-e2e.mjs              自动拉起临时服务，演完即停（含真实进程重启）
//   BASE=http://localhost:8092 node scripts/evidence-e2e.mjs --external   对已运行的服务测试
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';

const SELF_URL = new URL('../evidence/pack.js', import.meta.url);
const { buildEnvelope, manifestHashOf, R, generateGatewayKeyPair } = await import(SELF_URL.href);

let BASE = process.env.BASE || '';
const external = process.argv.includes('--external');
const SECRET = 'e2e-upload-secret-' + 'a'.repeat(20); // 固定值，便于泄露检查
let child = null;
let tmpDir = null;
// 任何退出路径都回收子服务，避免残留进程占用随机端口。
function cleanupProcess() {
  try { child?.kill('SIGKILL'); } catch { /* ignore */ }
}
process.on('exit', cleanupProcess);
process.on('SIGINT', () => { cleanupProcess(); process.exit(130); });
process.on('SIGTERM', () => { cleanupProcess(); process.exit(143); });
let pass = 0, fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log('  ✅', name, extra); }
  else { fail++; console.log('  ❌', name, extra); }
}
function eq(name, a, b) { check(name, a === b, `${JSON.stringify(a)} ${a === b ? '==' : '!='} ${JSON.stringify(b)}`); }

async function api(path, { method, body, secret = SECRET, headers = {} } = {}) {
  const method0 = method || (body === undefined ? 'GET' : 'POST');
  const h = {};
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (secret !== null) h['X-Upload-Secret'] = secret;
  Object.assign(h, headers);
  const res = await fetch(BASE + path, { method: method0, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) throw Object.assign(new Error(typeof data === 'object' ? data.error : text), {
    status: res.status, code: data?.code, raw: data,
  });
  return data;
}
async function expectCode(name, fn, code) {
  try { await fn(); check(name, false, '未拒绝'); }
  catch (e) { check(name, e.code === code, `${e.code || e.status}（期望 ${code}）`); }
}
async function apiRaw(path, method = 'GET') {
  const res = await fetch(BASE + path, { method });
  return { status: res.status, text: await res.text() };
}

async function startServer() {
  if (!tmpDir) tmpDir = mkdtempSync(join(tmpdir(), 'evidence-e2e-'));
  child = spawn(process.execPath, ['evidence/server.js'], {
    env: { ...process.env, EVIDENCE_DIR: tmpDir, EVIDENCE_PORT: '0', EVIDENCE_HOST: '127.0.0.1', EVIDENCE_UPLOAD_SECRET: SECRET, EVIDENCE_DEMO: '1' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  let buf = '';
  const port = await new Promise((resolve, reject) => {
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/http:\/\/localhost:(\d+)\//);
      if (m) resolve(Number(m[1]));
    });
    child.on('exit', (code) => reject(new Error('服务提前退出 code=' + code)));
    setTimeout(() => reject(new Error('服务启动超时')), 5000);
  });
  BASE = `http://127.0.0.1:${port}`;
  await new Promise((r) => setTimeout(r, 50));
}
async function stopServer() {
  if (!child) return;
  child.kill('SIGTERM');
  await Promise.race([
    once(child, 'exit').catch(() => {}),
    new Promise((r) => setTimeout(r, 1500)),
  ]);
  if (child.exitCode === null && child.signalCode === null) {
    try { child.kill('SIGKILL'); } catch { /* 已退出 */ }
    await once(child, 'exit').catch(() => {});
  }
  child = null;
}
async function restartServer() {
  await stopServer();
  await startServer();
}

// ---------- 网关材料 ----------
const gwA = generateGatewayKeyPair();
const gwB = generateGatewayKeyPair();
const KID_A = 'gw-key-1', KID_B = 'gw-key-1';

const PKG = 'PKG-E2E-001';
function manifestEntries() {
  return [
    { seq: 0, deviceId: 'DEV-1' },
    { seq: 1, deviceId: 'DEV-2' },
    { seq: 2, deviceId: 'DEV-3' },
  ];
}
function env(packageId, gateway, keyId, priv, records) {
  return buildEnvelope({ packageId, gatewayId: gateway, keyId, records, privateKeyPem: priv });
}
function tamper(envelope, mutate) {
  const clone = JSON.parse(JSON.stringify(envelope));
  mutate(clone);
  return clone; // 不重算 hash/signature
}

console.log('① 服务启动 / 网关登记');
if (!external) await startServer();
else BASE = BASE || 'http://localhost:8092';

await api('/api/gateways', { body: { gatewayId: 'gw-A', keyId: KID_A, publicKeyPem: gwA.publicKeyPem } });
await api('/api/gateways', { body: { gatewayId: 'gw-B', keyId: KID_B, publicKeyPem: gwB.publicKeyPem } });
// 重复登记同公钥幂等
await api('/api/gateways', { body: { gatewayId: 'gw-A', keyId: KID_A, publicKeyPem: gwA.publicKeyPem } });
// 私钥投递必须被拒
await expectCode('注册接口拒绝私钥材料', () =>
  api('/api/gateways', { body: { gatewayId: 'x', keyId: 'k', publicKeyPem: gwA.privateKeyPem } }), 'PRIVATE_KEY_REJECTED');
// 无 secret 401
await expectCode('无 X-Upload-Secret 被拒', () => api('/api/gateways', { secret: null, body: {} }), 'UNAUTHORIZED');
await expectCode('错误 X-Upload-Secret 被拒', () => api('/api/gateways', { secret: 'wrong-secret', body: {} }), 'UNAUTHORIZED');

console.log('② 有效证据包导入并生成报告');
const T = '2026-10-01T08:00:00Z';
const manifest = { entries: manifestEntries(), issuedAt: T, validUntil: '2026-10-03T00:00:00Z' };
const mHash = manifestHashOf(manifest);
const env1 = env(PKG, 'gw-A', KID_A, gwA.privateKeyPem, [
  R.manifest(T, manifest, mHash),
  R.fence(T, 'fence-A', 1, 'CREATED', null, '首次领取'),
  R.segment(T, 'fence-A', 1, 1, [
    { seq: 0, deviceId: 'DEV-1', outcome: 'EXECUTED', note: 'ok' },
    { seq: 1, deviceId: 'DEV-2', outcome: 'SKIPPED' },
  ]),
  R.checkpoint(T, 'fence-A', 1, 1, { EXECUTED: 1, SKIPPED: 1, FAILED: 0 }),
]);
const r1 = await api(`/api/packages/${PKG}/import`, { body: env1 });
eq('首封导入 ACCEPTED', r1.result, 'ACCEPTED');
eq('接受 4 条', r1.disposition.recordsAccepted, 4);
const report1 = await api(`/api/packages/${PKG}/report`);
check('报告生成且有摘要', /^[0-9a-f]{64}$/.test(report1.reportDigest), report1.reportDigest);
eq('当前围栏 v1', report1.currentFence.version, 1);
eq('当前检查点 lastSeq=1', report1.currentProgress.lastSeq, 1);
eq('时间线 4 条且首条是 manifest', report1.timeline[0].type, 'MANIFEST_ARCHIVED');
check('时间线确定排序（围栏→分段→检查点）',
  report1.timeline.map((x) => x.type).join(',') === 'MANIFEST_ARCHIVED,FENCE_CREATED,SEGMENT_ACCEPTED,CHECKPOINT');
const digest1 = report1.reportDigest;

console.log('③ 签名或哈希错误被拒绝');
// 哈希被改（记录内容篡改但不重算）
const badHash = tamper(env1, (c) => { c.records[2].entries[0].outcome = 'FAILED'; });
await expectCode('篡改分段内容 → ENVELOPE_HASH_MISMATCH', () =>
  api(`/api/packages/${PKG}/import`, { body: badHash }), 'ENVELOPE_HASH_MISMATCH');
// 签名错误（重算哈希但不重签）
const badSig = JSON.parse(JSON.stringify(env1));
{
  const { canonicalJSON } = await import('../evidence/hashing.js');
  const { createHash } = await import('node:crypto');
  badSig.records[2].entries[0].note = 'changed';
  badSig.envelopeHash = createHash('sha256').update(canonicalJSON({
    schema: badSig.schema, packageId: badSig.packageId, gatewayId: badSig.gatewayId,
    keyId: badSig.keyId, records: badSig.records,
  })).digest('hex');
}
await expectCode('改内容重算哈希但不重签 → SIGNATURE_INVALID', () =>
  api(`/api/packages/${PKG}/import`, { body: badSig }), 'SIGNATURE_INVALID');
// 用错误私钥（gw-B 签 gw-A 信封）
const wrongSigner = env(PKG, 'gw-A', KID_A, gwB.privateKeyPem, env1.records);
await expectCode('他网密钥代签 → SIGNATURE_INVALID', () =>
  api(`/api/packages/${PKG}/import`, { body: wrongSigner }), 'SIGNATURE_INVALID');
// 未知网关
const envUnknown = env(PKG, 'gw-X', 'k', gwA.privateKeyPem, env1.records);
await expectCode('未知网关 → GATEWAY_UNKNOWN', () =>
  api(`/api/packages/${PKG}/import`, { body: envUnknown }), 'GATEWAY_UNKNOWN');
// manifest hash 不自洽
const badManifest = env(PKG, 'gw-A', KID_A, gwA.privateKeyPem, [
  R.manifest(T, { entries: manifestEntries(), issuedAt: T }, 'f'.repeat(64)),
]);
await expectCode('manifestHash 不自洽 → MANIFEST_HASH_MISMATCH', () =>
  api(`/api/packages/${PKG}/import`, { body: badManifest }), 'MANIFEST_HASH_MISMATCH');
// 越界设备/序号
const badRange = env(PKG, 'gw-A', KID_A, gwA.privateKeyPem, [
  R.segment(T, 'fence-A', 1, 2, [{ seq: 0, deviceId: 'DEV-2', outcome: 'EXECUTED' }]),
]);
await expectCode('设备与清单序号不符 → DEVICE_NOT_IN_PACKAGE', () =>
  api(`/api/packages/${PKG}/import`, { body: badRange }), 'DEVICE_NOT_IN_PACKAGE');
const badSeq = env(PKG, 'gw-A', KID_A, gwA.privateKeyPem, [
  R.segment(T, 'fence-A', 1, 2, [{ seq: 9, deviceId: 'DEV-1', outcome: 'EXECUTED' }]),
]);
await expectCode('序号越界 → SEQ_OUT_OF_RANGE', () =>
  api(`/api/packages/${PKG}/import`, { body: badSeq }), 'SEQ_OUT_OF_RANGE');
// 围栏跳号
const gapEnv = env(PKG, 'gw-A', KID_A, gwA.privateKeyPem, [
  R.fence(T, 'fence-A', 4, 'CREATED', null, '跳号'),
]);
await expectCode('围栏版本跳号 → FENCE_VERSION_GAP', () =>
  api(`/api/packages/${PKG}/import`, { body: gapEnv }), 'FENCE_VERSION_GAP');
// 被拒证据不影响摘要
const reportAfterRejects = await api(`/api/packages/${PKG}/report`);
eq('拒绝不改变报告摘要', reportAfterRejects.reportDigest, digest1);

console.log('④ 重复导入返回原归档结果');
const dup = await api(`/api/packages/${PKG}/import`, { body: env1 });
check('重复标记 duplicate=true', dup.duplicate === true);
eq('重复返首次 importId', dup.importId, r1.importId);
eq('重复返首次时间', dup.firstImportedAt, r1.importedAt);
eq('重复信封首次结果在 disposition 中', dup.disposition.result, 'ACCEPTED');
eq('首次裁决 ACCEPTED', dup.disposition.result, 'ACCEPTED');
eq('首次接受数不变', dup.disposition.recordsAccepted, 4);
const reportAfterDup = await api(`/api/packages/${PKG}/report`);
eq('重复导入摘要不变', reportAfterDup.reportDigest, digest1);

console.log('⑤ 同围栏同分段号不同内容 → 冲突隔离，不覆盖');
// 同分段号 seg2，先导入正常一份
const env2 = env(PKG, 'gw-B', KID_B, gwB.privateKeyPem, [
  R.segment('2026-10-01T09:00:00Z', 'fence-A', 1, 2, [
    { seq: 2, deviceId: 'DEV-3', outcome: 'EXECUTED', note: 'gw-B 首次' },
  ]),
]);
const r2 = await api(`/api/packages/${PKG}/import`, { body: env2 });
eq('seg2 首次 ACCEPTED', r2.result, 'ACCEPTED');
// 同槽位不同内容（不同 outcome）
const env2conflict = env(PKG, 'gw-A', KID_A, gwA.privateKeyPem, [
  R.segment('2026-10-01T09:05:00Z', 'fence-A', 1, 2, [
    { seq: 2, deviceId: 'DEV-3', outcome: 'FAILED', note: 'gw-A 说失败' },
  ]),
]);
const r2c = await api(`/api/packages/${PKG}/import`, { body: env2conflict });
eq('异内容信封结果 CONFLICTS', r2c.result, 'CONFLICTS');
eq('冲突 1 条', r2c.disposition.recordsConflicted, 1);
eq('冲突原因 SEGMENT_CONTENT_CONFLICT', r2c.disposition.conflicts[0].reason, 'SEGMENT_CONTENT_CONFLICT');
// 已存证据未被覆盖：报告时间线中 seg2 仍是 gw-B 的 EXECUTED
const reportC = await api(`/api/packages/${PKG}/report`);
const seg2 = reportC.timeline.find((t) => t.type === 'SEGMENT_ACCEPTED' && t.segSeq === 2);
eq('已存 seg2 网关不变（未覆盖）', seg2.gatewayId, 'gw-B');
eq('已存 seg2 内容不变 EXECUTED', seg2.entries[0].outcome, 'EXECUTED');
eq('冲突列表 1 条', reportC.conflicts.length, 1);
eq('冲突条目保留外来指纹', /^[0-9a-f]{64}$/.test(reportC.conflicts[0].fingerprint), true);
check('冲突同时记录已存指纹', Boolean(reportC.conflicts[0].existingFingerprint));
// 冲突信封再次导入：仍是首次裁决（CONFLICTS 幂等）
const dupConflict = await api(`/api/packages/${PKG}/import`, { body: env2conflict });
check('冲突信封重复导入 duplicate=true', dupConflict.duplicate === true);
eq('冲突信封重复导入仍记 CONFLICTS', dupConflict.disposition.result, 'CONFLICTS');
const reportC2 = await api(`/api/packages/${PKG}/report`);
eq('冲突不重复入账（仍 1 条）', reportC2.conflicts.length, 1);

console.log('⑥ 多围栏合并，当前检查点不倒退；旧围栏可查');
// 新围栏 v2（强制移交，围栏只增），seg3 + 检查点 lastSeq=2（≥ v1 的 1）
const env3 = env(PKG, 'gw-B', KID_B, gwB.privateKeyPem, [
  R.fence('2026-10-01T10:00:00Z', 'fence-B', 2, 'CREATED', 1, '强制移交，upload-secret=' + SECRET),
  R.segment('2026-10-01T10:10:00Z', 'fence-B', 2, 3, [
    { seq: 2, deviceId: 'DEV-3', outcome: 'EXECUTED', note: 'v2 续作' },
  ]),
  R.checkpoint('2026-10-01T10:15:00Z', 'fence-B', 2, 2, { EXECUTED: 2, SKIPPED: 1, FAILED: 0 }),
]);
const r3 = await api(`/api/packages/${PKG}/import`, { body: env3 });
eq('v2 导入 ACCEPTED', r3.result, 'ACCEPTED');
const report3 = await api(`/api/packages/${PKG}/report`);
eq('当前围栏升到 v2', report3.currentFence.version, 2);
eq('当前检查点 v2 lastSeq=2', report3.currentProgress.lastSeq, 2);
check('时间线跨围栏确定排序', report3.timeline.some((t) => t.type === 'FENCE_CREATED' && t.fenceVersion === 2));

// v2 尝试倒退检查点 lastSeq=0 → CHECKPOINT_REGRESSED 隔离
const envRegress = env(PKG, 'gw-B', KID_B, gwB.privateKeyPem, [
  R.checkpoint('2026-10-01T11:00:00Z', 'fence-B', 2, 0, { EXECUTED: 0, SKIPPED: 0, FAILED: 0 }),
]);
const rReg = await api(`/api/packages/${PKG}/import`, { body: envRegress });
eq('倒退检查点进入冲突', rReg.disposition.conflicts[0]?.reason, 'CHECKPOINT_REGRESSED');
const reportR = await api(`/api/packages/${PKG}/report`);
eq('当前水位不倒退仍为 2', reportR.currentProgress.lastSeq, 2);

// v3 关闭 v2 围栏，再开 v3（高版本无检查点 → 沿用 v2 水位，标记 carried）
const env4 = env(PKG, 'gw-A', KID_A, gwA.privateKeyPem, [
  R.fence('2026-10-01T12:00:00Z', 'fence-B', 2, 'CLOSED', 1, 'v2 完成'),
  R.fence('2026-10-01T12:05:00Z', 'fence-C', 3, 'CREATED', 2, '再移交'),
]);
await api(`/api/packages/${PKG}/import`, { body: env4 });
const report4 = await api(`/api/packages/${PKG}/report`);
eq('当前围栏 v3', report4.currentFence.version, 3);
check('v3 无检查点时沿用 v2 水位',
  report4.currentProgress.fenceVersion === 2 && report4.currentProgress.carried === true &&
  report4.currentProgress.lastSeq === 2);
eq('v2 标记已关闭', report4.fences.find((f) => f.version === 2).closedAt, '2026-10-01T12:00:00Z');

// 旧围栏证据可查但明确不是当前进度
const oldV1 = await api(`/api/packages/${PKG}/fences/1`);
eq('旧围栏 v1 可查询', oldV1.fence.version, 1);
check('v1 标记非当前围栏', oldV1.isCurrentFence === false);
check('提示旧围栏不充当进度', /不得作为当前进度/.test(oldV1.note));
eq('v1 分段证据仍在', oldV1.segments.length, 2); // seg1（gw-A）+ seg2（gw-B）
const seg1Old = oldV1.segments.find((s) => s.segSeq === 1);
eq('旧围栏 seg1 内容保留', seg1Old.entries[0].outcome, 'EXECUTED');

console.log('⑦ 哈希链独立核验');
const chain = await api(`/api/chain/verify`);
const c = chain.packages[PKG];
eq('ledger 链 OK', c.chains.ledger.ok, true);
eq('quarantine 链 OK', c.chains.quarantine.ok, true);
eq('audit 链 OK', c.chains.audit.ok, true);

console.log('⑧ 重启后报告摘要与冲突列表不变（真实进程重启）');
const before = await api(`/api/packages/${PKG}/report`);
const digestBefore = before.reportDigest;
const conflictSeqsBefore = before.conflicts.map((x) => x.seq + ':' + x.reason + ':' + x.slot);
const listApi = await api('/api/packages');
const listBefore = listApi.packages.map((p) => ({ id: p.packageId, digest: p.reportDigest }));
if (!external) await restartServer();
else await api('/api/admin/restart');
// 重启后网关表/密钥 sidecar 持久，不需重新登记
const after = await api(`/api/packages/${PKG}/report`);
eq('重启后摘要相同', after.reportDigest, digestBefore);
eq('重启后冲突数相同', after.conflicts.length, before.conflicts.length);
eq('重启后冲突定位相同',
  JSON.stringify(after.conflicts.map((x) => x.seq + ':' + x.reason + ':' + x.slot)),
  JSON.stringify(conflictSeqsBefore));
eq('重启后当前围栏仍 v3', after.currentFence.version, 3);
eq('重启后水位仍 2', after.currentProgress.lastSeq, 2);
const listAfter = (await api('/api/packages')).packages.map((p) => ({ id: p.packageId, digest: p.reportDigest }));
eq('重启后包列表/摘要一致', JSON.stringify(listAfter), JSON.stringify(listBefore));
const chainAfter = (await api('/api/chain/verify')).packages[PKG];
eq('重启后三链仍 OK', chainAfter.chains.ledger.ok && chainAfter.chains.quarantine.ok && chainAfter.chains.audit.ok, true);
// 重启后重复导入仍幂等
const dupAfterRestart = await api(`/api/packages/${PKG}/import`, { body: env1 });
check('重启后重复导入仍返原结果', dupAfterRestart.duplicate === true && dupAfterRestart.importId === r1.importId);
eq('重启后重复导入摘要不变', (await api(`/api/packages/${PKG}/report`)).reportDigest, digestBefore);

console.log('⑨ 导出报告只含脱敏证据（无 secret / 私钥泄露）');
const txt = await apiRaw(`/api/packages/${PKG}/report.txt`);
const jsonExp = await apiRaw(`/api/packages/${PKG}/report.json`);
const html = await apiRaw(`/api/packages/${PKG}/report.html`);
for (const [name, r] of [['TXT', txt], ['JSON', jsonExp], ['HTML', html]]) {
  check(`${name} 可下载 200`, r.status === 200);
  check(`${name} 不含 upload secret 原文`, !r.text.includes(SECRET), `长度 ${r.text.length}`);
  check(`${name} 不含私钥 PEM`, !r.text.includes('PRIVATE KEY'));
  check(`${name} 含脱敏标注`, r.text.includes('REDACTED') || /脱敏/.test(r.text));
}
const reportJson = JSON.parse(jsonExp.text);
check('JSON 导出带 redaction 标记', reportJson.redaction?.applied === true);
// fence v2 的 detail 里故意夹带 secret → 应被打码（导入的是已接受证据，导出时脱敏）
const v2 = reportJson.fences.find((f) => f.version === 2);
// 时间线中 FENCE_CREATED v2 的 detail 同样要脱敏
const fenceV2Event = reportJson.timeline.find((t) => t.type === 'FENCE_CREATED' && t.fenceVersion === 2);
check('自由文本中夹带的 upload secret 被打码', fenceV2Event.detail.includes('***REDACTED***'));
// 包列表 API
const listResp = await apiRaw('/api/packages');
check('包列表不含 secret', !listResp.text.includes(SECRET));
// 服务端日志文件不泄露 secret
if (!external) {
  const logPath = join(tmpDir, 'audit-server.log');
  if (existsSync(logPath)) {
    const logText = readFileSync(logPath, 'utf8');
    check('服务日志不含 upload secret 原文', !logText.includes(SECRET));
    check('服务日志不含 PRIVATE KEY', !logText.includes('PRIVATE KEY'));
  } else {
    check('服务日志文件存在', false, logPath);
  }
  // 原始证据链文件必须 0600（内部存储允许含原文，出口才脱敏）
  const { statSync } = await import('node:fs');
  for (const f of ['ledger.jsonl', 'quarantine.jsonl', 'audit.jsonl']) {
    const mode = statSync(join(tmpDir, 'packages', PKG, f)).mode & 0o777;
    check(`${f} 权限为 0600`, mode === 0o600, String(mode));
  }
}
// 冲突证据导出也不泄露
const conflictsResp = await apiRaw(`/api/packages/${PKG}/conflicts`);
check('冲突列表不含 secret', !conflictsResp.text.includes(SECRET));
const timelineResp = await apiRaw(`/api/packages/${PKG}/timeline`);
check('时间线出口不含 secret（自由文本 detail/note 已脱敏）', !timelineResp.text.includes(SECRET));
const importsResp = await apiRaw(`/api/packages/${PKG}/imports`);
check('裁决历史不含 secret', !importsResp.text.includes(SECRET));

console.log('⑩ 第二个包独立成链');
const envP2 = env('PKG-E2E-002', 'gw-A', KID_A, gwA.privateKeyPem, [
  R.manifest(T, { entries: [{ seq: 0, deviceId: 'X-1' }], issuedAt: T }),
  R.fence(T, 'fence-X', 1, 'CREATED'),
]);
await api('/api/packages/PKG-E2E-002/import', { body: envP2 });
const p2 = await api('/api/packages/PKG-E2E-002/report');
check('独立包摘要生成', /^[0-9a-f]{64}$/.test(p2.reportDigest));

if (!external) {
  await stopServer();
  rmSync(tmpDir, { recursive: true, force: true });
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
if (fail) process.exitCode = 1;
