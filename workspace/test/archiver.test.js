// 证据归档与冲突核验契约（node:test）：
// 有效导入生成报告 / 签名·哈希链·清单·摘要·检查点错误拒绝 / 重复导入幂等 /
// 同围栏同分段号冲突隔离不覆盖 / 跨围栏序号内容冲突隔离 / 多围栏合并不倒退 /
// 旧围栏不计入当前进度 / 重启重放摘要与冲突列表一致 / 脱敏不落盘不输出。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventStore } from '../src/store.js';
import { canonicalJSON } from '../src/util.js';
import { signCanonical } from '../src/package-crypto.js';
import { EvidenceArchive, EvidenceError, bundleHashOf } from '../archiver/evidence.js';
import { EvidenceKeyStore } from '../archiver/keys.js';
import {
  GatewayEvidenceBuilder,
  generateIssuer,
  buildManifest,
  demoUploadSecret,
  rehashChain,
} from '../archiver/gateway-sdk.js';

const PKG = 'PKG-T1';
const DEVICES = ['D-1', 'D-2', 'D-3', 'D-4'];

// 内存环境：归档引擎 + 已轮换证据密钥 + 演示签发方
function setup() {
  const store = new EventStore(null);
  const keys = new EvidenceKeyStore(null);
  const archive = new EvidenceArchive({ store, keys });
  archive.rotateKey('2026-10-01T00:00:00.000Z');
  const issuer = generateIssuer('pkg-key-demo');
  return { archive, store, keys, issuer };
}

// 构造网关证据构建器（清单已签发）
function builderFor(issuer, { packageId = PKG, gatewayId = 'gw-1', deviceIds = DEVICES } = {}) {
  const { manifest, manifestHash, manifestSignature } = buildManifest(issuer, { packageId, deviceIds });
  return new GatewayEvidenceBuilder({
    packageId, gatewayId, manifest, manifestHash, manifestSignature,
    issuer: { keyId: issuer.keyId, publicKeyPem: issuer.publicKeyPem },
  });
}

function itemsFor(builder, seqs, outcome = 'EXECUTED') {
  return seqs.map((seq) => ({
    seq, deviceId: builder.manifest.instructions[seq - 1].deviceId, outcome, detail: null,
  }));
}

function countsFor(total, seqs, { executed = seqs.length, skipped = 0, failed = 0 } = {}) {
  return { total, merged: seqs.length, executed, skipped, failed, remaining: total - seqs.length };
}

// 标准有效证据包：fence 1，分段1（序号1-2），分段2（序号3-4），检查点
function validBuilder(issuer, opts = {}) {
  const b = builderFor(issuer, opts);
  b.fenceChange({ fence: 1, kind: 'CLAIM' });
  b.segment({ fence: 1, segSeq: 1, items: itemsFor(b, [1, 2]) });
  b.segment({ fence: 1, segSeq: 2, items: itemsFor(b, [3, 4]) });
  b.checkpoint({ fence: 1, appliedSeqs: [1, 2, 3, 4], counts: countsFor(4, [1, 2, 3, 4]) });
  return b;
}

// 签名并导出（私钥不出归档引擎，测试经 signBundle 演示签名）
function exportBundle(archive, builder) {
  const body = builder.unsignedBody({ keyId: archive.keys.currentKeyId });
  const { signature } = archive.signBundle(body);
  return { ...body, signature };
}

// 改动正文后重算链并重新签名（精确触发某一类校验错误）
function resignTampered(archive, bundle, mutate, { rehash = true } = {}) {
  const copy = JSON.parse(JSON.stringify(bundle));
  mutate(copy);
  if (rehash) rehashChain(copy);
  const { signature } = archive.signBundle(copy);
  return { ...copy, signature };
}

function expectErr(code, fn) {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof EvidenceError, `应抛 EvidenceError，实际 ${err}`);
    assert.equal(err.code, code, `期望 ${code}，实际 ${err.code}: ${err.message}`);
    return err;
  }
  assert.fail(`应抛出 ${code}`);
}

test('有效证据包导入并生成报告（签名/哈希链/清单/摘要/检查点全部通过）', () => {
  const { archive } = setup();
  const bundle = exportBundle(archive, validBuilder(generateIssuer('pkg-key-demo')));
  const out = archive.importBundle(bundle);
  assert.equal(out.duplicate, false);
  assert.equal(out.packageId, PKG);
  assert.deepEqual(out.segments, { accepted: 2, duplicates: 0, quarantined: 0 });
  assert.equal(out.conflicts.length, 0);

  const { report, reportDigest } = archive.buildReport(PKG);
  assert.equal(reportDigest, out.reportDigest);
  assert.equal(report.currentFence, 1);
  assert.deepEqual(report.mergedCheckpoint.appliedSeqs, [1, 2, 3, 4]);
  assert.equal(report.mergedCheckpoint.watermark, 4);
  assert.equal(report.mergedCheckpoint.counts.executed, 4);
  assert.deepEqual(report.currentProgress.appliedSeqs, [1, 2, 3, 4]);
  assert.equal(report.conflicts.length, 0);
  assert.equal(report.timeline.filter((t) => t.type === 'SEGMENT').length, 2);
  assert.equal(report.verification.allSignaturesValid, true);
});

test('签名错误被拒绝（EVIDENCE_SIGNATURE_INVALID）并留审计，不落任何证据', () => {
  const { archive, store } = setup();
  const bundle = exportBundle(archive, validBuilder(generateIssuer('pkg-key-demo')));
  bundle.signature = '0'.repeat(128);
  expectErr('EVIDENCE_SIGNATURE_INVALID', () => archive.importBundle(bundle));
  assert.equal(archive.packages.size, 0);
  const rejected = store.all().filter((r) => r.type === 'EVIDENCE_REJECTED');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].payload.code, 'EVIDENCE_SIGNATURE_INVALID');
  // 审计记录不含证据包正文（杜绝 uploadSecret 泄露）
  assert.equal(rejected[0].payload.bundle, undefined);
});

test('未登记密钥签名被拒绝（EVIDENCE_KEY_UNKNOWN）', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  const b = validBuilder(issuer);
  const rogue = generateIssuer('ev-rogue'); // 未在归档服务登记
  const body = b.unsignedBody({ keyId: rogue.keyId });
  const bundle = { ...body, signature: signCanonical(rogue.privateKeyPem, canonicalJSON(body)) };
  expectErr('EVIDENCE_KEY_UNKNOWN', () => archive.importBundle(bundle));
});

test('哈希链断裂被拒绝（EVIDENCE_CHAIN_BROKEN）：内容改写 / 序号跳号 / prevHash 不衔接', () => {
  const { archive } = setup();
  const good = exportBundle(archive, validBuilder(generateIssuer('pkg-key-demo')));

  // 内容被改写（hash 未更新），重新签名后仍被链校验拦截
  const tampered = resignTampered(archive, good, (c) => {
    c.chain.find((e) => e.type === 'SEGMENT').payload.items[0].outcome = 'FAILED';
  }, { rehash: false });
  expectErr('EVIDENCE_CHAIN_BROKEN', () => archive.importBundle(tampered));

  // 序号跳号
  const skipped = resignTampered(archive, good, (c) => { c.chain[2].seq = 9; }, { rehash: false });
  expectErr('EVIDENCE_CHAIN_BROKEN', () => archive.importBundle(skipped));

  // prevHash 不衔接
  const broken = resignTampered(archive, good, (c) => { c.chain[1].prevHash = 'a'.repeat(64); }, { rehash: false });
  expectErr('EVIDENCE_CHAIN_BROKEN', () => archive.importBundle(broken));
  assert.equal(archive.packages.size, 0);
});

test('清单哈希 / 清单签名 / packageId 不一致被拒绝', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  const good = exportBundle(archive, validBuilder(issuer));

  const badHash = resignTampered(archive, good, (c) => { c.manifestHash = 'e'.repeat(64); });
  expectErr('MANIFEST_HASH_MISMATCH', () => archive.importBundle(badHash));

  const badSig = resignTampered(archive, good, (c) => { c.manifestSignature = 'f'.repeat(128); });
  expectErr('MANIFEST_SIGNATURE_INVALID', () => archive.importBundle(badSig));

  const badPkg = resignTampered(archive, good, (c) => { c.manifest.packageId = 'PKG-OTHER'; });
  expectErr('PACKAGE_ID_MISMATCH', () => archive.importBundle(badPkg));
});

test('分段摘要错误被拒绝（DIGEST_MISMATCH），缺上传密钥被拒绝（UPLOAD_SECRET_MISSING）', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  const good = exportBundle(archive, validBuilder(issuer));

  // 链自洽但分段 HMAC 错误
  const badDigest = resignTampered(archive, good, (c) => {
    c.chain.find((e) => e.type === 'SEGMENT').payload.digest = 'f'.repeat(64);
  });
  expectErr('DIGEST_MISMATCH', () => archive.importBundle(badDigest));

  // 用错误密钥计算的摘要同样不匹配
  const wrongSecret = resignTampered(archive, good, (c) => {
    c.uploadSecrets['1'] = demoUploadSecret(PKG, 99);
  });
  expectErr('DIGEST_MISMATCH', () => archive.importBundle(wrongSecret));

  // 未携带该围栏密钥
  const noSecret = resignTampered(archive, good, (c) => { c.uploadSecrets = {}; });
  expectErr('UPLOAD_SECRET_MISSING', () => archive.importBundle(noSecret));
});

test('检查点令牌错误被拒绝（CHECKPOINT_TOKEN_MISMATCH）', () => {
  const { archive } = setup();
  const good = exportBundle(archive, validBuilder(generateIssuer('pkg-key-demo')));
  const bad = resignTampered(archive, good, (c) => {
    c.chain.find((e) => e.type === 'CHECKPOINT').payload.checkpointToken = 'b'.repeat(64);
  });
  expectErr('CHECKPOINT_TOKEN_MISMATCH', () => archive.importBundle(bad));
});

test('序号越界 / 设备不符 / 围栏未声明 / 围栏倒退被拒绝', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  const good = exportBundle(archive, validBuilder(issuer));

  const outOfRange = resignTampered(archive, good, (c) => {
    const seg = c.chain.find((e) => e.type === 'SEGMENT');
    seg.payload.items[0].seq = 99;
    seg.payload.digest = null; // 摘要在序号校验之后，先被序号拦截
  });
  expectErr('SEQ_OUT_OF_RANGE', () => archive.importBundle(outOfRange));

  const wrongDevice = resignTampered(archive, good, (c) => {
    const seg = c.chain.find((e) => e.type === 'SEGMENT');
    seg.payload.items[0].deviceId = 'D-404';
  });
  expectErr('DEVICE_NOT_IN_PACKAGE', () => archive.importBundle(wrongDevice));

  // 分段引用未声明的围栏
  const b2 = builderFor(issuer, { gatewayId: 'gw-2' });
  b2.fenceChange({ fence: 1, kind: 'CLAIM' });
  b2.segment({ fence: 2, segSeq: 1, items: itemsFor(b2, [1]) });
  expectErr('FENCE_UNDECLARED', () => archive.importBundle(exportBundle(archive, b2)));

  // 围栏倒退
  const b3 = builderFor(issuer, { gatewayId: 'gw-3' });
  b3.fenceChange({ fence: 2, kind: 'CLAIM' });
  b3.fenceChange({ fence: 1, kind: 'CLAIM' });
  b3.segment({ fence: 2, segSeq: 1, items: itemsFor(b3, [1]) });
  expectErr('FENCE_REGRESSION', () => archive.importBundle(exportBundle(archive, b3)));
});

test('重复导入返回原归档回执（幂等，不重复计数）', () => {
  const { archive } = setup();
  const bundle = exportBundle(archive, validBuilder(generateIssuer('pkg-key-demo')));
  const first = archive.importBundle(bundle);
  const second = archive.importBundle(bundle);
  assert.equal(second.duplicate, true);
  assert.deepEqual(second, { ...first, duplicate: true });
  // 投影未被重复合并
  const { report } = archive.buildReport(PKG);
  assert.equal(report.generatedFrom.bundles, 1);
  assert.equal(report.mergedCheckpoint.counts.merged, 4);
});

test('同围栏同分段号不同内容进入冲突隔离，已保存证据不被覆盖', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  const first = archive.importBundle(exportBundle(archive, validBuilder(issuer, { gatewayId: 'gw-a' })));

  // 另一网关导出：同 fence 1、同 segSeq 1，但内容不同（FAILED）
  const rival = builderFor(issuer, { gatewayId: 'gw-b' });
  rival.fenceChange({ fence: 1, kind: 'CLAIM' });
  rival.segment({ fence: 1, segSeq: 1, items: itemsFor(rival, [1, 2], 'FAILED') });
  const out = archive.importBundle(exportBundle(archive, rival));

  assert.deepEqual(out.segments, { accepted: 0, duplicates: 0, quarantined: 1 });
  assert.equal(out.conflicts.length, 1);

  const { report } = archive.buildReport(PKG);
  assert.equal(report.conflicts.length, 1);
  const c = report.conflicts[0];
  assert.equal(c.kind, 'SEGMENT_SEQ_CONFLICT');
  assert.equal(c.fence, 1);
  assert.equal(c.segSeq, 1);
  assert.equal(c.kept.gatewayId, 'gw-a');
  assert.equal(c.rejected.gatewayId, 'gw-b');
  // 原证据不变：回执仍是 EXECUTED，检查点不倒退
  const view = archive.packageView(PKG);
  assert.equal(view.receipts.find((r) => r.seq === 1).outcome, 'EXECUTED');
  assert.deepEqual(report.mergedCheckpoint.appliedSeqs, [1, 2, 3, 4]);
  // 冲突双方的证据都保留（kept.items / rejected.items）
  assert.equal(c.kept.items[0].outcome, 'EXECUTED');
  assert.equal(c.rejected.items[0].outcome, 'FAILED');
  // 时间线可查询被隔离的证据
  const q = report.timeline.find((t) => t.status === 'QUARANTINED');
  assert.equal(q.conflictId, c.conflictId);
  assert.equal(first.reportDigest !== out.reportDigest, true);
});

test('完全相同分段的重传幂等（DUPLICATE，不产生冲突）', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  archive.importBundle(exportBundle(archive, validBuilder(issuer, { gatewayId: 'gw-a' })));

  // 同一分段内容、不同证据包（导出时间不同 → bundleHash 不同）
  const retry = builderFor(issuer, { gatewayId: 'gw-a' });
  retry.fenceChange({ fence: 1, kind: 'CLAIM' });
  retry.segment({ fence: 1, segSeq: 1, items: itemsFor(retry, [1, 2]) });
  const out = archive.importBundle(exportBundle(archive, retry));
  assert.deepEqual(out.segments, { accepted: 0, duplicates: 1, quarantined: 0 });
  assert.equal(archive.buildReport(PKG).report.conflicts.length, 0);
});

test('多围栏按规则合并：当前检查点不倒退，旧围栏证据可查但不计入当前进度', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');

  // gw-a：fence 1 完成序号 1-2
  const b1 = builderFor(issuer, { gatewayId: 'gw-a' });
  b1.fenceChange({ fence: 1, kind: 'CLAIM' });
  b1.segment({ fence: 1, segSeq: 1, items: itemsFor(b1, [1, 2]) });
  b1.checkpoint({ fence: 1, appliedSeqs: [1, 2], counts: countsFor(4, [1, 2]) });
  const r1 = archive.importBundle(exportBundle(archive, b1));

  // gw-b：移交后 fence 2 完成序号 3-4（并确认继承 1-2）
  const b2 = builderFor(issuer, { gatewayId: 'gw-b' });
  b2.fenceChange({ fence: 1, kind: 'CLAIM' });
  b2.fenceChange({ fence: 2, kind: 'HANDOVER', fromGatewayId: 'gw-a', toGatewayId: 'gw-b' });
  b2.segment({ fence: 2, segSeq: 1, items: itemsFor(b2, [3, 4]) });
  b2.checkpoint({ fence: 2, appliedSeqs: [1, 2, 3, 4], counts: countsFor(4, [1, 2, 3, 4]) });
  const r2 = archive.importBundle(exportBundle(archive, b2));

  const { report } = archive.buildReport(PKG);
  assert.equal(report.currentFence, 2);
  // 当前进度只算当前围栏自己的回执
  assert.deepEqual(report.currentProgress.appliedSeqs, [3, 4]);
  // 旧围栏回执作为继承证据保留可查
  assert.deepEqual(report.inheritedProgress.seqs, [1, 2]);
  // 合并检查点覆盖全部序号且不倒退
  assert.deepEqual(report.mergedCheckpoint.appliedSeqs, [1, 2, 3, 4]);
  assert.equal(report.mergedCheckpoint.fence, 2);
  assert.equal(report.mergedCheckpoint.watermark, 4);
  const fence1 = report.fences.find((f) => f.fence === 1);
  assert.equal(fence1.status, 'HISTORICAL');
  assert.equal(report.fences.find((f) => f.fence === 2).status, 'CURRENT');
  assert.ok(r2.reportDigest !== r1.reportDigest);

  // 旧围栏迟到证据（fence 1 重复内容）不倒退当前检查点
  const late = builderFor(issuer, { gatewayId: 'gw-a' });
  late.fenceChange({ fence: 1, kind: 'CLAIM' });
  late.segment({ fence: 1, segSeq: 2, items: itemsFor(late, [3, 4]) });
  archive.importBundle(exportBundle(archive, late));
  const after = archive.buildReport(PKG).report;
  assert.equal(after.currentFence, 2);
  assert.deepEqual(after.mergedCheckpoint.appliedSeqs, [1, 2, 3, 4]);
  assert.deepEqual(after.currentProgress.appliedSeqs, [3, 4]);
});

test('跨围栏同序号不同内容 → SEQ_CONTENT_CONFLICT 隔离，不倒退', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  archive.importBundle(exportBundle(archive, validBuilder(issuer, { gatewayId: 'gw-a' })));

  // fence 2 对序号 1 报了不同结果
  const b = builderFor(issuer, { gatewayId: 'gw-b' });
  b.fenceChange({ fence: 1, kind: 'CLAIM' });
  b.fenceChange({ fence: 2, kind: 'HANDOVER', fromGatewayId: 'gw-a', toGatewayId: 'gw-b' });
  b.segment({ fence: 2, segSeq: 1, items: itemsFor(b, [1], 'FAILED') });
  const out = archive.importBundle(exportBundle(archive, b));
  assert.equal(out.conflicts.length, 1);

  const { report } = archive.buildReport(PKG);
  const c = report.conflicts[0];
  assert.equal(c.kind, 'SEQ_CONTENT_CONFLICT');
  assert.equal(c.seq, 1);
  // 既有证据未被覆盖
  assert.equal(archive.packageView(PKG).receipts.find((r) => r.seq === 1).outcome, 'EXECUTED');
  assert.deepEqual(report.mergedCheckpoint.appliedSeqs, [1, 2, 3, 4]);
});

test('同一 packageId 清单不一致被拒绝（MANIFEST_CONFLICT）', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  archive.importBundle(exportBundle(archive, validBuilder(issuer, { gatewayId: 'gw-a' })));
  // 同一 packageId 但设备集合不同 → manifestHash 不同
  const other = validBuilder(issuer, { gatewayId: 'gw-b', deviceIds: ['D-1', 'D-2', 'D-3', 'D-5'] });
  expectErr('MANIFEST_CONFLICT', () => archive.importBundle(exportBundle(archive, other)));
});

test('重启重放：报告摘要与冲突列表逐字节一致，重复导入仍返回原回执', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ev-arch-'));
  const logFile = join(dir, 'evidence.log');
  const keyFile = join(dir, 'keys.json');

  const issuer = generateIssuer('pkg-key-demo');
  let digest1; let conflicts1; let receipt1;

  // 第一次启动：建钥 + 导入（有效 + 冲突 + 第二围栏）
  {
    const store = new EventStore(logFile);
    const archive = new EvidenceArchive({ store, keys: new EvidenceKeyStore(keyFile) });
    archive.rotateKey('2026-10-01T00:00:00.000Z');
    const bundle = exportBundle(archive, validBuilder(issuer, { gatewayId: 'gw-a' }));
    receipt1 = archive.importBundle(bundle);

    const rival = builderFor(issuer, { gatewayId: 'gw-b' });
    rival.fenceChange({ fence: 1, kind: 'CLAIM' });
    rival.segment({ fence: 1, segSeq: 1, items: itemsFor(rival, [1, 2], 'FAILED') });
    archive.importBundle(exportBundle(archive, rival));

    const b2 = builderFor(issuer, { gatewayId: 'gw-b' });
    b2.fenceChange({ fence: 1, kind: 'CLAIM' });
    b2.fenceChange({ fence: 2, kind: 'HANDOVER', fromGatewayId: 'gw-a', toGatewayId: 'gw-b' });
    b2.segment({ fence: 2, segSeq: 1, items: itemsFor(b2, [3, 4]) });
    archive.importBundle(exportBundle(archive, b2));

    digest1 = archive.buildReport(PKG).reportDigest;
    conflicts1 = JSON.stringify(archive.listConflicts());
    assert.equal(store.writable, true);
  }

  // 模拟重启：新进程从同一日志重放
  {
    const store = new EventStore(logFile);
    const archive = new EvidenceArchive({ store, keys: new EvidenceKeyStore(keyFile) });
    await store.load();
    for (const rec of store.all()) archive.apply(rec);
    const digest2 = archive.buildReport(PKG).reportDigest;
    assert.equal(digest2, digest1, '重启后报告摘要必须一致');
    assert.equal(JSON.stringify(archive.listConflicts()), conflicts1, '重启后冲突列表必须一致');
    // 重复导入仍命中原回执（回执随重放重建；构造器确定性导出 → bundleHash 一致）
    const bundle = exportBundle(archive, validBuilder(issuer, { gatewayId: 'gw-a' }));
    const again = archive.importBundle(bundle);
    assert.equal(again.duplicate, true);
    assert.equal(again.bundleHash, receipt1.bundleHash);
    assert.equal(again.reportDigest, receipt1.reportDigest);
  }
});

test('脱敏：归档日志/详情/报告不含原始 uploadSecret，只保留 secretHash', () => {
  const { archive, store } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  const bundle = exportBundle(archive, validBuilder(issuer, { gatewayId: 'gw-a' }));
  const secrets = Object.values(bundle.uploadSecrets);
  assert.ok(secrets.length >= 1);
  archive.importBundle(bundle);

  const logText = store.all().map((r) => JSON.stringify(r)).join('\n');
  const viewText = JSON.stringify(archive.packageView(PKG));
  const reportText = JSON.stringify(archive.buildReport(PKG));
  for (const secret of secrets) {
    assert.ok(!logText.includes(secret), '归档日志不得包含原始 uploadSecret');
    assert.ok(!viewText.includes(secret), '归档详情不得包含原始 uploadSecret');
    assert.ok(!reportText.includes(secret), '核验报告不得包含原始 uploadSecret');
  }
  // 脱敏标记与 secretHash 存在
  const archived = store.all().find((r) => r.type === 'EVIDENCE_BUNDLE_ARCHIVED');
  assert.equal(archived.payload.bundle.uploadSecrets['1'].redacted, true);
  assert.match(archived.payload.bundle.uploadSecrets['1'].secretHash, /^[0-9a-f]{64}$/);
  // 私钥从不出现在任何记录中
  assert.ok(!logText.includes('PRIVATE KEY'));
  // 脱敏自检：原始密钥串会被拦截
  assert.throws(() => archive.assertRedacted(secrets[0]), /REDACTION_BREACH|未脱敏/);
  assert.doesNotThrow(() => archive.assertRedacted(reportText));
});

test('bundleHash 幂等键与签名正文一致（改签名不算重复，改正文即新证据）', () => {
  const { archive } = setup();
  const issuer = generateIssuer('pkg-key-demo');
  const bundle = exportBundle(archive, validBuilder(issuer, { gatewayId: 'gw-a' }));
  assert.equal(bundleHashOf(bundle), bundleHashOf(JSON.parse(JSON.stringify(bundle))));
  archive.importBundle(bundle);
  // 同一正文换签名（例如重签）→ bundleHash 相同 → 仍幂等
  const resigned = { ...bundle, signature: archive.signBundle(bundle).signature };
  const out = archive.importBundle(resigned);
  assert.equal(out.duplicate, true);
});
