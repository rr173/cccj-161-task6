// 一键演示：证据归档与冲突核验的 7 个场景（自拉起服务，真实 HTTP + 真实重启）。
//   node archiver/demo.mjs
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { createApp } = await import('./server.js');
const { generateIssuer, buildManifest, GatewayEvidenceBuilder, rehashChain } = await import('./gateway-sdk.js');

const dir = mkdtempSync(join(tmpdir(), 'ev-demo-'));
const issuer = generateIssuer('pkg-key-demo');
const PKG = 'PKG-DEMO-1';
const DEVICES = ['D-1', 'D-2', 'D-3', 'D-4'];

let base;
const call = async (p, opts) => {
  const res = await fetch(base + p, opts);
  return { status: res.status, json: await res.json().catch(() => ({})) };
};
const J = (b) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) });
const say = (s) => console.log(`\n\x1b[1m${s}\x1b[0m`);
const ok = (s) => console.log(`  → ${s}`);

async function freePort() {
  const { createServer } = await import('node:http');
  const s = createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const p = s.address().port;
  await new Promise((r) => s.close(r));
  return p;
}
async function start() {
  const port = await freePort();
  const app = await createApp({ logFile: join(dir, 'evidence.log'), keyFile: join(dir, 'keys.json') });
  await new Promise((r) => app.server.listen(port, '127.0.0.1', r));
  base = `http://127.0.0.1:${port}`;
  return app;
}
function builderFor(gatewayId) {
  const { manifest, manifestHash, manifestSignature } = buildManifest(issuer, { packageId: PKG, deviceIds: DEVICES });
  return new GatewayEvidenceBuilder({
    packageId: PKG, gatewayId, manifest, manifestHash, manifestSignature,
    issuer: { keyId: issuer.keyId, publicKeyPem: issuer.publicKeyPem },
  });
}
const itemsFor = (b, seqs, outcome = 'EXECUTED') => seqs.map((seq) => ({
  seq, deviceId: b.manifest.instructions[seq - 1].deviceId, outcome, detail: null,
}));
const countsFor = (seqs) => ({
  total: DEVICES.length, merged: seqs.length, executed: seqs.length, skipped: 0, failed: 0,
  remaining: DEVICES.length - seqs.length,
});
async function exportBundle(builder) {
  const body = builder.unsignedBody({ keyId: 'ev-key-1' });
  const sig = await call('/api/evidence/sign', J(body));
  return { ...body, signature: sig.json.signature };
}

let app = await start();
console.log(`演示数据目录：${dir}`);

say('① 轮换证据签名密钥（私钥只存 sidecar 0600，链上/页面只有公钥）');
await call('/api/evidence/keys/rotate', J({}));
ok(`已生成 ev-key-1：${(await call('/api/evidence/keys')).json.keys[0].publicKeyPem.split('\n')[1]}`);

say('② 网关 gw-alpha 断网执行后导出证据包（围栏1 · 分段1-2 · 检查点），导入归档');
const b1 = builderFor('gw-alpha');
b1.fenceChange({ fence: 1, kind: 'CLAIM' });
b1.segment({ fence: 1, segSeq: 1, items: itemsFor(b1, [1, 2]) });
b1.segment({ fence: 1, segSeq: 2, items: itemsFor(b1, [3, 4]) });
b1.checkpoint({ fence: 1, appliedSeqs: [1, 2, 3, 4], counts: countsFor([1, 2, 3, 4]) });
const bundle1 = await exportBundle(b1);
const imp1 = await call('/api/evidence/import', J({ bundle: bundle1 }));
ok(`归档成功：archiveSeq=${imp1.json.archiveSeq}，报告摘要 ${imp1.json.reportDigest.slice(0, 16)}…`);

say('③ 篡改演示：签名 / 哈希链 / 分段摘要 一律被拒绝并留审计');
const bad1 = { ...bundle1, signature: '0'.repeat(128) };
ok(`篡改签名 → ${(await call('/api/evidence/import', J({ bundle: bad1 }))).json.code}`);
const bad2 = JSON.parse(JSON.stringify(bundle1));
bad2.chain.find((e) => e.type === 'SEGMENT').payload.items[0].outcome = 'FAILED';
const bad2Signed = await exportBundle({ unsignedBody: () => bad2 });
ok(`改写链内容（重签名）→ ${(await call('/api/evidence/import', J({ bundle: bad2Signed }))).json.code}`);
const bad3 = JSON.parse(JSON.stringify(bundle1));
bad3.chain.find((e) => e.type === 'SEGMENT').payload.digest = 'f'.repeat(64);
rehashChain(bad3);
const bad3Signed = await exportBundle({ unsignedBody: () => bad3 });
ok(`伪造分段摘要（链自洽）→ ${(await call('/api/evidence/import', J({ bundle: bad3Signed }))).json.code}`);

say('④ 重复导入同一证据包 → 返回原归档回执（幂等）');
const dup = await call('/api/evidence/import', J({ bundle: bundle1 }));
ok(`duplicate=${dup.json.duplicate}，archiveSeq 仍为 ${dup.json.archiveSeq}，摘要一致=${dup.json.reportDigest === imp1.json.reportDigest}`);

say('⑤ 另一网关对同围栏同分段号上报不同内容 → 冲突隔离，不覆盖已保存证据');
const rival = builderFor('gw-beta');
rival.fenceChange({ fence: 1, kind: 'CLAIM' });
rival.segment({ fence: 1, segSeq: 1, items: itemsFor(rival, [1, 2], 'FAILED') });
const impRival = await call('/api/evidence/import', J({ bundle: await exportBundle(rival) }));
const conflict = (await call('/api/evidence/conflicts')).json.conflicts[0];
ok(`隔离 ${impRival.json.segments.quarantined} 段：${conflict.conflictId}（保留 ${conflict.kept.gatewayId} 的 EXECUTED，隔离 ${conflict.rejected.gatewayId} 的 FAILED）`);

say('⑥ 强制移交后 gw-beta 以围栏2续传 → 多围栏合并，检查点不倒退，旧围栏不计入当前进度');
const b2 = builderFor('gw-beta');
b2.fenceChange({ fence: 1, kind: 'CLAIM' });
b2.fenceChange({ fence: 2, kind: 'HANDOVER', fromGatewayId: 'gw-alpha', toGatewayId: 'gw-beta' });
b2.segment({ fence: 2, segSeq: 1, items: itemsFor(b2, [3, 4]) });
b2.checkpoint({ fence: 2, appliedSeqs: [1, 2, 3, 4], counts: countsFor([1, 2, 3, 4]) });
await call('/api/evidence/import', J({ bundle: await exportBundle(b2) }));
let rep = (await call(`/api/evidence/packages/${PKG}/report`)).json;
ok(`当前围栏=${rep.report.currentFence}，当前进度=[${rep.report.currentProgress.appliedSeqs}]，继承历史=[${rep.report.inheritedProgress.seqs}]，合并检查点水位=${rep.report.mergedCheckpoint.watermark}`);
const digestBefore = rep.reportDigest;
const conflictsBefore = JSON.stringify((await call('/api/evidence/conflicts')).json);

say('⑦ 真实重启：报告摘要与冲突列表逐字节不变；导出报告全脱敏');
await new Promise((r) => app.server.close(r));
app = await start();
rep = (await call(`/api/evidence/packages/${PKG}/report`)).json;
ok(`重启后报告摘要一致=${rep.reportDigest === digestBefore}（${rep.reportDigest.slice(0, 16)}…）`);
ok(`冲突列表一致=${JSON.stringify((await call('/api/evidence/conflicts')).json) === conflictsBefore}`);
const dl = await fetch(`${base}/api/evidence/packages/${PKG}/report/download?format=text`);
const text = await dl.text();
const secrets = Object.values(bundle1.uploadSecrets);
ok(`导出文本报告 ${text.length} 字符，不含原始 uploadSecret=${secrets.every((s) => !text.includes(s))}`);
console.log(`\n可打开归档台查看：先运行 npm run archiver，再访问 http://localhost:8092/`);
console.log('—— 以下为本次演示的文本核验报告 ——\n');
console.log(text);
await new Promise((r) => app.server.close(r));
