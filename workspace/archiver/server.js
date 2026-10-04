// 证据归档与冲突核验服务（独立进程，零依赖 Node ≥20）。
//   导入带签名证据包 → 校验（规范化签名 + 哈希链 + 清单 + 分段摘要 + 检查点）
//   → 按 packageId 归档 → 冲突隔离 → 生成可阅读/可下载的核验报告。
// 默认端口 8092（EVIDENCE_PORT 可覆盖）；数据默认落盘 data/evidence/（EVIDENCE_DATA 可覆盖）。
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, extname } from 'node:path';
import { EventStore } from '../src/store.js';
import { EvidenceArchive } from './evidence.js';
import { EvidenceKeyStore } from './keys.js';
import {
  GatewayEvidenceBuilder,
  generateIssuer,
  buildManifest,
  rehashChain,
} from './gateway-sdk.js';
import { renderReportText } from './report-text.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');
const DATA_DIR = process.env.EVIDENCE_DATA || join(__dirname, '..', 'data', 'evidence');
const LOG_FILE = process.env.EVIDENCE_LOG || join(DATA_DIR, 'evidence-archive.log');
const KEY_FILE = process.env.EVIDENCE_KEYS || join(DATA_DIR, 'evidence-keys.json');
const PORT = Number(process.env.EVIDENCE_PORT || 8092);
const HOST = process.env.EVIDENCE_HOST || '127.0.0.1';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

async function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return {};
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 4_000_000) reject(Object.assign(new Error('body too large'), { status: 413 }));
    });
    req.on('end', () => {
      if (!data.trim()) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(Object.assign(new Error('非法 JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

async function serveStatic(req, res) {
  let path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (path === '/') path = '/index.html';
  const file = normalize(join(PUBLIC_DIR, path));
  if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, { error: 'forbidden' });
  try {
    const buf = await readFile(file);
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' });
    res.end(buf);
  } catch {
    send(res, 404, { error: 'not found' });
  }
}

// 演示签发方（仅演示/测试：真实环境由编排服务签发清单并随包分发公钥）。
// 进程内生成一次；演示证据包由此签发，经 TOFU 登记后即可通过清单验签。
const demoIssuer = generateIssuer('pkg-key-demo');

// 按场景构造演示证据包（页面“生成演示证据包”按钮与 demo 脚本共用）。
function buildDemoBundle(archive, scenario, opts = {}) {
  const packageId = opts.packageId || 'PKG-DEMO-1';
  const gatewayId = opts.gatewayId || 'gw-alpha';
  const { manifest, manifestHash, manifestSignature } = buildManifest(demoIssuer, { packageId });
  const issuer = { keyId: demoIssuer.keyId, publicKeyPem: demoIssuer.publicKeyPem };
  const builder = new GatewayEvidenceBuilder({
    packageId, gatewayId, manifest, manifestHash, manifestSignature, issuer,
  });
  const items = (seqs, outcome = 'EXECUTED') => seqs.map((seq) => ({
    seq, deviceId: manifest.instructions[seq - 1].deviceId, outcome, detail: null,
  }));
  const checkpointOf = (fence, seqs) => ({
    fence,
    appliedSeqs: seqs,
    counts: {
      total: manifest.instructions.length,
      merged: seqs.length,
      executed: seqs.length,
      skipped: 0,
      failed: 0,
      remaining: manifest.instructions.length - seqs.length,
    },
  });

  builder.fenceChange({ fence: 1, kind: 'CLAIM' });
  switch (scenario) {
    case 'partial':
      builder.segment({ fence: 1, segSeq: 1, items: items([1, 2]) });
      builder.checkpoint(checkpointOf(1, [1, 2]));
      break;
    case 'continuation':
      builder.segment({ fence: 1, segSeq: 2, items: items([3, 4]) });
      builder.checkpoint(checkpointOf(1, [1, 2, 3, 4]));
      break;
    case 'fence2':
      // 断网期间被强制移交：新网关围栏 2 继续执行 seq 3-4
      builder.fenceChange({ fence: 2, kind: 'HANDOVER', fromGatewayId: 'gw-alpha', toGatewayId: gatewayId });
      builder.segment({ fence: 2, segSeq: 1, items: items([3, 4]) });
      builder.checkpoint(checkpointOf(2, [1, 2, 3, 4]));
      break;
    case 'conflict':
      // 同围栏同分段号、不同内容（seq 1 结果 FAILED）→ 应进入冲突隔离
      builder.segment({ fence: 1, segSeq: 1, items: items([1, 2], 'FAILED') });
      break;
    case 'valid':
    default:
      builder.segment({ fence: 1, segSeq: 1, items: items([1, 2]) });
      builder.segment({ fence: 1, segSeq: 2, items: items([3, 4]) });
      builder.checkpoint(checkpointOf(1, [1, 2, 3, 4]));
      break;
  }

  const body = builder.unsignedBody({ keyId: archive.keys.currentKeyId });
  body.bundleId = `${body.bundleId}-${Date.now().toString(36)}`; // 演示包编号唯一化

  // 篡改场景：先破坏证据正文，再视情况重算链哈希并重新签名，
  // 使每类校验错误都能被精确演示（签名错误除外——直接破坏签名本身）。
  if (opts.tamper === 'chain') {
    const seg = body.chain.find((e) => e.type === 'SEGMENT');
    seg.payload.items[0].outcome = 'FAILED'; // 链内容被改写但 hash 未更新
  }
  if (opts.tamper === 'digest') {
    body.chain.find((e) => e.type === 'SEGMENT').payload.digest = 'f'.repeat(64);
    rehashChain(body); // 链自洽但分段 HMAC 错误
  }
  if (opts.tamper === 'manifest') body.manifestHash = 'e'.repeat(64);

  const { signature } = archive.signBundle(body);
  const bundle = { ...body, signature };
  if (opts.tamper === 'signature') bundle.signature = '0'.repeat(128);
  return bundle;
}

export async function createApp(deps = {}) {
  const store = deps.store ?? new EventStore(deps.memory ? null : (deps.logFile || LOG_FILE));
  const keys = deps.keys ?? new EvidenceKeyStore(deps.memory ? null : (deps.keyFile || KEY_FILE));
  const archive = deps.archive ?? new EvidenceArchive({ store, keys });
  await store.load();
  for (const rec of store.all()) archive.apply(rec);
  const recovery = store.verify();

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const path = url.pathname;
    try {
      if (req.method === 'GET' && !path.startsWith('/api')) return serveStatic(req, res);
      const body = await readBody(req);

      // ---- 密钥与信任 ----
      if (path === '/api/evidence/keys/rotate' && req.method === 'POST') {
        return send(res, 201, archive.rotateKey(body.now || new Date().toISOString()));
      }
      if (path === '/api/evidence/keys' && req.method === 'GET') {
        return send(res, 200, { keys: archive.keys.listPublic() });
      }
      if (path === '/api/evidence/trust/issuers' && req.method === 'POST') {
        return send(res, 201, archive.trustIssuer({ keyId: body.keyId, publicKeyPem: body.publicKeyPem }));
      }
      if (path === '/api/evidence/trust/issuers' && req.method === 'GET') {
        return send(res, 200, {
          issuers: [...archive.trustedIssuers.entries()].map(([keyId, publicKeyPem]) => ({ keyId, publicKeyPem })),
        });
      }
      // 演示 SDK 小工具：对未签名证据包正文签名（私钥不出进程；网关应本地自签）
      if (path === '/api/evidence/sign' && req.method === 'POST') {
        return send(res, 200, archive.signBundle(body.bundle ?? body));
      }
      // 演示证据包生成（含篡改场景，用于演示拒绝路径）
      if (path === '/api/evidence/demo/bundle' && req.method === 'POST') {
        if (!archive.keys.currentKeyId) archive.rotateKey(new Date().toISOString());
        const bundle = buildDemoBundle(archive, body.scenario || 'valid', body);
        return send(res, 200, { bundle });
      }

      // ---- 导入 / 归档 ----
      if (path === '/api/evidence/import' && req.method === 'POST') {
        const out = archive.importBundle(body.bundle ?? body);
        return send(res, out.duplicate ? 200 : 201, out);
      }
      if (path === '/api/evidence/packages' && req.method === 'GET') {
        return send(res, 200, { count: archive.packages.size, packages: archive.listPackages() });
      }
      const pkgGet = path.match(/^\/api\/evidence\/packages\/([^/]+)$/);
      if (pkgGet && req.method === 'GET') {
        const view = archive.packageView(decodeURIComponent(pkgGet[1]));
        if (!view) return send(res, 404, { error: '归档不存在', code: 'EVIDENCE_NOT_FOUND' });
        return send(res, 200, JSON.parse(archive.assertRedacted(JSON.stringify(view))));
      }
      const pkgReport = path.match(/^\/api\/evidence\/packages\/([^/]+)\/report$/);
      if (pkgReport && req.method === 'GET') {
        const built = archive.buildReport(decodeURIComponent(pkgReport[1]));
        if (!built) return send(res, 404, { error: '归档不存在', code: 'EVIDENCE_NOT_FOUND' });
        return send(res, 200, JSON.parse(archive.assertRedacted(JSON.stringify(built))));
      }
      const pkgDownload = path.match(/^\/api\/evidence\/packages\/([^/]+)\/report\/download$/);
      if (pkgDownload && req.method === 'GET') {
        const packageId = decodeURIComponent(pkgDownload[1]);
        const built = archive.buildReport(packageId);
        if (!built) return send(res, 404, { error: '归档不存在', code: 'EVIDENCE_NOT_FOUND' });
        const format = url.searchParams.get('format') || 'text';
        if (format === 'json') {
          const text = archive.assertRedacted(JSON.stringify({ ...built.report, reportDigest: built.reportDigest }, null, 2) + '\n');
          res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Disposition': `attachment; filename="evidence-report-${encodeURIComponent(packageId)}.json"`,
          });
          return res.end(text);
        }
        const text = archive.assertRedacted(renderReportText(built.report, built.reportDigest));
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Content-Disposition': `attachment; filename="evidence-report-${encodeURIComponent(packageId)}.txt"`,
        });
        return res.end(text);
      }
      if (path === '/api/evidence/conflicts' && req.method === 'GET') {
        const packageId = url.searchParams.get('packageId');
        const conflicts = archive.listConflicts(packageId || null);
        return send(res, 200, { count: conflicts.length, conflicts });
      }

      // ---- 状态 / 校验 / 日志 ----
      if (path === '/api/evidence/state' && req.method === 'GET') {
        return send(res, 200, {
          mode: store.mode,
          readOnly: !store.writable,
          recovery: store.recovery,
          packages: archive.packages.size,
          bundles: archive.receipts.size,
          conflicts: archive.listConflicts().length,
          keys: archive.keys.listPublic().map((k) => k.keyId),
          chain: store.verify(),
        });
      }
      if (path === '/api/evidence/verify' && req.method === 'GET') {
        // 独立复验：归档链完整性 + 全部报告摘要按投影重算（重启前后必须一致）
        const reportChecks = archive.listPackages().map((p) => {
          const rebuilt = archive.buildReport(p.packageId);
          return { packageId: p.packageId, reportDigest: rebuilt.reportDigest, conflicts: rebuilt.report.conflicts.length };
        });
        return send(res, 200, { ...store.verify(), reportChecks });
      }
      if (path === '/api/evidence/log' && req.method === 'GET') {
        const type = url.searchParams.get('type');
        const limit = Number(url.searchParams.get('limit') || 200);
        let recs = store.all();
        if (type) recs = recs.filter((r) => r.type === type);
        recs = recs.slice(-limit);
        // 归档记录已脱敏；仍过一次自检兜底
        return send(res, 200, JSON.parse(archive.assertRedacted(JSON.stringify({ count: recs.length, records: recs }))));
      }
      if (path === '/api/evidence/reset' && req.method === 'POST') {
        store.truncate();
        keys.reset();
        archive.reset();
        return send(res, 200, { ok: true });
      }

      return send(res, 404, { error: 'unknown route', path });
    } catch (err) {
      const statusMap = {
        BAD_REQUEST: 400, EVIDENCE_STRUCTURE_INVALID: 400,
        EVIDENCE_KEY_UNKNOWN: 422, EVIDENCE_KEY_UNAVAILABLE: 503,
        EVIDENCE_SIGNATURE_INVALID: 422, EVIDENCE_CHAIN_BROKEN: 422,
        MANIFEST_HASH_MISMATCH: 422, MANIFEST_SIGNATURE_INVALID: 422,
        MANIFEST_CONFLICT: 409, PACKAGE_ID_MISMATCH: 422,
        ISSUER_KEY_MISMATCH: 409,
        UPLOAD_SECRET_MISSING: 422, DIGEST_MISMATCH: 422,
        CHECKPOINT_TOKEN_MISMATCH: 422, FENCE_REGRESSION: 422, FENCE_UNDECLARED: 422,
        SEQ_OUT_OF_RANGE: 422, DEVICE_NOT_IN_PACKAGE: 422,
        EVIDENCE_NOT_FOUND: 404, REDACTION_BREACH: 500,
        LOG_QUARANTINED: 503,
      };
      const status = err.status || statusMap[err.code] || 500;
      if (status === 500) console.error(err);
      const headers = status === 503 ? { 'Retry-After': '300', 'Cache-Control': 'no-store' } : {};
      send(res, status, {
        error: err.message,
        code: err.code || 'INTERNAL',
        details: err.details || {},
        ...(err.code === 'LOG_QUARANTINED' ? { recovery: err.recovery || store.recovery } : {}),
      }, headers);
    }
  });

  return { server, archive, store, keys, recovery };
}

// 直接运行（node archiver/server.js）时启动服务；被测试 import 时只导出工厂。
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === normalize(process.argv[1]);
if (isMain) {
  const { server, recovery } = await createApp({ memory: !!process.env.EVIDENCE_MEMORY });
  if (!recovery.writable) {
    console.error('⛔ 证据归档日志已进入只读隔离：');
    console.error(`   首个损坏位置 seq=${recovery.brokenAt}（第 ${recovery.lineNo ?? '?'} 行）`);
    console.error(`   原因：${recovery.reason}`);
    console.error('   导入接口返回 503；只读接口与页面照常可用，请人工核验。');
  }
  server.listen(PORT, HOST, () => {
    console.log(`证据归档与冲突核验服务已启动: http://${HOST}:${server.address().port}`);
    console.log(`归档日志: ${process.env.EVIDENCE_MEMORY ? '(内存，不持久化)' : LOG_FILE}`);
  });
}
