// 证据包的签名原语与本机密钥材料管理。
//
// 信任模型：网关侧持 Ed25519 私钥（离线期间对证据包签名）；归档服务只保存
// 【网关注册表】（gatewayId -> 公钥 PEM，0644 可随工具管理，无密），
// 以及一个与所有网关共享的 upload secret（sidecar，0600），用于 HTTP 导入鉴权。
// 归档服务从不接触任何网关私钥；页面/日志/导出永不出现私钥或 upload secret 原文。
import {
  generateKeyPairSync,
  sign,
  verify,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync } from 'node:fs';
import { dirname, join } from 'node:path';

export function generateGatewayKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

export function signEnvelope(privateKeyPem, canonical) {
  return sign(null, Buffer.from(canonical, 'utf8'), privateKeyPem).toString('hex');
}

export function verifyEnvelope(publicKeyPem, canonical, signatureHex) {
  try {
    return verify(
      null,
      Buffer.from(canonical, 'utf8'),
      publicKeyPem,
      Buffer.from(signatureHex, 'hex'),
    );
  } catch {
    return false;
  }
}

export function newUploadSecret() {
  return randomBytes(32).toString('hex');
}

// 常量时间比较，避免 upload secret 的计时探测；长度不等直接失败（但比较前不泄露长度差异）。
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    // 仍做一次等长比较以拉平耗时。
    timingSafeEqual(Buffer.alloc(Math.max(ab.length, bb.length || 1)), Buffer.alloc(Math.max(ab.length, bb.length || 1)));
    return false;
  }
  return timingSafeEqual(ab, bb);
}

// 原子写：同目录临时文件 + rename，断电不会留下半截文件。
function atomicWrite(file, content, mode) {
  const dir = dirname(file);
  mkdirSync(dir, { recursive: true });
  const tmp = join(dir, `.${Date.now()}-${process.pid}.tmp`);
  writeFileSync(tmp, content, { mode });
  renameSync(tmp, file);
}

// 网关公钥注册表：data/evidence/gateways.json
// 结构 { version:1, gateways:[{gatewayId,keyId,publicKeyPem,createdAt,note}] }
// 公钥本身公开，无密；私钥只在制包工具进程里出现，绝不写入本机。
export class GatewayRegistry {
  constructor(file) {
    this.file = file;
    this.gateways = new Map();
    if (file && existsSync(file)) {
      const raw = JSON.parse(readFileSync(file, 'utf8'));
      for (const g of raw.gateways || []) {
        this.gateways.set(g.gatewayId, g);
      }
    }
  }

  list() {
    return [...this.gateways.values()].map((g) => ({
      gatewayId: g.gatewayId, keyId: g.keyId, publicKeyPem: g.publicKeyPem,
      createdAt: g.createdAt, note: g.note || null,
    }));
  }

  has(gatewayId) {
    return this.gateways.has(gatewayId);
  }

  get(gatewayId) {
    return this.gateways.get(gatewayId) || null;
  }

  register({ gatewayId, keyId, publicKeyPem, createdAt, note = null }) {
    if (this.gateways.has(gatewayId)) {
      const g = this.gateways.get(gatewayId);
      if (g.publicKeyPem !== publicKeyPem) {
      throw Object.assign(new Error(`网关 ${gatewayId} 已用不同公钥登记`), {
        code: 'GATEWAY_KEY_CONFLICT', status: 409,
      });
      }
      return g;
    }
    const entry = { gatewayId, keyId, publicKeyPem, createdAt: createdAt || new Date().toISOString(), note };
    this.gateways.set(gatewayId, entry);
    this.#persist();
    return entry;
  }

  #persist() {
    const gateways = [...this.gateways.values()];
    atomicWrite(this.file, JSON.stringify({ version: 1, gateways }, null, 2) + '\n', 0o644);
  }
}

// upload secret sidecar：data/evidence/upload-secret.json（0600）。
// 读取优先级：环境变量 EVIDENCE_UPLOAD_SECRET > sidecar；都没有则生成并落盘。
// 永不通过任何 API 返回该值；演示/测试可从文件读取（文件权限 0600）。
export function loadOrCreateUploadSecret(file, envValue) {
  if (envValue && envValue.trim()) {
    return { secret: envValue.trim(), source: 'env', file };
  }
  if (file && existsSync(file)) {
    const raw = JSON.parse(readFileSync(file, 'utf8'));
    if (raw.secret) return { secret: raw.secret, source: 'file', file };
  }
  const secret = newUploadSecret();
  atomicWrite(file, JSON.stringify({ version: 1, secret, createdAt: new Date().toISOString() }, null, 2) + '\n', 0o600);
  return { secret, source: 'generated', file };
}
