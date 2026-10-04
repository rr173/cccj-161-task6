// 离线作业包的密钥材料与签名原语。
//
// 两类密钥、两种用途：
//  1) 签发密钥（Ed25519 非对称签名）：运营服务对【只读包清单 manifest】签名；
//     网关离线领取后，可仅凭 manifest + signature + 公钥独立验签，不依赖在线服务。
//  2) 上传密钥（HMAC-SHA256 对称密钥）：每次领取/移交都会轮换围栏号 fence，
//     并由主密钥派生 uploadSecret = HMAC(master, "upload-v1"|packageId|fence)。
//     网关上传分段时必须携带该 secret 的 HMAC 摘要；旧围栏的 secret 天然失效，
//     旧领取者恢复联网后的回执在围栏校验阶段即被拒绝，根本到不了合并阶段。
//
// 持久化：链上只记录 keyId 与公钥（PACKAGE_KEY_PUBLISHED），绝不含私钥/主密钥；
// 私钥与主密钥保存在日志旁的 sidecar 文件（data/package-keys.json，权限 0600）。
// 纯内存模式（DR_MEMORY=1）只保存在进程内存，不落盘。
// 密钥轮换只追加新版本，旧 key/旧 master 永不删除——历史包仍可按 keyId 复验、
// 历史围栏仍可按当时的 master 复算审计。
import {
  generateKeyPairSync,
  sign,
  verify,
  createHmac,
  randomBytes,
} from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalJSON } from './util.js';

// 生成 Ed25519 密钥对（PEM）。Ed25519 是 PureEdDSA，签名/验签时 hash 必须为 null。
export function generateIssuerKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

export function signCanonical(privateKeyPem, canonical) {
  return sign(null, Buffer.from(canonical, 'utf8'), privateKeyPem).toString('hex');
}

export function verifyCanonical(publicKeyPem, canonical, signatureHex) {
  try {
    return verify(null, Buffer.from(canonical, 'utf8'), publicKeyPem, Buffer.from(signatureHex, 'hex'));
  } catch {
    return false;
  }
}

function hmac(secret, message) {
  // 约定 uploadSecret 为 64 位 hex（HMAC-SHA256 输出）；hex 密钥按字节使用，
  // 与 deriveUploadSecret 的 Buffer(hex) 路径保持一致。非 hex 输入按 UTF-8 兜底。
  const key = /^[0-9a-f]{64}$/.test(secret) ? Buffer.from(secret, 'hex') : secret;
  return createHmac('sha256', key).update(message).digest('hex');
}

// 上传分段摘要：HMAC-SHA256(uploadSecret, canonicalJSON(segmentBody))，hex。
// segmentBody 只包含可复算的字段 {packageId,fence,segSeq,items}，网关按同样的
// “键名字典序 + 无多余空白”规则即可独立计算。
export function segmentDigest(uploadSecret, segmentBody) {
  return hmac(uploadSecret, canonicalJSON(segmentBody));
}

// 每次领取/移交派生的上传密钥；master 轮换后旧围栏的派生结果不再匹配。
export function deriveUploadSecret(masterSecretHex, packageId, fence) {
  return hmac(
    Buffer.from(masterSecretHex, 'hex'),
    `dr-package-upload-v1|${packageId}|${fence}`,
  );
}

export class PackageKeyStore {
  // file 为 null 时纯内存（演示/测试）。
  constructor(file = null) {
    this.file = file;
    // 按版本保存 [{ keyId, publicKeyPem, privateKeyPem, masterSecretHex, rotatedAt }]
    this.keys = [];
    if (file && existsSync(file)) {
      const raw = JSON.parse(readFileSync(file, 'utf8'));
      this.keys = raw.keys || [];
    }
  }

  get currentKeyId() {
    return this.current?.keyId || null;
  }

  get current() {
    return this.keys.at(-1) || null;
  }

  #persist() {
    if (!this.file) return;
    if (dirname(this.file) && dirname(this.file) !== '.') mkdirSync(dirname(this.file), { recursive: true });
    // 只落盘私钥/主密钥；公钥另随链上 PACKAGE_KEY_PUBLISHED 公开分发
    writeFileSync(this.file, JSON.stringify({ version: 1, keys: this.keys }, null, 2) + '\n', { mode: 0o600 });
  }

  // 生成并登记一把新签发密钥（首个 keyId = pkg-key-1，之后递增）。
  // 返回可写入哈希链的公开部分。
  rotate(nowIso) {
    const { publicKeyPem, privateKeyPem } = generateIssuerKeyPair();
    const entry = {
      keyId: `pkg-key-${this.keys.length + 1}`,
      publicKeyPem,
      privateKeyPem,
      masterSecretHex: randomBytes(32).toString('hex'),
      rotatedAt: nowIso || new Date().toISOString(),
    };
    this.keys.push(entry);
    this.#persist();
    return { keyId: entry.keyId, publicKeyPem: entry.publicKeyPem, rotatedAt: entry.rotatedAt };
  }

  // 从链上 PACKAGE_KEY_PUBLISHED 记录登记/核对公钥（重启重放用）。
  // sidecar 已存在 -> 校验公钥一致；sidecar 缺失（被删/换机器）-> 只登记公钥，
  // 该版本将无法再签名或派生上传密钥（只能用于历史验签）。
  reconcile(record) {
    const existing = this.keys.find((k) => k.keyId === record.keyId);
    if (existing) {
      if (existing.publicKeyPem !== record.publicKeyPem) {
        throw new Error(`包签发密钥 ${record.keyId} 的链上公钥与 sidecar 不一致`);
      }
      return;
    }
    this.keys.push({
      keyId: record.keyId,
      publicKeyPem: record.publicKeyPem,
      privateKeyPem: null,
      masterSecretHex: null,
      rotatedAt: record.rotatedAt,
    });
    // 不持久化：重放结果以链为准；写操作发生时自然落盘。
  }

  publicKey(keyId) {
    return this.require(keyId).publicKeyPem;
  }

  require(keyId) {
    const k = this.keys.find((x) => x.keyId === keyId);
    if (!k) throw new Error(`包签发密钥 ${keyId} 未登记`);
    return k;
  }

  signManifest(keyId, canonical) {
    const k = this.require(keyId);
    if (!k.privateKeyPem) throw new Error(`包签发密钥 ${keyId} 仅有公钥（sidecar 缺失），无法签发新包`);
    return signCanonical(k.privateKeyPem, canonical);
  }

  verifyManifest(keyId, canonical, signatureHex) {
    return verifyCanonical(this.publicKey(keyId), canonical, signatureHex);
  }

  uploadSecretFor(keyId, packageId, fence) {
    const k = this.require(keyId);
    if (!k.masterSecretHex) throw new Error(`包签发密钥 ${keyId} 缺少主密钥（sidecar 缺失），无法派生上传密钥`);
    return deriveUploadSecret(k.masterSecretHex, packageId, fence);
  }

  // 清空 sidecar（演示复位用）
  reset() {
    this.keys = [];
    if (this.file) writeFileSync(this.file, '');
  }
}
