// 证据归档模块的密钥材料（独立于编排内核的包签发密钥）。
//
// 只有一类密钥：证据签名密钥（Ed25519）。网关/采集端导出证据包时用它对
// 【规范化证据包正文】签名，归档模块验签后才归档。
//  - 公钥随 EVIDENCE_KEY_PUBLISHED 记录上链分发，可独立核验；
//  - 私钥只保存在日志旁 sidecar（evidence-keys.json，权限 0600），链上永不出现；
//  - 轮换只追加新版本，旧 key 永不删除——历史证据包仍可按 keyId 复验。
// 注意：本模块【不持有】包签发私钥与 HMAC 主密钥；证据包里携带的 uploadSecret
// 仅用于导入时核验分段摘要，归档前一律脱敏（见 evidence.js）。
import {
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

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

export class EvidenceKeyStore {
  // file 为 null 时纯内存（演示/测试）。
  constructor(file = null) {
    this.file = file;
    // 按版本保存 [{ keyId, publicKeyPem, privateKeyPem, rotatedAt }]
    this.keys = [];
    if (file && existsSync(file)) {
      const text = readFileSync(file, 'utf8').trim();
      // 空文件（reset 后）视为全新密钥库
      const raw = text ? JSON.parse(text) : {};
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
    // 只落盘私钥；公钥另随链上 EVIDENCE_KEY_PUBLISHED 公开分发
    writeFileSync(this.file, JSON.stringify({ version: 1, keys: this.keys }, null, 2) + '\n', { mode: 0o600 });
  }

  // 生成并登记一把新证据签名密钥（首个 keyId = ev-key-1，之后递增）。
  // 返回可写入哈希链的公开部分。
  rotate(nowIso) {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const entry = {
      keyId: `ev-key-${this.keys.length + 1}`,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
      privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      rotatedAt: nowIso || new Date().toISOString(),
    };
    this.keys.push(entry);
    this.#persist();
    return { keyId: entry.keyId, publicKeyPem: entry.publicKeyPem, rotatedAt: entry.rotatedAt };
  }

  // 从链上 EVIDENCE_KEY_PUBLISHED 记录登记/核对公钥（重启重放用）。
  // sidecar 已存在 -> 校验公钥一致；sidecar 缺失 -> 只登记公钥，
  // 该版本将无法再签名（只能用于历史验签）。
  reconcile(record) {
    const existing = this.keys.find((k) => k.keyId === record.keyId);
    if (existing) {
      if (existing.publicKeyPem !== record.publicKeyPem) {
        throw new Error(`证据签名密钥 ${record.keyId} 的链上公钥与 sidecar 不一致`);
      }
      return;
    }
    this.keys.push({
      keyId: record.keyId,
      publicKeyPem: record.publicKeyPem,
      privateKeyPem: null,
      rotatedAt: record.rotatedAt,
    });
    // 不持久化：重放结果以链为准；写操作发生时自然落盘。
  }

  publicKey(keyId) {
    return this.require(keyId).publicKeyPem;
  }

  require(keyId) {
    const k = this.keys.find((x) => x.keyId === keyId);
    if (!k) throw new Error(`证据签名密钥 ${keyId} 未登记`);
    return k;
  }

  has(keyId) {
    return this.keys.some((k) => k.keyId === keyId);
  }

  sign(keyId, canonical) {
    const k = this.require(keyId);
    if (!k.privateKeyPem) throw new Error(`证据签名密钥 ${keyId} 仅有公钥（sidecar 缺失），无法签名`);
    return signCanonical(k.privateKeyPem, canonical);
  }

  verify(keyId, canonical, signatureHex) {
    if (!this.has(keyId)) return false;
    return verifyCanonical(this.publicKey(keyId), canonical, signatureHex);
  }

  listPublic() {
    return this.keys.map((k) => ({ keyId: k.keyId, publicKeyPem: k.publicKeyPem, rotatedAt: k.rotatedAt }));
  }

  // 清空 sidecar（演示复位用）
  reset() {
    this.keys = [];
    if (this.file) writeFileSync(this.file, '');
  }
}
