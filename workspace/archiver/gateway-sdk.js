// 网关侧证据 SDK（演示/测试用）：模拟现场网关断网期间本地积累证据、
// 恢复联网后导出【带签名证据包】的全过程。真实网关应在本地实现同一套规范化：
//   - 链条目：{seq,ts,type,payload,prevHash,hash}，hash = sha256(规范化JSON(其余字段))；
//   - 分段摘要：HMAC-SHA256(uploadSecret, 规范化JSON({packageId,fence,segSeq,items}))；
//   - 检查点令牌：sha256(规范化JSON({packageId,fence,appliedSeqs,counts}))；
//   - 包签名：Ed25519(规范化JSON(除 signature 外的全部字段))。
import { generateKeyPairSync } from 'node:crypto';
import { canonicalJSON, sha256Hex } from '../src/util.js';
import { segmentDigest, signCanonical } from '../src/package-crypto.js';
import { ZERO_HASH } from '../src/store.js';
import {
  BUNDLE_FORMAT,
  MANIFEST_FORMAT,
  normalizeItems,
  checkpointTokenOf,
  bundleSignedBody,
} from './evidence.js';

// 生成一对演示用包签发密钥（真实环境由编排服务的 PackageKeyStore 持有私钥）。
export function generateIssuer(keyId = 'pkg-key-demo') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    keyId,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

// 生成演示用上传密钥（真实环境 = deriveUploadSecret(master, packageId, fence)）。
export function demoUploadSecret(packageId, fence) {
  return sha256Hex(`dr-demo-upload|${packageId}|${fence}`);
}

// 构造并签发一份只读清单（与编排服务 ISSUE_PACKAGE 的 manifest 结构一致）。
export function buildManifest(issuer, {
  packageId,
  eventId = 'EV-DEMO',
  deviceIds = ['D-1', 'D-2', 'D-3', 'D-4'],
  targetKw = 25,
  startMs = Date.UTC(2026, 9, 1, 2, 0, 0),
  endMs = Date.UTC(2026, 9, 1, 6, 0, 0),
  validUntil = Date.UTC(2026, 9, 1, 2, 0, 0),
  issuedAt = Date.UTC(2026, 8, 30, 8, 0, 0),
} = {}) {
  const devices = [...deviceIds].sort();
  const instructions = devices.map((deviceId, i) => ({
    seq: i + 1,
    deviceId,
    deviceName: `设备${deviceId}`,
    action: 'SET_SHED_KW',
    targetKw,
    startMs,
    endMs,
  }));
  const manifest = {
    format: MANIFEST_FORMAT,
    packageId,
    eventId,
    eventVersion: 1,
    eventSpec: { meterId: 'MP-1', meterName: '演示计量点', algorithm: 'LAST10', targetKw, startMs, endMs },
    manifestSummary: {
      deviceCount: devices.length,
      devices,
      entriesHash: sha256Hex(canonicalJSON(instructions)),
    },
    instructions,
    issuedAt,
    validUntil,
    keyId: issuer.keyId,
  };
  return {
    manifest,
    manifestHash: sha256Hex(canonicalJSON(manifest)),
    manifestSignature: signCanonical(issuer.privateKeyPem, canonicalJSON(manifest)),
  };
}

// 篡改演示/测试辅助：改动链条目后重算整条哈希链（保持链内自洽），
// 之后重新签名即可精确触发某一类校验错误（如 DIGEST_MISMATCH）。
export function rehashChain(bundle) {
  let prev = ZERO_HASH;
  for (const entry of bundle.chain) {
    entry.prevHash = prev;
    delete entry.hash;
    entry.hash = sha256Hex(canonicalJSON(entry));
    prev = entry.hash;
  }
  return bundle;
}

// 网关证据构建器：断网期间逐条追加围栏变更 / 分段回执 / 检查点，最后导出签名证据包。
export class GatewayEvidenceBuilder {
  constructor({ packageId, gatewayId, manifest, manifestHash, manifestSignature, issuer }) {
    this.packageId = packageId;
    this.gatewayId = gatewayId;
    this.manifest = manifest;
    this.manifestHash = manifestHash;
    this.manifestSignature = manifestSignature;
    this.issuer = issuer; // {keyId, publicKeyPem}
    this.chain = [];
    this.secrets = {}; // fence -> uploadSecret（导出时随包携带，归档模块核验后脱敏）
    this.bundleSeq = 0;
  }

  #appendEntry(type, payload, ts) {
    const entry = {
      seq: this.chain.length + 1,
      ts: ts ?? Date.UTC(2026, 8, 30, 9, 0, 0) + this.chain.length * 60000,
      type,
      payload,
      prevHash: this.chain.length ? this.chain.at(-1).hash : ZERO_HASH,
    };
    entry.hash = sha256Hex(canonicalJSON(entry));
    this.chain.push(entry);
    return entry;
  }

  // 围栏变更（领取 / 强制移交）：fence 必须严格递增。
  fenceChange({ fence, kind = 'CLAIM', fromGatewayId = null, toGatewayId = null, at } = {}) {
    return this.#appendEntry('FENCE_CHANGE', {
      fence, kind, gatewayId: this.gatewayId, fromGatewayId, toGatewayId,
      at: at ?? null,
    });
  }

  // 分段回执：items = [{seq, deviceId, outcome, detail?}]；自动计算 HMAC 摘要。
  segment({ fence, segSeq, items, uploadSecret, at } = {}) {
    const secret = uploadSecret || demoUploadSecret(this.packageId, fence);
    this.secrets[String(fence)] = secret;
    const normalized = normalizeItems(items);
    const digest = segmentDigest(secret, canonicalJSON({
      packageId: this.packageId, fence, segSeq, items: normalized,
    }));
    return this.#appendEntry('SEGMENT', {
      fence, segSeq, items: normalized, digest, at: at ?? null,
    });
  }

  // 检查点：appliedSeqs 升序；自动计算令牌。
  checkpoint({ fence, appliedSeqs, counts, at } = {}) {
    const token = checkpointTokenOf(this.packageId, fence, appliedSeqs, counts);
    return this.#appendEntry('CHECKPOINT', {
      fence, appliedSeqs, counts, checkpointToken: token, at: at ?? null,
    });
  }

  // 导出未签名正文（可交给归档服务的 /api/evidence/sign 演示签名）。
  unsignedBody({ keyId, exportedAt } = {}) {
    this.bundleSeq += 1;
    return {
      format: BUNDLE_FORMAT,
      bundleId: `EVB-${this.packageId}-${this.gatewayId}-${this.bundleSeq}`,
      packageId: this.packageId,
      gatewayId: this.gatewayId,
      keyId,
      exportedAt: exportedAt ?? Date.UTC(2026, 8, 30, 12, 0, 0),
      issuer: { keyId: this.issuer.keyId, publicKeyPem: this.issuer.publicKeyPem },
      manifest: this.manifest,
      manifestHash: this.manifestHash,
      manifestSignature: this.manifestSignature,
      uploadSecrets: { ...this.secrets },
      chain: this.chain.map((e) => ({ ...e, payload: JSON.parse(JSON.stringify(e.payload)) })),
    };
  }

  // 导出完整签名证据包（私钥由调用方持有，例如演示环境的证据签名密钥）。
  export({ keyId, privateKeyPem, exportedAt } = {}) {
    const body = this.unsignedBody({ keyId, exportedAt });
    const signature = signCanonical(privateKeyPem, canonicalJSON(bundleSignedBody(body)));
    return { ...body, signature };
  }
}
