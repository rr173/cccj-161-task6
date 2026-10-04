# 证据归档与冲突核验模块（`archiver/`，独立服务）

断网期间，多个现场网关可能各自保存**同一作业包（packageId）**的证据：只读清单 manifest、
围栏变更、分段回执、检查点。运营人员恢复联网后，通过**网页或 HTTP 接口**导入这些
**带签名的证据包**；本模块先校验（规范化签名 + 哈希链 + 清单 + 分段摘要 + 检查点），
再把同一 `packageId` 的证据归档，并生成**可阅读、可下载**的核验报告。

- 零依赖、纯 Node.js（≥ 20）；独立进程，默认端口 **8092**，数据独立落盘 `data/evidence/`。
- 与编排内核同一套只增哈希链存储（`src/store.js`）：归档记录只增、可独立复验，
  损坏即只读隔离（导入 503，只读接口照常）。
- **私钥 / uploadSecret / 凭据从不落盘、不上屏**：证据签名私钥只在 sidecar
  `evidence-keys.json`（0600）；证据包里的 uploadSecret 仅用于导入时核验 HMAC，
  归档前一律替换为 `{redacted:true, secretHash}`。

```bash
npm run archiver          # 归档服务 + 归档台 → http://localhost:8092/
npm run demo:archiver     # 一键演示 7 个场景（篡改拒绝/幂等/冲突隔离/多围栏合并/重启）
npm run test:archiver     # 45 项真实 HTTP 端到端断言（含真实重启）
node --test test/archiver.test.js   # 17 个领域契约单测
```

## 证据包格式（`dr-package-evidence/v1`）

网关断网期间本地积累证据链，恢复联网后导出并签名（见 `gateway-sdk.js`，
真实网关应在本地实现同一套规范化）：

```jsonc
{
  "format": "dr-package-evidence/v1",
  "bundleId": "EVB-...", "packageId": "PKG-...", "gatewayId": "gw-alpha",
  "keyId": "ev-key-1",                 // 证据签名密钥（Ed25519，公钥已随链登记）
  "exportedAt": 1759226400000,
  "issuer": { "keyId": "pkg-key-1", "publicKeyPem": "-----BEGIN PUBLIC KEY-----..." },
  "manifest": { "format": "dr-offline-package/v1", "...": "只读清单（与制包时一致）" },
  "manifestHash": "sha256(规范化JSON(manifest))",
  "manifestSignature": "Ed25519(规范化JSON(manifest))，包签发密钥",
  "uploadSecrets": { "1": "按围栏的上传密钥（仅导入时核验用，归档前脱敏）" },
  "chain": [
    { "seq": 1, "ts": 1, "type": "FENCE_CHANGE",
      "payload": { "fence": 1, "kind": "CLAIM", "gatewayId": "gw-alpha", "at": 0 },
      "prevHash": "000...000", "hash": "sha256(规范化JSON(本条除hash外))" },
    { "seq": 2, "type": "SEGMENT",
      "payload": { "fence": 1, "segSeq": 1,
                   "items": [{ "seq": 1, "deviceId": "D-1", "outcome": "EXECUTED", "detail": null }],
                   "digest": "HMAC-SHA256(uploadSecret, 规范化JSON({packageId,fence,segSeq,items}))" } },
    { "seq": 3, "type": "CHECKPOINT",
      "payload": { "fence": 1, "appliedSeqs": [1, 2], "counts": { "...": "..." },
                   "checkpointToken": "sha256(规范化JSON({packageId,fence,appliedSeqs,counts}))" } }
  ],
  "signature": "Ed25519(规范化JSON(除 signature 外全部字段))，证据签名密钥"
}
```

## 校验管线（任一失败即整体拒绝，不归档任何内容）

| 顺序 | 校验 | 失败拒绝码（HTTP） |
| --- | --- | --- |
| 1 | 结构：格式版本 / 必填字段 / 链条目结构 | `EVIDENCE_STRUCTURE_INVALID`（400） |
| 2 | 规范化签名：keyId 已登记 + Ed25519 验签 | `EVIDENCE_KEY_UNKNOWN` / `EVIDENCE_SIGNATURE_INVALID`（422） |
| 3 | 哈希链：seq 从 1 连续、prevHash 衔接、逐条重算 | `EVIDENCE_CHAIN_BROKEN`（422） |
| 4 | 清单：manifestHash 重算、签发签名验签、packageId 一致 | `MANIFEST_HASH_MISMATCH` / `MANIFEST_SIGNATURE_INVALID` / `PACKAGE_ID_MISMATCH`（422） |
| 5 | 分段：序号/设备/结果 + HMAC 摘要重算 | `SEQ_OUT_OF_RANGE` / `DEVICE_NOT_IN_PACKAGE` / `UPLOAD_SECRET_MISSING` / `DIGEST_MISMATCH`（422） |
| 6 | 检查点：checkpointToken 重算 | `CHECKPOINT_TOKEN_MISMATCH`（422） |
| 7 | 围栏：FENCE_CHANGE 严格递增、引用围栏已声明 | `FENCE_REGRESSION` / `FENCE_UNDECLARED`（422） |

每次拒绝追加 `EVIDENCE_REJECTED` 审计记录（只含错误码与元信息，**不含证据包正文**）。
同一 `packageId` 锚定首次归档的清单：后续证据包清单哈希不符 → `MANIFEST_CONFLICT`（409）。
签发方公钥首次见到按 TOFU 登记上链（`ISSUER_TRUSTED`），之后不符 → `ISSUER_KEY_MISMATCH`（409）。

## 归档与合并规则（确定性，重放逐字节一致）

- **幂等**：`bundleHash = sha256(规范化签名正文)`。同一证据包重复导入返回
  **原归档回执**（`duplicate:true`，HTTP 200），不重复计数。
- **冲突隔离**：同一 `(fence, segSeq)` 只接受第一段内容——同哈希幂等；**不同内容进入
  冲突隔离**（`SEGMENT_SEQ_CONFLICT`），先归档的证据永不覆盖，后到的完整保留在隔离区可查。
  跨围栏同一序号内容不同 → `SEQ_CONTENT_CONFLICT` 条目级隔离。
- **多围栏合并**：当前围栏 = 有已接受分段的**最大围栏号**；同一序号被更新围栏以
  **相同内容**再次回报时归属转移到最新围栏（移交继承）。**当前进度只统计当前围栏**；
  旧围栏证据保留可查（`HISTORICAL`）但**不计入当前进度**。
- **合并检查点**：全部已接受回执的并集（每序号计一次）归因到当前围栏，
  令牌 = `sha256(规范化JSON({packageId,fence,appliedSeqs,counts}))`。
  证据只增不改 → 检查点**单调不倒退**（任意导入顺序、迟到旧围栏证据都不会倒退）。
- **重启**：归档日志落盘 `data/evidence/evidence-archive.log`，重启逐条重放重建投影，
  **报告摘要（reportDigest）与冲突列表与重启前逐字节一致**；重复导入仍命中原回执。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/evidence/keys/rotate` | 轮换证据签名密钥 → `{keyId, publicKeyPem}`（私钥只存 sidecar 0600） |
| GET | `/api/evidence/keys` | 公钥列表（绝无私钥） |
| POST | `/api/evidence/trust/issuers` | 手动登记包签发方公钥 `{keyId, publicKeyPem}` |
| POST | `/api/evidence/sign` | 演示工具：对未签名证据包正文签名（私钥不出进程） |
| POST | `/api/evidence/demo/bundle` | 生成演示证据包 `{scenario, tamper?, packageId?, gatewayId?}` |
| POST | `/api/evidence/import` | 导入证据包 `{bundle}`（201 新归档 / 200 幂等重复；错误码见上表） |
| GET | `/api/evidence/packages` | 归档列表（当前围栏/进度/冲突数/报告摘要） |
| GET | `/api/evidence/packages/:id` | 归档详情（时间线、回执、冲突隔离区、报告摘要） |
| GET | `/api/evidence/packages/:id/report` | 核验报告 JSON + `reportDigest` |
| GET | `/api/evidence/packages/:id/report/download?format=text\|json` | 下载报告（attachment，全脱敏） |
| GET | `/api/evidence/conflicts?packageId=` | 冲突隔离区（全部或按包） |
| GET | `/api/evidence/state` | 模块状态（模式/计数/链校验） |
| GET | `/api/evidence/verify` | 独立复验：归档链 + 全部报告摘要重算 |
| GET | `/api/evidence/log?type=&limit=` | 原始归档日志（已脱敏） |
| POST | `/api/evidence/reset` | 清空归档与密钥（演示复位） |

## 归档台页面（`http://localhost:8092/`）

1. **① 证据签名密钥**：轮换生成、查看公钥（私钥永不上屏）。
2. **② 导入证据包**：按场景生成演示包（含篡改场景）或粘贴 JSON 导入；结果展示回执。
3. **③ 冲突隔离区**：全部冲突（保留方 / 隔离方证据均可查）。
4. **④ 归档列表**：按 packageId 汇总当前围栏、进度、冲突数、报告摘要。
5. **⑤ 归档详情**：确定时间线（按围栏与分段序号）、回执、核验报告与下载。

页面与接口**不展示** uploadSecret、私钥或未脱敏凭据；导出的报告只含脱敏后的证据。

## 文件

```
archiver/
  evidence.js     领域核心：校验管线 + 归档投影 + 冲突隔离 + 报告生成（确定性）
  keys.js         证据签名密钥库（Ed25519，私钥 sidecar 0600，链上只有公钥）
  gateway-sdk.js  网关侧证据 SDK（演示/测试：本地建链、算摘要、导出签名证据包）
  report-text.js  可阅读文本报告渲染
  server.js       HTTP API + 静态归档台（默认 8092）
  public/         归档台页面（index.html + app.js）
  demo.mjs        一键演示 7 场景
  e2e.mjs         45 项真实 HTTP 端到端断言（含真实重启）
data/evidence/    evidence-archive.log（只增哈希链）+ evidence-keys.json（0600）
```
