# 证据归档与冲突核验模块（现场网关离线作业包）

断网期间多个现场网关各自保存**同一作业包**的清单、围栏变更、分段回执与检查点。运营人员通过
网页或 HTTP 接口导入这些**带签名的证据包**；模块校验规范化签名与哈希链后，按 `packageId` 归档，
并生成**可阅读、可下载的核验报告**。零依赖，纯 Node.js ≥ 20，独立进程（默认端口 **8092**）。

```bash
npm run evidence                 # 启动服务 → http://localhost:8092/
npm run demo:evidence            # 一键演示 9 个场景（有效/重复/冲突/多围栏/倒退/篡改/错签）
npm run demo:evidence -- --print # 输出可直接粘到网页的示例信封（含两个网关公钥）
npm run test:e2e:evidence        # 83 项真实 HTTP 断言（含真实进程重启）
```

## 信任模型与密钥纪律

- **网关私钥（Ed25519）只存在于网关/制包工具侧**，服务从不接收；注册接口只收 SPKI 公钥 PEM，
  收到私钥材料直接 `PRIVATE_KEY_REJECTED`。
- **upload secret** 用于导入鉴权，仅经请求头 `X-Upload-Secret` 传输，常量时间比较；
  存于 `data/evidence/upload-secret.json`（**0600**；环境变量 `EVIDENCE_UPLOAD_SECRET` 优先），
  任何响应、页面、日志、导出报告都**不回显**该值。
- 被拒绝的信封原样落盘到 `data/evidence/rejected/`（**0600**，仅审计用），不进入证据链。

## 证据信封（可独立复算）

```jsonc
{
  "schema": "offline-evidence/1",
  "packageId": "PKG-001",
  "gatewayId": "gw-A",
  "keyId": "gw-key-1",
  "records": [ /* manifest / fence / segment / checkpoint */ ],
  "envelopeHash": "<sha256(canonicalJSON({schema,packageId,gatewayId,keyId,records}))>",
  "signature": "<Ed25519 网关私钥对 envelopeHash hex 文本的签名>"
}
```

规范化规则：键名字典序、无多余空白（见 `hashing.js#canonicalJSON`，任意语言可复算）。
记录字段有**严格白名单**，夹带未知字段整包拒绝。四类记录：

| kind | 关键字段 |
| --- | --- |
| `manifest` | `manifest.entries[{seq,deviceId}]`、`issuedAt`、`validUntil`、`manifestHash`（内容不自洽即 `MANIFEST_HASH_MISMATCH`） |
| `fence` | `fenceId`、`version`（全局只增、必须连续）、`action: CREATED/REVISED/CLOSED`、`prevVersion` |
| `segment` | `fenceId`、`fenceVersion`、`segSeq`（同围栏严格递增）、`entries[{seq,deviceId,outcome,note?}]`（序号/设备必须与清单一致） |
| `checkpoint` | `fenceVersion`、`lastSeq`、`counts{EXECUTED,SKIPPED,FAILED}` |

## 裁决流水线（严格顺序）

1. **结构**：信封/记录形状、字段白名单；
2. **信封哈希**：规范化复算，任何字节被改 → `ENVELOPE_HASH_MISMATCH`；
3. **注册表 + Ed25519 验签**：未知网关 `GATEWAY_UNKNOWN`，keyId 不符 `SIGNATURE_KEY_MISMATCH`，
   签名失败 `SIGNATURE_INVALID`（**先验签后查重复**，错签信封不能借"同哈希重复"放行）；
4. **重复导入**：同一 `envelopeHash` 返回**首次裁决原结果**（同 `importId`、同首次时间、同 disposition）；
5. **业务规则**：manifest 首位、序号/设备范围、围栏版本连续（`FENCE_VERSION_GAP`）、
   引用围栏存在（`FENCE_UNKNOWN`）、分段号递增；
6. **槽位裁决（原子）**：
   - 同槽位（manifest / `fence:id:v#` / `segment:id:v#:seg#` / `checkpoint:id:v#`）**同语义指纹** → 幂等跳过；
   - **不同指纹 → 冲突隔离**：原证据写入 `quarantine.jsonl`（保留外来+已存双指纹），
     **已存证据绝不覆盖**；
   - 检查点跨围栏**不倒退**：新版本 `lastSeq` 低于历史最高 → `CHECKPOINT_REGRESSED` 隔离；
   - `CLOSED` 是围栏生命周期推进（独立槽），重复 CLOSED 幂等。

> **语义指纹**只覆盖业务字段（不含 `ts`、网关身份、信封哈希），所以同内容由不同网关、
> 不同时刻重传判为**重复**而非冲突；同分段号但 outcome/note 不同则判**冲突**。

## 落盘与重启（摘要不变）

每个包目录 `data/evidence/packages/<packageId>/` 下三条独立 SHA-256 哈希链（各自 genesis 锚定
`packageId`，跨包/跨链调换即断）：

```
ledger.jsonl      已接受证据（只增，永不覆盖/删除）
quarantine.jsonl  冲突隔离的原证据（含已存证据指纹）
audit.jsonl       每次导入裁决（ACCEPTED / DUPLICATE / CONFLICTS）
```

- 进程重启时逐行重放重建全部投影；**报告摘要 `reportDigest`、冲突列表、链尖重启前后完全一致**。
- 链文件**中途损坏/断链/哈希不符** → 该链只读隔离（503 `CHAIN_QUARANTINED`），文件原样保留；
- 仅文件**末尾单条无换行残尾**（断电）→ 原始字节归档到同目录旁证后截断续链。

## 核验报告

- **确定性时间线**：按 `(围栏版本, 事件类别, 分段序号, ts, ledgerSeq)` 排序，
  围栏创建/关闭、分段回执、检查点交错呈现；
- **多围栏合并**：当前围栏=最高版本；当前检查点从高版本向低版本取第一个有效水位，
  高版本尚无检查点时**沿用上一围栏水位（carried）**，绝不因新围栏把水位归零；
- **旧围栏证据仍可查询**（`GET .../fences/:version`），但显式标注"不得作为当前进度"；
- 报告导出三种格式，**全部经递归脱敏**（敏感键名、私钥 PEM、密钥字面量一律打码）：
  - `GET /api/packages/:id/report.json`（下载，带 `redaction.applied`）
  - `GET /api/packages/:id/report.txt`（可阅读文本）
  - `GET /api/packages/:id/report.html`（可内嵌 HTML 片段）
- `reportDigest = sha256(canonicalJSON(确定性语义字段 + 三链链尖 + 时间线 + 冲突 + 裁决))`，
  不含生成时间/接收时间等易变项——重复导入与重启都不改变它。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/gateways` | 登记网关公钥（需 `X-Upload-Secret`；拒收私钥） |
| GET | `/api/gateways` | 已登记网关列表 |
| POST | `/api/packages/:id/import` | 导入证据信封（201 ACCEPTED / 200 CONFLICTS或DUPLICATE；拒绝 4xx） |
| GET | `/api/packages` | 包列表（摘要/当前围栏/水位/冲突数） |
| GET | `/api/packages/:id/report` | 完整脱敏报告（JSON） |
| GET | `/api/packages/:id/report.{json,txt,html}` | 下载/预览脱敏报告 |
| GET | `/api/packages/:id/timeline` | 确定性时间线 |
| GET | `/api/packages/:id/conflicts` | 冲突隔离清单 |
| GET | `/api/packages/:id/fences/:version` | 指定围栏证据（旧围栏标注"不充当进度"） |
| GET | `/api/packages/:id/imports` | 导入裁决历史 |
| GET | `/api/packages/:id/verify` | 三包哈希链校验 |
| GET | `/api/chain/verify` | 全部包链校验 |
| POST | `/api/admin/restart` | 丢弃内存投影并从磁盘重放（等价进程重启，便于页面核对） |

环境变量：`EVIDENCE_PORT`（默认 8092）、`EVIDENCE_HOST`、`EVIDENCE_DIR`
（默认 `data/evidence`）、`EVIDENCE_UPLOAD_SECRET`、`EVIDENCE_DEMO=1`（开启本机密钥对演示接口）。

## 目录

```
evidence/
  hashing.js   规范化 JSON / 记录哈希 / 语义指纹 / 槽位 / 递归脱敏 / 安全日志字段
  crypto.js    Ed25519 验签、upload secret sidecar(0600)、网关公钥注册表、常量时间比较
  pack.js      网关侧制包 SDK（buildEnvelope/R.manifest/R.fence/...），供任意实现对照
  chains.js    通用 JSONL 哈希链（残尾恢复 / 损坏只读隔离）
  archive.js   归档内核：校验流水线、槽位去重/冲突、三链落账、ArchiveManager
  report.js    报告纯函数投影 + 确定性摘要 + JSON/TXT/HTML 脱敏渲染
  server.js    HTTP API + 网页 + 脱敏结构化日志
  demo.mjs     9 场景一键演示 / --print 输出示例信封
  public/      运营页面（index.html + app.js）
scripts/evidence-e2e.mjs  83 项真实 HTTP 端到端断言（含真实进程重启）
test/evidence.test.js     22 个领域单测
```
