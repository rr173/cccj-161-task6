// 核验报告投影：纯函数，从三条链重建，重启后逐字节相同。
//
// 报告给出：
//  - 按围栏（版本号）与分段序号的【确定性时间线】；
//  - 当前围栏（最高版本，CLOSED 则标注 closedAt）与当前检查点（跨围栏不倒退水位）；
//  - 冲突隔离清单（原证据保留、不覆盖，旧围栏证据可查但不充当当前进度）；
//  - 稳定摘要 reportDigest：只覆盖确定性字段（不含 receivedAt/导入时间等易变项），
//    重复导入不改变摘要，重启后摘要与冲突列表不变。
import { canonicalJSON, sha256Hex, REPORT_SCHEMA, redact } from './hashing.js';

function recBySeq(archive) {
  return archive.ledger.records;
}

// 重建围栏视图：每个版本一条；closed 版本保留但不再是当前围栏。
function buildFences(records) {
  const byVersion = new Map();
  for (const r of records) {
    if (r.kind !== 'fence') continue;
    const v = byVersion.get(r.version) || {
      version: r.version, fenceId: null, createdAt: null, closedAt: null,
      createGateways: [], segments: [], checkpoints: [],
    };
    if (r.action === 'CREATED') {
      v.fenceId = r.fenceId;
      v.createdAt = r.ts;
      if (!v.createGateways.includes(r.gatewayId)) v.createGateways.push(r.gatewayId);
    }
    if (r.action === 'CLOSED') {
      v.closedAt = r.ts;
      v.closedBy = r.gatewayId;
      v.closeDetail = r.detail ?? null;
    }
    byVersion.set(r.version, v);
  }
  return [...byVersion.values()].sort((a, b) => a.version - b.version);
}

function entryKey(e) {
  return { seq: e.seq, deviceId: e.deviceId, outcome: e.outcome, note: e.note ?? null };
}

export function buildReport(archive) {
  const records = recBySeq(archive);
  const manifest = records.find((r) => r.kind === 'manifest') || null;
  const fences = buildFences(records);

  // 分段挂到对应围栏版本；同槽位只有一条（其余在冲突链），按 segSeq 排序。
  for (const r of records) {
    if (r.kind !== 'segment') continue;
    const f = fences.find((x) => x.version === r.fenceVersion);
    if (!f) continue; // 理论不可能（引用校验已拒）
    f.segments.push({
      segSeq: r.segSeq,
      ts: r.ts,
      gatewayId: r.gatewayId,
      entries: r.entries.map(entryKey),
      ledgerSeq: r.seq,
      fingerprint: r.fingerprint,
      slot: r.slot,
    });
  }
  for (const f of fences) f.segments.sort((a, b) => a.segSeq - b.segSeq || a.ledgerSeq - b.ledgerSeq);

  // 检查点（每版本取 ledger 中最后一条已接受记录；同槽位冲突不入链）。
  for (const r of records) {
    if (r.kind !== 'checkpoint') continue;
    const f = fences.find((x) => x.version === r.fenceVersion);
    if (!f) continue;
    f.checkpoints.push({
      ts: r.ts, gatewayId: r.gatewayId, lastSeq: r.lastSeq,
      counts: { ...r.counts }, ledgerSeq: r.seq, fingerprint: r.fingerprint,
    });
  }
  for (const f of fences) f.checkpoints.sort((a, b) => a.ledgerSeq - b.ledgerSeq);
  for (const f of fences) f.checkpoint = f.checkpoints.at(-1) || null;

  // 当前围栏 = 最高版本；其状态决定当前检查点是否视为活动进度。
  const currentVersion = fences.length ? fences[fences.length - 1].version : null;
  const currentFence = currentVersion ? fences.find((f) => f.version === currentVersion) : null;

  // 当前检查点（多围栏按规则合并、不倒退）：
  //  从最高版本围栏向下，取第一个拥有已接受检查点的围栏——
  //  导入校验已保证新版本 lastSeq 不低于旧版本，故该水位必然不回退；
  //  高版本还没产生检查点时沿用上一围栏水位（carried，可查旧证据）。
  let progress = null;
  for (const f of [...fences].reverse()) {
    if (f.checkpoint) {
      progress = {
        fenceVersion: f.version,
        fenceId: f.fenceId,
        lastSeq: f.checkpoint.lastSeq,
        counts: { ...f.checkpoint.counts },
        checkpointTs: f.checkpoint.ts,
        active: !f.closedAt,
        carried: f.version !== currentVersion,
      };
      break;
    }
  }

  // 确定性时间线：围栏事件（CREATED/CLOSED）与分段交错，按
  // (fenceVersion, rank, segSeq, ts, ledgerSeq) 排序。
  const timeline = [];
  for (const r of records) {
    if (r.kind === 'fence') {
      timeline.push({
        fenceVersion: r.version,
        rank: 0,
        segSeq: 0,
        ts: r.ts,
        type: r.action === 'CREATED' ? 'FENCE_CREATED' : 'FENCE_CLOSED',
        fenceId: r.fenceId,
        gatewayId: r.gatewayId,
        detail: r.detail ?? null,
        ledgerSeq: r.seq,
      });
    } else if (r.kind === 'segment') {
      timeline.push({
        fenceVersion: r.fenceVersion,
        rank: 1,
        segSeq: r.segSeq,
        ts: r.ts,
        type: 'SEGMENT_ACCEPTED',
        fenceId: r.fenceId,
        gatewayId: r.gatewayId,
        entries: r.entries.map(entryKey),
        ledgerSeq: r.seq,
      });
    } else if (r.kind === 'checkpoint') {
      timeline.push({
        fenceVersion: r.fenceVersion,
        rank: 2,
        segSeq: 0,
        ts: r.ts,
        type: 'CHECKPOINT',
        fenceId: r.fenceId,
        gatewayId: r.gatewayId,
        lastSeq: r.lastSeq,
        counts: { ...r.counts },
        ledgerSeq: r.seq,
      });
    } else if (r.kind === 'manifest') {
      timeline.push({
        fenceVersion: 0,
        rank: 0,
        segSeq: 0,
        ts: r.ts,
        type: 'MANIFEST_ARCHIVED',
        gatewayId: r.gatewayId,
        manifestHash: r.manifestHash,
        entryCount: r.manifest.entries.length,
        ledgerSeq: r.seq,
      });
    }
  }
  timeline.sort((a, b) =>
    (a.fenceVersion - b.fenceVersion) ||
    (a.rank - b.rank) ||
    (a.segSeq - b.segSeq) ||
    (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0) ||
    (a.ledgerSeq - b.ledgerSeq));

  // 冲突隔离清单（quarantine 链），确定性排序：seq（归档顺序）。
  const conflicts = archive.quarantine.records.map((q) => ({
    seq: q.seq,
    at: q.at,
    importId: q.importId,
    envelopeHash: q.envelopeHash,
    gatewayId: q.gatewayId,
    slot: q.slot,
    reason: q.reason,
    kind: q.record.kind,
    fingerprint: q.fingerprint,
    existingFingerprint: q.existingFingerprint ?? null,
    fenceVersion: q.record.fenceVersion ?? null,
    segSeq: q.record.segSeq ?? null,
    ts: q.record.ts,
    detail: conflictDetail(q),
    ledgerSeq: q.seq,
  }));

  // 导入裁决历史（去重/冲突/接受全部留痕），仅取确定性字段。
  const imports = archive.audit.records
    .filter((r) => r.kind === 'IMPORT')
    .map((r) => ({
      at: r.at,
      importId: r.importId,
      envelopeHash: r.envelopeHash,
      gatewayId: r.gatewayId,
      result: r.result,
      recordsAccepted: r.disposition.recordsAccepted,
      recordsDuplicate: r.disposition.recordsDuplicate,
      recordsConflicted: r.disposition.recordsConflicted,
    }));

  const evidence = {
    manifest: manifest ? {
      manifestHash: manifest.manifestHash,
      ts: manifest.ts,
      issuedAt: manifest.manifest.issuedAt,
      validUntil: manifest.manifest.validUntil,
      entries: [...manifest.manifest.entries]
        .sort((a, b) => a.seq - b.seq)
        .map((e) => ({ seq: e.seq, deviceId: e.deviceId })),
      ledgerSeq: manifest.seq,
    } : null,
    fenceCount: fences.length,
    fences: fences.map((f) => ({
      version: f.version,
      fenceId: f.fenceId,
      createdAt: f.createdAt,
      closedAt: f.closedAt,
      closedBy: f.closedBy || null,
      isCurrent: f.version === currentVersion,
      segmentCount: f.segments.length,
      segmentSeqs: f.segments.map((s) => s.segSeq),
      checkpoint: f.checkpoint ? {
        ts: f.checkpoint.ts, lastSeq: f.checkpoint.lastSeq,
        counts: f.checkpoint.counts, gatewayId: f.checkpoint.gatewayId,
      } : null,
    })),
    currentFence: currentFence ? {
      version: currentFence.version,
      fenceId: currentFence.fenceId,
      createdAt: currentFence.createdAt,
      closed: Boolean(currentFence.closedAt),
      closedAt: currentFence.closedAt,
    } : null,
    currentProgress: progress,
    acceptedRecordCount: archive.ledger.records.length,
    conflictCount: conflicts.length,
    conflicts,
    timeline,
  };

  const summary = digestMaterial(archive, evidence);
  const reportDigest = sha256Hex(canonicalJSON({ schema: REPORT_SCHEMA, ...summary }));

  return {
    schema: REPORT_SCHEMA,
    packageId: archive.packageId,
    reportDigest,
    generated: {
      // 展示用时间，不参与摘要；重启/重复导入不影响 reportDigest。
      at: new Date().toISOString(),
    },
    chainTips: {
      ledger: { seq: archive.ledger.seq, hash: archive.ledger.tipHash },
      quarantine: { seq: archive.quarantine.seq, hash: archive.quarantine.tipHash },
      audit: { seq: archive.audit.seq, hash: archive.audit.tipHash },
    },
    imports,
    ...evidence,
  };
}

function conflictDetail(q) {
  const r = q.record;
  if (r.kind === 'segment') {
    return {
      fenceId: r.fenceId,
      fenceVersion: r.fenceVersion,
      segSeq: r.segSeq,
      entries: r.entries.map(entryKey),
    };
  }
  if (r.kind === 'fence') {
    return { fenceId: r.fenceId, version: r.version, action: r.action, prevVersion: r.prevVersion, detail: r.detail ?? null };
  }
  if (r.kind === 'checkpoint') {
    return { fenceId: r.fenceId, fenceVersion: r.fenceVersion, lastSeq: r.lastSeq, counts: { ...r.counts }, ...(q.reason === 'CHECKPOINT_REGRESSED' ? { priorMaxLastSeq: q.priorMaxLastSeq } : {}) };
  }
  if (r.kind === 'manifest') {
    return { manifestHash: r.manifestHash, entryCount: r.manifest.entries.length };
  }
  return {};
}

// 摘要材料：只含确定性语义字段（不含 generated.at / receivedAt / gateway 自由字段等易变项）。
function digestMaterial(archive, ev) {
  return {
    packageId: archive.packageId,
    ledgerTipHash: archive.ledger.tipHash,
    ledgerTipSeq: archive.ledger.seq,
    quarantineTipHash: archive.quarantine.tipHash,
    quarantineTipSeq: archive.quarantine.seq,
    auditTipHash: archive.audit.tipHash,
    auditTipSeq: archive.audit.seq,
    manifestHash: ev.manifest?.manifestHash ?? null,
    currentFence: ev.currentFence ? {
      version: ev.currentFence.version,
      fenceId: ev.currentFence.fenceId,
      closed: ev.currentFence.closed,
    } : null,
    currentProgress: ev.currentProgress ? {
      fenceVersion: ev.currentProgress.fenceVersion,
      lastSeq: ev.currentProgress.lastSeq,
      counts: ev.currentProgress.counts,
      active: ev.currentProgress.active,
      carried: ev.currentProgress.carried,
    } : null,
    timeline: ev.timeline.map((t) => ({
      fenceVersion: t.fenceVersion, rank: t.rank, segSeq: t.segSeq,
      type: t.type, ts: t.ts, ledgerSeq: t.ledgerSeq,
      entries: t.entries ? t.entries.map(entryKey) : undefined,
      lastSeq: t.lastSeq, counts: t.counts,
    })),
    conflicts: ev.conflicts.map((c) => ({
      slot: c.slot, reason: c.reason, kind: c.kind,
      fingerprint: c.fingerprint, existingFingerprint: c.existingFingerprint,
      envelopeHash: c.envelopeHash,
    })),
    imports: archive.audit.records
      .filter((r) => r.kind === 'IMPORT')
      .map((r) => ({
        envelopeHash: r.envelopeHash, gatewayId: r.gatewayId, result: r.result,
        recordsAccepted: r.disposition.recordsAccepted,
        recordsDuplicate: r.disposition.recordsDuplicate,
        recordsConflicted: r.disposition.recordsConflicted,
      })),
  };
}

// ---------- 导出（仅脱敏证据；upload secret / 私钥等永不出现） ----------

// 导出 JSON：递归脱敏。literals 为进程内密钥原文，任何自由文本里出现也会打码。
export function exportRedactedJSON(report, literals = []) {
  const out = redact({
    schema: report.schema,
    packageId: report.packageId,
    reportDigest: report.reportDigest,
    generatedAt: report.generated.at,
    chainTips: report.chainTips,
    manifest: report.manifest,
    currentFence: report.currentFence,
    currentProgress: report.currentProgress,
    fences: report.fences,
    timeline: report.timeline,
    conflicts: report.conflicts,
    imports: report.imports,
  }, literals);
  out.redaction = { applied: true, note: '导出仅含脱敏证据；凭据/私钥/上传密钥已移除或打码' };
  return out;
}

// 可阅读文本报告（.txt），同样只含脱敏内容。
export function renderText(report) {
  const L = [];
  L.push('证据归档核验报告');
  L.push('================');
  L.push(`packageId   : ${report.packageId}`);
  L.push(`报告摘要     : ${report.reportDigest}`);
  L.push(`证据链       : seq=${report.chainTips.ledger.seq} tip=${report.chainTips.ledger.hash.slice(0, 16)}…`);
  L.push(`冲突链       : seq=${report.chainTips.quarantine.seq} tip=${report.chainTips.quarantine.hash.slice(0, 16)}…`);
  L.push(`裁决链       : seq=${report.chainTips.audit.seq} tip=${report.chainTips.audit.hash.slice(0, 16)}…`);
  L.push('');
  if (report.manifest) {
    L.push(`清单 manifest: hash=${report.manifest.manifestHash}`);
    L.push(`  条目数=${report.manifest.entries.length}，issuedAt=${report.manifest.issuedAt ?? '-'}，validUntil=${report.manifest.validUntil ?? '-'}`);
  }
  const cf = report.currentFence;
  if (cf) {
    L.push(`当前围栏     : v${cf.version} fenceId=${cf.fenceId} ${cf.closed ? `已关闭(${cf.closedAt})` : '活动中'}`);
  } else {
    L.push('当前围栏     : （无）');
  }
  if (report.currentProgress) {
    const p = report.currentProgress;
    L.push(`当前检查点   : fence=v${p.fenceVersion} lastSeq=${p.lastSeq} ` +
      `EXECUTED=${p.counts.EXECUTED} SKIPPED=${p.counts.SKIPPED} FAILED=${p.counts.FAILED}` +
      `${p.carried ? '（沿用上一围栏水位，不倒退）' : ''}${p.active ? '' : '（围栏已关闭，仅历史可查）'}`);
  } else {
    L.push('当前检查点   : （无）');
  }
  L.push('');
  L.push('-- 时间线（按围栏版本 / 分段序号，确定性排序）--');
  for (const t of report.timeline) {
    const fence = t.fenceVersion === 0 ? 'manifest' : `fence v${t.fenceVersion}`;
    if (t.type === 'SEGMENT_ACCEPTED') {
      L.push(`[${t.ts}] ${fence} seg#${t.segSeq} SEGMENT (${t.entries.length} 条) 网关=${t.gatewayId}`);
      for (const e of t.entries) {
        L.push(`           - seq=${e.seq} device=${e.deviceId} outcome=${e.outcome}${e.note ? ` note=${e.note}` : ''}`);
      }
    } else if (t.type === 'CHECKPOINT') {
      L.push(`[${t.ts}] ${fence} CHECKPOINT lastSeq=${t.lastSeq} ` +
        `E=${t.counts.EXECUTED}/S=${t.counts.SKIPPED}/F=${t.counts.FAILED} 网关=${t.gatewayId}`);
    } else if (t.type === 'FENCE_CREATED') {
      L.push(`[${t.ts}] ${fence} FENCE CREATED fenceId=${t.fenceId} 网关=${t.gatewayId}${t.detail ? ` detail=${t.detail}` : ''}`);
    } else if (t.type === 'FENCE_CLOSED') {
      L.push(`[${t.ts}] ${fence} FENCE CLOSED fenceId=${t.fenceId} 网关=${t.gatewayId}${t.detail ? ` detail=${t.detail}` : ''}`);
    } else {
      L.push(`[${t.ts}] ${fence} ${t.type} 网关=${t.gatewayId}`);
    }
  }
  L.push('');
  L.push(`-- 冲突隔离（${report.conflicts.length}）--`);
  if (!report.conflicts.length) L.push('（无冲突）');
  for (const c of report.conflicts) {
    L.push(`#${c.seq} [${c.at}] ${c.reason} slot=${c.slot} 网关=${c.gatewayId}`);
    L.push(`     外来指纹=${c.fingerprint.slice(0, 16)}… 已存指纹=${(c.existingFingerprint || '').slice(0, 16)}… 信封=${c.envelopeHash.slice(0, 16)}…`);
  }
  L.push('');
  L.push(`-- 导入裁决（${report.imports.length}）--`);
  for (const i of report.imports) {
    L.push(`[${i.at}] ${i.result} 网关=${i.gatewayId} 接受=${i.recordsAccepted} 重复=${i.recordsDuplicate} 冲突=${i.recordsConflicted} 信封=${i.envelopeHash.slice(0, 16)}…`);
  }
  L.push('');
  L.push('（本报告仅含脱敏证据；不含 upload secret / 私钥 / 未脱敏凭据）');
  return L.join('\n') + '\n';
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
}

// HTML 片段（由前端页面 fetch 后嵌入；同样只含脱敏内容）。
export function renderHTMLFragment(report) {
  const rows = report.timeline.map((t) => {
    const fence = t.fenceVersion === 0 ? 'manifest' : `v${t.fenceVersion}`;
    const body = t.type === 'SEGMENT_ACCEPTED'
      ? t.entries.map((e) => `seq=${e.seq} · ${esc(e.deviceId)} · ${esc(e.outcome)}${e.note ? ` · ${esc(e.note)}` : ''}`).join('<br>')
      : t.type === 'CHECKPOINT'
        ? `lastSeq=${t.lastSeq} E/S/F=${t.counts.EXECUTED}/${t.counts.SKIPPED}/${t.counts.FAILED}`
        : `${esc(t.type)}${t.detail ? ' · ' + esc(t.detail) : ''}`;
    return `<tr><td>${esc(t.ts)}</td><td>${esc(fence)}</td><td>${t.segSeq ? `#${t.segSeq}` : ''}</td>` +
      `<td>${esc(t.type)}</td><td>${body}</td><td>${esc(t.gatewayId)}</td></tr>`;
  }).join('');
  const conflicts = report.conflicts.map((c) =>
    `<tr><td>${c.seq}</td><td>${esc(c.reason)}</td><td>${esc(c.slot)}</td><td>${esc(c.gatewayId)}</td>` +
    `<td><code>${esc(c.fingerprint.slice(0, 20))}…</code></td><td><code>${esc((c.existingFingerprint || '').slice(0, 20))}…</code></td></tr>`).join('');
  return `<div class="report-head">
    <div>packageId：<b>${esc(report.packageId)}</b></div>
    <div>报告摘要：<code>${esc(report.reportDigest)}</code></div>
    <div>当前围栏：${report.currentFence ? `v${esc(String(report.currentFence.version))} · ${esc(report.currentFence.fenceId)} ${report.currentFence.closed ? '· <b>已关闭</b>' : '· 活动中'}` : '（无）'}</div>
    <div>当前检查点：${report.currentProgress ? `v${esc(String(report.currentProgress.fenceVersion))} lastSeq=${report.currentProgress.lastSeq} ${report.currentProgress.carried ? '· <b>沿用旧围栏水位（不倒退）</b>' : ''}${report.currentProgress.active ? '' : '· 围栏已关闭仅历史可查'}` : '（无）'}</div>
  </div>
  <h4>时间线（围栏 / 分段序号确定排序）</h4>
  <table class="grid"><thead><tr><th>时间</th><th>围栏</th><th>分段</th><th>事件</th><th>内容</th><th>网关</th></tr></thead><tbody>${rows || '<tr><td colspan=6>（无）</td></tr>'}</tbody></table>
  <h4>冲突隔离（${report.conflicts.length}）</h4>
  <table class="grid"><thead><tr><th>#</th><th>原因</th><th>槽位</th><th>网关</th><th>外来指纹</th><th>已存指纹</th></tr></thead><tbody>${conflicts || '<tr><td colspan=6>（无冲突）</td></tr>'}</tbody></table>
  <p class="muted" style="margin-top:10px">本报告仅含脱敏证据（REDACTED）；不含 upload secret / 私钥 / 未脱敏凭据。</p>`;
}
