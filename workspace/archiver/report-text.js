// 核验报告的纯文本渲染（可阅读、可下载）。只使用已脱敏的归档投影。
import { iso } from '../src/util.js';

function fmtAt(at) {
  return Number.isFinite(at) ? iso(at) : '—';
}

function countsLine(c) {
  return `合并 ${c.merged}/${c.total}（执行 ${c.executed} · 跳过 ${c.skipped} · 失败 ${c.failed} · 剩余 ${c.remaining}）`;
}

export function renderReportText(report, reportDigest) {
  const L = [];
  const hr = '─'.repeat(64);
  L.push('现场网关离线作业包 · 证据核验报告');
  L.push(hr);
  L.push(`作业包：${report.packageId}`);
  L.push(`清单哈希：${report.manifest.manifestHash}`);
  L.push(`签发方：${report.manifest.issuerKeyId} · 事件 ${report.manifest.eventId ?? '—'} · 设备 ${report.manifest.deviceCount} 台`);
  L.push(`证据包数：${report.generatedFrom.bundles} · 归档水位 seq=${report.generatedFrom.archiveSeqHigh}`);
  L.push(`报告摘要 reportDigest：${reportDigest}`);
  L.push('');
  L.push('■ 当前进度（当前围栏，旧围栏证据不计入）');
  L.push(hr);
  L.push(`当前围栏：fence ${report.currentFence}`);
  L.push(`当前进度：${countsLine(report.currentProgress.counts)}`);
  L.push(`当前围栏序号：${report.currentProgress.appliedSeqs.join(', ') || '（无）'}`);
  L.push(`继承自旧围栏的历史回执：${report.inheritedProgress.count} 条${report.inheritedProgress.seqs.length ? `（序号 ${report.inheritedProgress.seqs.join(', ')}）` : ''}——可查询，不算当前进度`);
  L.push('');
  L.push('■ 合并检查点（多围栏按规则合并，单调不倒退）');
  L.push(hr);
  const mc = report.mergedCheckpoint;
  L.push(`围栏 ${mc.fence} · 水位 ${mc.watermark} · ${countsLine(mc.counts)}`);
  L.push(`已合并序号：${mc.appliedSeqs.join(', ') || '（无）'}`);
  L.push(`检查点令牌：${mc.checkpointToken}`);
  L.push('');
  L.push('■ 围栏时间线');
  L.push(hr);
  for (const f of report.fences) {
    L.push(`fence ${f.fence} [${f.status === 'CURRENT' ? '当前' : '历史'}] 网关 ${f.gatewayIds.join(', ') || '—'} · 分段 ${f.segmentsAccepted} 段 · ${countsLine(f.counts)}`);
    for (const c of f.changes) {
      L.push(`    ${c.kind} · 网关 ${c.gatewayId}${c.fromGatewayId ? ` · 自 ${c.fromGatewayId}` : ''}${c.toGatewayId ? ` · 至 ${c.toGatewayId}` : ''} · 归档 seq ${c.archiveSeq} · ${fmtAt(c.at)}`);
    }
  }
  L.push('');
  L.push('■ 证据时间线（按归档顺序，确定可复算）');
  L.push(hr);
  for (const t of report.timeline) {
    const seg = t.type === 'SEGMENT' ? ` 分段 ${t.segSeq}` : '';
    const fence = t.fence != null ? ` fence ${t.fence}` : '';
    const status = {
      MERGED: '已合并', DUPLICATE: '幂等重复', QUARANTINED: '冲突隔离', RECORDED: '已记录',
    }[t.status] || t.status;
    L.push(`#${t.order} [归档 seq ${t.archiveSeq} · 链 ${t.chainSeq}] ${t.type}${fence}${seg} · ${status}${t.conflictId ? `（${t.conflictId}）` : ''} · 网关 ${t.gatewayId} · ${fmtAt(t.at)}`);
  }
  L.push('');
  L.push('■ 冲突隔离区（已保存证据永不覆盖，冲突双方均保留）');
  L.push(hr);
  if (!report.conflicts.length) L.push('（无冲突）');
  for (const c of report.conflicts) {
    L.push(`${c.conflictId} [${c.kind}] fence ${c.fence}${c.segSeq != null ? ` 分段 ${c.segSeq}` : ''}${c.seq != null ? ` 序号 ${c.seq}` : ''} · 检出于归档 seq ${c.detectedAtSeq}`);
    L.push(`    保留：${c.kept.segmentHash || c.kept.contentHash}（${c.kept.gatewayId} · 归档 seq ${c.kept.archiveSeq}）`);
    L.push(`    隔离：${c.rejected.segmentHash || c.rejected.contentHash}（${c.rejected.gatewayId} · 归档 seq ${c.rejected.archiveSeq}）`);
  }
  L.push('');
  L.push('■ 校验结论');
  L.push(hr);
  L.push(`已核验证据包 ${report.verification.bundlesVerified} 个：签名 ${report.verification.allSignaturesValid ? '全部有效' : '存在失败'} · 哈希链 ${report.verification.allChainsValid ? '全部完整' : '存在断链'} · 被拒绝的导入 ${report.verification.rejectedImports} 次`);
  if (report.checkpointWarnings.length) {
    L.push(`检查点告警 ${report.checkpointWarnings.length} 条：`);
    for (const w of report.checkpointWarnings) L.push(`    [${w.warning}] fence ${w.fence} · ${w.reason}`);
  } else {
    L.push('检查点交叉核验：无告警');
  }
  L.push('');
  L.push(`脱敏声明：${report.redaction.note}`);
  L.push('');
  return L.join('\n');
}
