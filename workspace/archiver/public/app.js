// 证据归档台前端逻辑。注意：本页面绝不渲染 uploadSecret / 私钥等凭据字段。
const $ = (id) => document.getElementById(id);
let selectedPackage = null;

async function api(path, opts = {}) {
  const res = await fetch(path, opts.method
    ? { method: opts.method, headers: { 'Content-Type': 'application/json' }, body: opts.body ? JSON.stringify(opts.body) : undefined }
    : undefined);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { status: res.status, data });
  return data;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function short(h, n = 12) {
  return h ? `${String(h).slice(0, n)}…` : '—';
}

function showResult(el, obj, ok = true) {
  el.className = `result ${ok ? 'ok' : 'err'}`;
  el.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

// ---------- 状态 ----------

async function loadState() {
  const s = await api('/api/evidence/state');
  const badge = $('modeBadge');
  if (s.mode === 'QUARANTINED') {
    badge.className = 'badge b-err';
    badge.textContent = '只读隔离';
    const r = s.recovery || {};
    $('quarantineBanner').textContent = `⛔ 归档日志已隔离（只读）：首个损坏位置 seq=${r.brokenAt ?? '?'}，原因：${r.reason ?? '未知'}。导入接口返回 503。`;
    $('quarantineBanner').className = 'banner quarantine show';
  } else {
    badge.className = 'badge b-ok';
    badge.textContent = `正常 · 归档 ${s.bundles} 包 · 冲突 ${s.conflicts}`;
    $('quarantineBanner').className = 'banner';
  }
}

// ---------- 密钥 ----------

async function rotateKey() {
  try {
    const k = await api('/api/evidence/keys/rotate', { method: 'POST', body: {} });
    showResult($('importResult'), `已生成证据签名密钥 ${k.keyId}（私钥仅存 sidecar 0600）`);
    await loadKeys();
  } catch (e) { showResult($('importResult'), `${e.data?.code || ''} ${e.message}`, false); }
}

async function loadKeys() {
  const { keys } = await api('/api/evidence/keys');
  $('keys').innerHTML = keys.length
    ? `<table><tr><th>keyId</th><th>公钥指纹</th><th>登记时间</th></tr>${keys.map((k) => `
        <tr><td class="mono">${esc(k.keyId)}</td><td class="mono small">${esc(short(k.publicKeyPem.replace(/\W/g, ''), 16))}</td><td class="muted">${esc(k.rotatedAt)}</td></tr>`).join('')}</table>`
    : '<p class="hint">尚未生成密钥。导入前请先轮换生成。</p>';
}

// ---------- 导入 ----------

async function genDemo() {
  try {
    const { bundle } = await api('/api/evidence/demo/bundle', {
      method: 'POST',
      body: {
        scenario: $('demoScenario').value,
        tamper: $('demoTamper').value || undefined,
        packageId: $('demoPackageId').value.trim() || undefined,
        gatewayId: $('demoGatewayId').value.trim() || undefined,
      },
    });
    // 页面展示前主动剔除 uploadSecrets（不脱敏的凭据不上屏）
    const view = { ...bundle, uploadSecrets: '<已脱敏：不在页面展示>' };
    $('bundleJson').value = JSON.stringify(bundle);
    showResult($('importResult'), `已生成演示证据包 ${bundle.bundleId}（${bundle.chain.length} 条链记录），点击“导入下方证据包”归档。\n${JSON.stringify(view, null, 2).slice(0, 600)}…`);
  } catch (e) { showResult($('importResult'), `${e.data?.code || ''} ${e.message}`, false); }
}

async function importBundle() {
  let bundle;
  try {
    bundle = JSON.parse($('bundleJson').value);
  } catch {
    showResult($('importResult'), '证据包不是合法 JSON', false);
    return;
  }
  try {
    const out = await api('/api/evidence/import', { method: 'POST', body: { bundle } });
    showResult($('importResult'), out);
    selectedPackage = out.packageId;
    await refreshAll();
    await openPackage(out.packageId);
  } catch (e) {
    showResult($('importResult'), e.data || e.message, false);
    await refreshAll();
  }
}

// ---------- 归档列表 / 详情 ----------

async function loadPackages() {
  const { packages } = await api('/api/evidence/packages');
  $('packages').innerHTML = packages.length
    ? `<table><tr><th>packageId</th><th>当前围栏</th><th>进度</th><th>证据包</th><th>冲突</th><th>报告摘要</th></tr>${packages.map((p) => `
        <tr class="clickable ${p.packageId === selectedPackage ? 'selected' : ''}" onclick="openPackage('${esc(p.packageId)}')">
          <td class="mono">${esc(p.packageId)}</td>
          <td>fence ${p.currentFence}</td>
          <td>${p.merged}/${p.total}</td>
          <td>${p.bundles}</td>
          <td>${p.conflicts ? `<span class="badge b-warn">${p.conflicts}</span>` : '<span class="badge b-ok">0</span>'}</td>
          <td class="mono small">${esc(short(p.reportDigest, 10))}</td>
        </tr>`).join('')}</table>`
    : '<p class="hint">暂无归档。导入证据包后在此出现。</p>';
}

async function openPackage(packageId) {
  selectedPackage = packageId;
  const v = await api(`/api/evidence/packages/${encodeURIComponent(packageId)}`);
  $('detailCard').style.display = '';
  $('detailPkg').textContent = packageId;
  const mc = v.mergedCheckpoint;
  $('detailSummary').innerHTML = `
    <div class="kv"><span class="k">当前围栏</span><span>fence ${v.currentFence}</span></div>
    <div class="kv"><span class="k">当前进度（当前围栏）</span><span>${v.currentProgress.counts.merged}/${v.currentProgress.counts.total}（序号 ${v.currentProgress.appliedSeqs.join(', ') || '无'}）</span></div>
    <div class="kv"><span class="k">继承历史回执</span><span>${v.inheritedProgress.count} 条（不计入当前进度）</span></div>
    <div class="kv"><span class="k">合并检查点</span><span>水位 ${mc.watermark} · ${mc.counts.merged}/${mc.counts.total}</span></div>
    <div class="kv"><span class="k">检查点令牌</span><span class="mono small">${esc(mc.checkpointToken)}</span></div>
    <div class="kv"><span class="k">报告摘要</span><span class="mono small">${esc(v.reportDigest)}</span></div>`;

  const statusName = { MERGED: '已合并', DUPLICATE: '幂等重复', QUARANTINED: '冲突隔离', RECORDED: '已记录' };
  const statusBadge = { MERGED: 'b-ok', DUPLICATE: 'b-pend', QUARANTINED: 'b-warn', RECORDED: 'b-pend' };
  $('tabBodyTimeline').innerHTML = `
    <table><tr><th>#</th><th>类型</th><th>围栏</th><th>分段</th><th>状态</th><th>网关</th><th>归档 seq</th></tr>
    ${v.timeline.map((t) => `<tr>
      <td>${t.order}</td><td>${t.type}</td><td>${t.fence ?? '—'}</td><td>${t.segSeq ?? '—'}</td>
      <td><span class="badge ${statusBadge[t.status] || 'b-pend'}">${statusName[t.status] || t.status}</span>${t.conflictId ? ` <span class="mono small">${esc(t.conflictId)}</span>` : ''}</td>
      <td class="mono">${esc(t.gatewayId)}</td><td>${t.archiveSeq}</td>
    </tr>`).join('')}</table>
    <p class="hint">围栏：${v.fences.map((f) => `fence ${f.fence}（${f.status === 'CURRENT' ? '当前' : '历史'} · ${f.gatewayIds.join('/')} · ${f.counts.merged} 条）`).join('；')}</p>`;

  $('tabBodyReceipts').innerHTML = v.receipts.length
    ? `<table><tr><th>序号</th><th>设备</th><th>结果</th><th>围栏</th><th>分段</th><th>网关</th></tr>
      ${v.receipts.map((r) => `<tr>
        <td>${r.seq}</td><td class="mono">${esc(r.deviceId)}</td><td>${esc(r.outcome)}</td>
        <td>${r.fence}</td><td>${r.segSeq}</td><td class="mono">${esc(r.gatewayId)}</td>
      </tr>`).join('')}</table>`
    : '<p class="hint">暂无已合并回执。</p>';

  const rep = await api(`/api/evidence/packages/${encodeURIComponent(packageId)}/report`);
  $('reportView').textContent = JSON.stringify({ ...rep.report, reportDigest: rep.reportDigest }, null, 2);
  await loadPackages();
}

function showTab(name) {
  for (const t of ['Timeline', 'Receipts', 'Report']) {
    $(`tabBody${t}`).style.display = 'none';
    $(`tab${t}`).className = '';
  }
  $(`tabBody${name[0].toUpperCase() + name.slice(1)}`).style.display = '';
  $(`tab${name[0].toUpperCase() + name.slice(1)}`).className = 'on';
}

function downloadReport(format) {
  if (!selectedPackage) return;
  window.open(`/api/evidence/packages/${encodeURIComponent(selectedPackage)}/report/download?format=${format}`, '_blank');
}

// ---------- 冲突 ----------

async function loadConflicts() {
  const { conflicts } = await api('/api/evidence/conflicts');
  $('conflicts').innerHTML = conflicts.length
    ? `<table><tr><th>冲突</th><th>类型</th><th>位置</th><th>保留</th><th>隔离</th></tr>${conflicts.map((c) => `
        <tr>
          <td class="mono small">${esc(c.conflictId)}</td>
          <td><span class="badge b-warn">${esc(c.kind)}</span></td>
          <td>fence ${c.fence}${c.segSeq != null ? ` · 分段 ${c.segSeq}` : ''}${c.seq != null ? ` · 序号 ${c.seq}` : ''}</td>
          <td class="mono small">${esc(short(c.kept.segmentHash || c.kept.contentHash, 10))}<br><span class="muted">${esc(c.kept.gatewayId)}</span></td>
          <td class="mono small">${esc(short(c.rejected.segmentHash || c.rejected.contentHash, 10))}<br><span class="muted">${esc(c.rejected.gatewayId)}</span></td>
        </tr>`).join('')}</table>`
    : '<p class="hint">（无冲突）</p>';
}

async function refreshAll() {
  await loadState();
  await loadKeys();
  await loadPackages();
  await loadConflicts();
  if (selectedPackage && $('detailCard').style.display !== 'none') {
    try { await openPackage(selectedPackage); } catch { /* 归档可能已复位 */ }
  }
}

refreshAll().catch((e) => {
  $('modeBadge').textContent = `连接失败：${e.message}`;
  $('modeBadge').className = 'badge b-err';
});
