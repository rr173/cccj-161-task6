/* 证据归档页面：原生 JS。
   安全纪律：upload secret 只存在内存变量 SECRET，仅经请求头发送；
   所有渲染文本都会过 ensureNoSecret（发现原文立即替换并告警）。 */
let SECRET = '';
let SELECTED = null;
let REPORTS = new Map();

const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
}
function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 6000);
}

// 出口扫描：任何即将渲染/记录的文本若含 secret 原文，打码并红色告警。
function ensureNoSecret(text) {
  if (SECRET && text.includes(SECRET)) {
    toast('安全告警：响应中出现 upload secret 原文，已在页面打码！', 'err');
    return text.split(SECRET).join('***LEAK-BLOCKED***');
  }
  return text;
}
function safeText(v) { return ensureNoSecret(String(v ?? '')); }

async function api(path, { method = 'GET', body = null, auth = false, raw = false } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (auth) {
    if (!SECRET) { toast('请先设置 X-Upload-Secret', 'warn'); throw new Error('no secret'); }
    headers['X-Upload-Secret'] = SECRET;
  }
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  const cleanText = ensureNoSecret(text);
  let data;
  try { data = JSON.parse(cleanText); } catch { data = raw ? cleanText : {}; }
  if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { code: data.code, details: data.details, status: res.status });
  return raw ? cleanText : data;
}

function setSecretState() {
  $('secretState').textContent = SECRET ? `已设置（长度 ${SECRET.length}，仅内存）` : '未设置';
  $('secretState').className = SECRET ? 'tag ok' : 'muted';
}
$('btnSaveSecret').onclick = () => {
  SECRET = $('secret').value.trim();
  $('secret').value = '';
  setSecretState();
  toast('upload secret 已保存在页面内存（不会持久化）', 'ok');
};
setSecretState();

// ---------- 网关 ----------
async function loadGateways() {
  const r = await api('/api/gateways');
  $('gwList').innerHTML = r.gateways.length
    ? '已登记：' + r.gateways.map((g) => `<span class="tag info">${esc(g.gatewayId)} <span class="muted">(${esc(g.keyId)})</span></span>`).join(' ')
    : '（尚无登记网关）';
}
$('btnRegGw').onclick = async () => {
  try {
    await api('/api/gateways', { method: 'POST', auth: true, body: {
      gatewayId: $('gwId').value.trim(), keyId: $('gwKeyId').value.trim(), publicKeyPem: $('gwPub').value.trim(),
    } });
    $('gwId').value = $('gwKeyId').value = $('gwPub').value = '';
    toast('网关注册成功', 'ok');
    loadGateways();
  } catch (e) { toast(`${e.code || '错误'}：${safeText(e.message)}`, 'err'); }
};

// ---------- 导入 ----------
$('btnFormat').onclick = () => {
  try { $('envelope').value = JSON.stringify(JSON.parse($('envelope').value), null, 2); }
  catch (e) { toast('JSON 无法解析：' + e.message, 'err'); }
};
$('btnImport').onclick = async () => {
  let env;
  try { env = JSON.parse($('envelope').value); }
  catch (e) { toast('证据信封不是合法 JSON', 'err'); return; }
  $('importState').textContent = '校验中…';
  try {
    const r = await api(`/api/packages/${encodeURIComponent(env.packageId || '')}/import`, { method: 'POST', auth: true, body: env });
    const kind = r.duplicate ? '重复导入（返回原归档结果）' : (r.result === 'CONFLICTS' ? '导入完成：存在冲突隔离' : '导入成功');
    $('importState').innerHTML = `<span class="tag ${r.duplicate || r.result === 'CONFLICTS' ? 'warn' : 'ok'}">${kind}</span>`;
    $('importResult').textContent = ensureNoSecret(JSON.stringify({
      packageId: r.packageId,
      duplicate: r.duplicate,
      importId: r.importId,
      firstImportedAt: r.firstImportedAt || null,
      importedAt: r.importedAt || null,
      result: r.duplicate ? r.result : r.result,
      disposition: r.duplicate ? r.disposition : r.disposition,
      envelopeHash: r.envelopeHash,
    }, null, 2));
    toast(kind, r.duplicate || r.result === 'CONFLICTS' ? 'warn' : 'ok');
    await refreshPackages();
  } catch (e) {
    $('importState').innerHTML = `<span class="tag err">${esc(e.code || 'REJECTED')}</span>`;
    $('importResult').textContent = ensureNoSecret(JSON.stringify({ code: e.code, error: e.message, details: e.details }, null, 2));
    toast(`导入被拒绝：${e.code}`, 'err');
  }
};

// ---------- 包列表 ----------
async function refreshPackages(selectId = SELECTED) {
  const r = await api('/api/packages');
  REPORTS = new Map(r.packages.map((p) => [p.packageId, p]));
  $('pkgList').innerHTML = r.packages.length ? '' : '<div class="muted">（尚无归档）</div>';
  for (const p of r.packages) {
    const div = document.createElement('div');
    div.className = 'pkg-item' + (p.packageId === selectId ? ' active' : '');
    const fence = p.currentFence
      ? `v${p.currentFence.version} ${p.currentFence.closed ? '·已关闭' : '·活动'}` : '无围栏';
    const prog = p.currentProgress
      ? `lastSeq=${p.currentProgress.lastSeq}${p.currentProgress.carried ? '·沿用' : ''}` : '无检查点';
    div.innerHTML = `<div><b>${esc(p.packageId)}</b>
        <span class="tag ${p.conflictCount ? 'err' : 'ok'}">冲突 ${p.conflictCount}</span></div>
      <div class="muted mono">${esc(p.reportDigest.slice(0, 20))}…</div>
      <div class="muted">围栏：${esc(fence)} ｜ 进度：${esc(prog)} ｜ 记录 ${p.acceptedRecordCount}</div>`;
    div.onclick = () => { SELECTED = p.packageId; renderDetail(); refreshPackages(p.packageId); };
    $('pkgList').appendChild(div);
  }
  if (selectId && !REPORTS.has(selectId)) SELECTED = null;
  if (SELECTED) renderDetail();
}
$('btnRefresh').onclick = () => refreshPackages().then(() => toast('已刷新', 'ok')).catch((e) => toast(e.message, 'err'));

// ---------- 详情/报告 ----------
async function renderDetail() {
  if (!SELECTED) return;
  const r = await api(`/api/packages/${encodeURIComponent(SELECTED)}/report`);
  $('detail').innerHTML = reportHTML(r);
}

function reportHTML(r) {
  const dl = (fmt) => `/api/packages/${encodeURIComponent(r.packageId)}/report.${fmt}`;
  const fenceRows = r.fences.map((f) => `<tr>
      <td>v${f.version}${f.isCurrent ? ' <span class="tag info">当前</span>' : ''}</td>
      <td>${esc(f.fenceId || '-')}</td>
      <td>${esc(f.createdAt || '-')}</td>
      <td>${f.closedAt ? `<span class="tag warn">已关闭 ${esc(f.closedAt)}</span>` : '<span class="tag ok">活动</span>'}</td>
      <td>${f.segmentSeqs.length ? f.segmentSeqs.map((s) => `#${s}`).join(' ') : '-'}</td>
      <td>${f.checkpoint ? `lastSeq=${f.checkpoint.lastSeq} E/S/F=${f.checkpoint.counts.EXECUTED}/${f.checkpoint.counts.SKIPPED}/${f.checkpoint.counts.FAILED}` : '-'}</td>
      <td><a href="#" data-fence="${f.version}" class="old-fence-link">查询证据</a></td></tr>`).join('');
  const rows = r.timeline.map((t) => {
    const fence = t.fenceVersion === 0 ? 'manifest' : `v${t.fenceVersion}`;
    const body = t.type === 'SEGMENT_ACCEPTED'
      ? esc(t.entries.map((e) => `seq=${e.seq} ${e.deviceId} ${e.outcome}${e.note ? ' ' + e.note : ''}`).join('；'))
      : t.type === 'CHECKPOINT'
        ? `lastSeq=${t.lastSeq} E/S/F=${t.counts.EXECUTED}/${t.counts.SKIPPED}/${t.counts.FAILED}`
        : esc(t.detail || t.type);
    return `<tr><td>${esc(t.ts)}</td><td>${esc(fence)}</td><td>${t.segSeq ? '#' + t.segSeq : ''}</td>
      <td>${esc(t.type)}</td><td>${body}</td><td>${esc(t.gatewayId || '-')}</td></tr>`;
  }).join('');
  const conflicts = r.conflicts.map((c) => {
    const d = c.detail || {};
    const extra = d.segSeq != null ? `seg#${d.segSeq}` : d.lastSeq != null ? `lastSeq=${d.lastSeq}` : '';
    return `<tr><td>${c.seq}</td><td><span class="tag err">${esc(c.reason)}</span></td>
      <td>${esc(c.slot)}</td><td>${esc(extra)}</td><td>${esc(c.gatewayId)}</td>
      <td><code>${esc(c.fingerprint.slice(0, 16))}…</code></td>
      <td><code>${esc((c.existingFingerprint || '').slice(0, 16))}…</code></td>
      <td>${esc(c.envelopeHash.slice(0, 12))}…</td></tr>`;
  }).join('');
  const cp = r.currentProgress;
  return `
  <div class="row" style="justify-content:space-between">
    <div><b>${esc(r.packageId)}</b></div>
    <div class="row">
      <a href="${dl('txt')}" target="_blank"><button>下载 TXT</button></a>
      <a href="${dl('json')}" target="_blank"><button>下载脱敏 JSON</button></a>
      <button id="btnHtml">预览 HTML 片段</button>
    </div>
  </div>
  <h3>报告摘要（重启/重复导入后不变）</h3>
  <div class="mono" style="word-break:break-all">${esc(r.reportDigest)}</div>
  <div class="muted">链尖：ledger#${r.chainTips.ledger.seq} · quarantine#${r.chainTips.quarantine.seq} · audit#${r.chainTips.audit.seq}</div>
  <h3>当前状态</h3>
  <div>清单：<code>${esc((r.manifest?.manifestHash || '-').slice(0, 24))}…</code>（${r.manifest?.entries.length ?? 0} 条）</div>
  <div>当前围栏：${r.currentFence
    ? `v${r.currentFence.version} · ${esc(r.currentFence.fenceId)} · ${r.currentFence.closed ? '<span class="tag warn">已关闭</span>' : '<span class="tag ok">活动中</span>'}`
    : '（无）'}</div>
  <div>当前检查点：${cp
    ? `<b>v${cp.fenceVersion}</b> lastSeq=${cp.lastSeq} E/S/F=${cp.counts.EXECUTED}/${cp.counts.SKIPPED}/${cp.counts.FAILED}
       ${cp.carried ? '<span class="tag warn">沿用上一围栏水位（不倒退）</span>' : ''}
       ${cp.active ? '' : '<span class="tag warn">围栏已关闭，仅历史可查</span>'}`
    : '（无）'}</div>
  <h3>围栏（多围栏合并；旧围栏可查询但不充当当前进度）</h3>
  <table class="grid"><thead><tr><th>版本</th><th>fenceId</th><th>创建</th><th>状态</th><th>已收分段</th><th>检查点</th><th></th></tr></thead><tbody>${fenceRows}</tbody></table>
  <h3>确定性时间线（围栏 → 分段序号）</h3>
  <table class="grid"><thead><tr><th>时间</th><th>围栏</th><th>分段</th><th>类型</th><th>内容</th><th>网关</th></tr></thead><tbody>${rows}</tbody></table>
  <h3>冲突隔离（${r.conflicts.length}，原证据保留、未覆盖）</h3>
  <table class="grid"><thead><tr><th>#</th><th>原因</th><th>槽位</th><th>定位</th><th>网关</th><th>外来指纹</th><th>已存指纹</th><th>信封</th></tr></thead>
  <tbody>${conflicts || '<tr><td colspan=8 class=muted>（无冲突）</td></tr>'}</tbody></table>
  <h3>导入裁决历史</h3>
  <table class="grid"><thead><tr><th>时间</th><th>网关</th><th>结果</th><th>接受</th><th>重复</th><th>冲突</th><th>信封</th></tr></thead><tbody>
  ${r.imports.map((i) => `<tr><td>${esc(i.at)}</td><td>${esc(i.gatewayId)}</td>
    <td><span class="tag ${i.result === 'CONFLICTS' ? 'warn' : 'ok'}">${i.result}</span></td>
    <td>${i.recordsAccepted}</td><td>${i.recordsDuplicate}</td><td>${i.recordsConflicted}</td>
    <td><code>${esc(i.envelopeHash.slice(0, 12))}…</code></td></tr>`).join('')}
  </tbody></table>`;
}

document.addEventListener('click', async (ev) => {
  const a = ev.target.closest('.old-fence-link');
  if (a) {
    ev.preventDefault();
    const v = a.dataset.fence;
    try {
      const r = await api(`/api/packages/${encodeURIComponent(SELECTED)}/fences/${v}`);
      const segs = (r.segments || []).map((s) =>
        `[${s.ts}] seg#${s.segSeq} ${s.entries.map((e) => `${e.seq}:${e.deviceId}/${e.outcome}`).join(' ')}`).join('\n');
      alert(ensureNoSecret(`围栏 v${v}（${r.note}）\n状态：${r.fence.closedAt ? '已关闭' : '活动'}\n分段：\n${segs || '（无）'}`));
    } catch (e) { toast(e.message, 'err'); }
  }
  if (ev.target.id === 'btnHtml') {
    fetch(`/api/packages/${encodeURIComponent(SELECTED)}/report.html`).then((x) => x.text()).then((t) => {
      const w = window.open('', '_blank');
      w.document.write(`<meta charset=utf8><title>${SELECTED}</title><style>body{font:13px sans-serif;padding:16px}
        table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:3px 6px;font-size:12px}code{font-size:11px}</style>` + ensureNoSecret(t));
    });
  }
});

// ---------- 链核验 / 重启 ----------
$('btnVerify').onclick = async () => {
  const r = await api('/api/chain/verify');
  const lines = [];
  for (const [id, v] of Object.entries(r.packages)) {
    for (const [name, c] of Object.entries(v.chains)) {
      lines.push(`${id}/${name}: ${c.ok ? 'OK' : 'BROKEN'} seq=${c.length} tip=${c.tipHash.slice(0, 12)}…${c.ok ? '' : ' reason=' + c.reason}`);
    }
  }
  $('verifyOut').textContent = lines.join('\n') || '（无包）';
};
$('btnRestart').onclick = async () => {
  try {
    await api('/api/admin/restart', { method: 'POST', auth: true });
    toast('已从磁盘重放重建（等价重启）', 'ok');
    await refreshPackages();
    if (SELECTED) {
      const before = REPORTS.get(SELECTED)?.reportDigest;
      await refreshPackages();
      const after = REPORTS.get(SELECTED)?.reportDigest;
      if (before && before !== after) toast('摘要在重放后发生变化！', 'err');
      else toast('重放后报告摘要一致', 'ok');
    }
  } catch (e) { toast(e.message, 'err'); }
};

loadGateways().catch(() => {});
refreshPackages().catch(() => {});
setInterval(() => refreshPackages().catch(() => {}), 15000);
