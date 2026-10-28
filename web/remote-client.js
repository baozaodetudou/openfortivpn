// Generated from remote-client.ts by node web/build.mjs.
"use strict";
function field(form, name) {
    const item = form.elements.namedItem(name);
    if (!(item instanceof HTMLInputElement))
        throw new Error('Missing form field');
    return item;
}
function errorMessage(error) { return error instanceof Error ? error.message : '请求失败，请重试'; }
const $ = (s) => {
    const element = document.querySelector(s);
    if (!element)
        throw new Error(`Missing element: ${s}`);
    return element;
}, state = { token: sessionStorage.getItem('ofv-token') || '', snapshot: null, selected: '', busy: false, poll: undefined, editing: null, generation: 0, request: null, online: false, capabilities: null, challenges: [], authChallenge: null };
let toastTimer;
const active = (s) => ['starting', 'connecting', 'connected', 'disconnecting'].includes(s), esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => Object.assign(Object.create(null), { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
function toast(message, bad = false) { const el = $('#toast'); el.textContent = message; el.className = 'toast' + (bad ? ' bad' : ''); clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.add('hidden'), 4200); }
async function api(path, options = {}) {
    const generation = state.generation, token = state.token;
    const headers = new Headers(options.headers);
    headers.set('Accept', 'application/json');
    headers.set('Authorization', `Bearer ${token}`);
    if (options.body)
        headers.set('Content-Type', 'application/json');
    const response = await fetch(path, { ...options, headers });
    if (generation !== state.generation)
        throw new DOMException('Session changed', 'AbortError');
    if (response.status === 401) {
        logout();
        throw new Error('令牌无效或已更新，请重新登录');
    }
    if (!response.ok) {
        let message = `请求失败 (${response.status})`;
        try {
            const body = await response.json();
            message = typeof body.error === 'string' ? body.error : body.error?.message || body.message || message;
        }
        catch { }
        throw new Error(message);
    }
    if (response.status === 204 || response.status === 202)
        return undefined;
    const body = await response.json();
    if (generation !== state.generation)
        throw new DOMException('Session changed', 'AbortError');
    return body;
}
function logout() { state.generation++; sessionStorage.removeItem('ofv-token'); state.token = ''; clearTimeout(state.poll); state.request?.abort(); state.request = null; state.snapshot = null; state.selected = ''; state.online = false; state.capabilities = null; state.challenges = []; renderAuthentication(); hideEditor(); $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); $('#token').value = ''; $('#token').focus(); }
function connectionState(online) { state.online = online; $('#connection-state').textContent = online ? '已同步' : '连接离线，正在重试'; }
function schedulePoll() {
    clearTimeout(state.poll);
    if (!state.token)
        return;
    state.poll = setTimeout(async () => {
        try {
            await refresh();
        }
        catch { }
        finally {
            schedulePoll();
        }
    }, 2000);
}
async function login() {
    const generation = state.generation;
    await refresh();
    if (!state.token || generation !== state.generation)
        throw new DOMException('Session changed', 'AbortError');
    state.capabilities = await api('/api/v1/capabilities');
    if (!state.token || generation !== state.generation)
        throw new DOMException('Session changed', 'AbortError');
    $('#use-sudo-option').hidden = !state.capabilities.privilegeSetup;
    sessionStorage.setItem('ofv-token', state.token);
    $('#login').classList.add('hidden');
    $('#app').classList.remove('hidden');
    schedulePoll();
}
function instanceFor(id) { return state.snapshot?.instances.find(i => i.profileId === id) || null; }
function profileFor(id) { return state.snapshot?.profiles.find(p => p.profile.id === id) || null; }
function statusLabel(s) { return ({ starting: '启动中', connecting: '连接中', connected: '已连接', disconnecting: '断开中', disconnected: '已断开', failed: '连接失败' })[s] || '未连接'; }
function render() {
    renderAuthentication();
    const s = state.snapshot;
    if (!s)
        return;
    $('#profile-count').textContent = String(s.profiles.length);
    $('#metric-profiles').textContent = String(s.profiles.length);
    $('#metric-connected').textContent = String(s.instances.filter(i => i.status === 'connected').length);
    $('#metric-engine').textContent = s.engine.available ? '可用' : '不可用';
    $('#version').textContent = `${s.engine.platform} · HTTPS`;
    $('#profiles').innerHTML = s.profiles.length ? s.profiles.map(v => { const p = v.profile, i = instanceFor(p.id), st = i?.status || 'disconnected'; return `<button class="profile ${state.selected === p.id ? 'selected' : ''}" data-select="${esc(p.id)}"><span class="avatar">${esc((p.name || 'V').slice(0, 1).toUpperCase())}</span><span><b>${esc(p.name)}</b><small>${esc(p.host)}:${p.port}</small></span><i class="dot ${st}"></i></button>`; }).join('') : '<div class="empty">还没有 VPN 配置</div>';
    const v = profileFor(state.selected);
    if (!v) {
        $('#content').innerHTML = '<article class="panel empty" style="grid-column:1/-1">选择或新建一个 VPN 配置</article>';
        return;
    }
    const p = v.profile, i = instanceFor(p.id), st = i?.status || 'disconnected', logs = (s.logs || []).filter(l => !i || l.instanceId === i.id).slice(-300), canConnect = !i || !active(i.status), canStop = i && active(i.status) && i.status !== 'disconnecting';
    $('#content').innerHTML = `<article class="panel"><div class="panel-head"><div><small>当前配置</small><h2>${esc(p.name)}</h2></div><span class="badge ${st}">${statusLabel(st)}</span></div><div class="endpoint"><small>服务器地址</small><b>${esc(p.host)}:${p.port}</b></div><dl class="facts"><div><dt>用户名</dt><dd>${esc(p.username)}</dd></div><div><dt>Realm</dt><dd>${esc(p.realm || '默认')}</dd></div><div><dt>凭据</dt><dd>${v.passwordStored ? '本机凭据存储' : '仅当前会话 / 未保存'}</dd></div><div><dt>自动重连</dt><dd>${p.autoReconnect ? '已启用' : '已关闭'}</dd></div></dl><div class="actions"><button class="secondary" data-edit="${esc(p.id)}" ${i && active(i.status) ? 'disabled' : ''}>编辑</button><button class="danger" data-delete="${esc(p.id)}">${i && active(i.status) ? '断开并删除' : '删除'}</button></div></article>
      <article class="panel"><div class="panel-head"><div><small>连接实例</small><h2>${i ? '运行状态' : '尚未启动'}</h2></div><span class="badge ${st}">${statusLabel(st)}</span></div>${i ? `<dl class="facts" style="margin-top:17px"><div><dt>实例 ID</dt><dd>${esc(i.id)}</dd></div><div><dt>进程 PID</dt><dd>${i.pid || '—'}</dd></div><div><dt>虚拟网卡</dt><dd>${esc(i.adapterName || '—')}</dd></div><div><dt>启动时间</dt><dd>${new Date(i.startedAt * 1000).toLocaleString()}</dd></div><div style="grid-column:1/-1"><dt>最新消息</dt><dd title="${esc(i.message)}">${esc(i.message || '等待状态更新')}</dd></div></dl>` : '<div class="empty">每个配置只会运行一个连接实例</div>'}<div class="actions">${canConnect ? `<button class="primary" data-connect="${esc(p.id)}">连接</button>` : ''}${canStop ? `<button class="danger" data-disconnect="${esc(p.id)}">断开</button><button class="secondary" data-reconnect="${esc(p.id)}">重新连接</button>` : ''}</div></article>
      <article class="panel logs"><div class="panel-head log-head"><div><small>实时日志</small><h2>${esc(p.name)}</h2></div><span class="badge">${logs.length} 条</span></div><div class="terminal">${logs.length ? logs.map(l => `<div class="log-line"><time>${new Date(l.timestamp * 1000).toLocaleTimeString()}</time><span class="stream ${esc(l.stream)}">${esc(l.stream)}</span><span class="${esc(l.stream)}">${esc(l.line)}</span></div>`).join('') : '<div class="empty">暂无日志</div>'}</div></article>`;
    requestAnimationFrame(() => {
        const term = document.querySelector('.terminal');
        if (term)
            term.scrollTop = term.scrollHeight;
    });
}
async function refresh() {
    state.request?.abort();
    const request = new AbortController(), generation = state.generation;
    state.request = request;
    try {
        const snapshot = await api('/api/v1/snapshot', { signal: request.signal });
        const authentication = state.capabilities?.apiVersions?.includes(2)
            ? await api('/api/v2/authentication/challenges', { signal: request.signal })
            : { challenges: [] };
        if (request.signal.aborted || generation !== state.generation)
            throw new DOMException('Session changed', 'AbortError');
        state.snapshot = snapshot;
        state.challenges = authentication.challenges;
        if (!state.selected || !profileFor(state.selected))
            state.selected = snapshot.profiles[0]?.profile.id || '';
        connectionState(true);
        render();
    }
    catch (e) {
        if (!(e instanceof DOMException && e.name === 'AbortError'))
            connectionState(false);
        throw e;
    }
    finally {
        if (state.request === request)
            state.request = null;
    }
}
function renderAuthentication() {
    const challenge = state.challenges.find(item => item.profileId === state.selected) ?? null;
    const input = $('#authentication-response');
    if (!challenge || state.authChallenge?.requestId !== challenge.requestId || state.authChallenge?.attemptId !== challenge.attemptId)
        input.value = '';
    state.authChallenge = challenge ? { ...challenge } : null;
    $('#authentication').classList[challenge ? 'remove' : 'add']('hidden');
    $('#authentication-prompt').textContent = challenge?.prompt ?? '';
    input.maxLength = challenge?.maxResponseBytes ?? 1024;
}
$('#authentication-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const challenge = state.authChallenge;
    if (!challenge || state.busy)
        return;
    const input = $('#authentication-response');
    const response = input.value;
    input.value = '';
    state.busy = true;
    $('#authentication-submit').disabled = true;
    try {
        await api('/api/v2/authentication/response', { method: 'POST', body: JSON.stringify({ profileId: challenge.profileId, attemptId: challenge.attemptId, requestId: challenge.requestId, response }) });
        toast('验证码已提交');
        await refresh();
    }
    catch (error) {
        toast(errorMessage(error), true);
    }
    finally {
        state.busy = false;
        $('#authentication-submit').disabled = false;
    }
});
$('#authentication-cancel').addEventListener('click', () => {
    if (state.authChallenge)
        action(`/api/v1/profiles/${encodeURIComponent(state.authChallenge.profileId)}/disconnect`, 'POST', '已取消连接');
});
async function action(path, method = 'POST', success = '操作已提交') {
    if (state.busy)
        return;
    state.busy = true;
    try {
        await api(path, { method });
        toast(success);
        await refresh();
    }
    catch (e) {
        toast(errorMessage(e), true);
    }
    finally {
        state.busy = false;
    }
}
let editorReturnFocus = null;
function openEditor(v = null) {
    editorReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    state.editing = v;
    const p = v?.profile || { id: crypto.randomUUID(), name: '', host: '', gatewayDns: '', port: 443, username: '', realm: '', trustedCert: '', setRoutes: true, setDns: true, pppdUsePeerdns: false, halfInternetRoutes: false, useSudo: true, autoConnect: false, autoReconnect: true };
    const f = $('#profile-form');
    for (const key of ['name', 'host', 'gatewayDns', 'port', 'username', 'realm', 'trustedCert'])
        field(f, key).value = String(p[key] ?? '');
    for (const key of ['setRoutes', 'setDns', 'pppdUsePeerdns', 'halfInternetRoutes', 'useSudo', 'autoConnect', 'autoReconnect'])
        field(f, key).checked = !!p[key];
    field(f, "useSudo").disabled = !state.capabilities?.privilegeSetup;
    if (field(f, "useSudo").disabled)
        field(f, "useSudo").checked = false;
    field(f, "password").value = '';
    field(f, "rememberPassword").checked = v ? !!v.passwordStored : true;
    f.dataset.id = p.id;
    $('#editor-title').textContent = v ? '编辑配置' : '新建配置';
    $('#editor').classList.remove('hidden');
    $('#app').inert = true;
    field(f, "name").focus();
}
function hideEditor() {
    $('#editor').classList.add('hidden');
    $('#app').inert = false;
    $('[name=password]').value = '';
    editorReturnFocus?.focus();
    editorReturnFocus = null;
}
function closeEditor() { if (!state.busy)
    hideEditor(); }
document.addEventListener('keydown', event => {
    if ($('#editor').classList.contains('hidden'))
        return;
    if (event.key === 'Escape') {
        event.preventDefault();
        closeEditor();
        return;
    }
    if (event.key !== 'Tab')
        return;
    const fields = Array.from($('#editor').querySelectorAll('input:not(:disabled),button:not(:disabled),select:not(:disabled)'));
    const first = fields[0], last = fields.at(-1);
    if (!first || !last)
        return;
    if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
    }
    else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
    }
});
$('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const error = $('#login-error');
    error.classList.add('hidden');
    const token = $('#token').value.trim();
    logout();
    state.token = token;
    try {
        await login();
    }
    catch (err) {
        error.textContent = errorMessage(err);
        error.classList.remove('hidden');
    }
});
$('#logout').addEventListener('click', logout);
$('#refresh').addEventListener('click', () => refresh().catch(e => toast(errorMessage(e), true)));
$('#new-profile').addEventListener('click', () => openEditor());
$('#top-new').addEventListener('click', () => openEditor());
document.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', closeEditor));
$('#profiles').addEventListener('click', e => {
    const b = e.target.closest('[data-select]');
    if (b) {
        state.selected = b.dataset.select;
        render();
    }
});
$('#content').addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b)
        return;
    if (b.dataset.edit)
        openEditor(profileFor(b.dataset.edit));
    if (b.dataset.connect) {
        const v = profileFor(b.dataset.connect);
        if (v && !v.hasSecret)
            openEditor(v);
        else
            action(`/api/v1/profiles/${encodeURIComponent(b.dataset.connect)}/connect`, 'POST', '连接进程已启动');
    }
    if (b.dataset.disconnect)
        action(`/api/v1/profiles/${encodeURIComponent(b.dataset.disconnect)}/disconnect`, 'POST', '正在断开连接');
    if (b.dataset.reconnect)
        action(`/api/v1/profiles/${encodeURIComponent(b.dataset.reconnect)}/reconnect`, 'POST', '连接已重新启动');
    if (b.dataset.delete && confirm('确定取消自动重连、断开 VPN，并删除这个配置及其已保存密码吗？'))
        action(`/api/v1/profiles/${encodeURIComponent(b.dataset.delete)}`, 'DELETE', '配置已删除');
});
$('#profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (state.busy)
        return;
    const f = e.currentTarget, old = state.editing, p = { id: f.dataset.id, name: field(f, "name").value.trim(), host: field(f, "host").value.trim(), gatewayDns: field(f, "gatewayDns").value.trim(), port: Number(field(f, "port").value), username: field(f, "username").value.trim(), realm: field(f, "realm").value.trim(), trustedCert: field(f, "trustedCert").value.trim(), setRoutes: field(f, "setRoutes").checked, setDns: field(f, "setDns").checked, pppdUsePeerdns: field(f, "pppdUsePeerdns").checked, halfInternetRoutes: field(f, "halfInternetRoutes").checked, useSudo: field(f, "useSudo").checked, autoConnect: field(f, "autoConnect").checked, autoReconnect: field(f, "autoReconnect").checked }, password = field(f, "password").value, rememberPassword = field(f, "rememberPassword").checked;
    if (p.autoConnect && (!rememberPassword || (!password && !old?.passwordStored)))
        return toast('自动连接需要输入并保存 VPN 密码', true);
    state.busy = true;
    $('#save-profile').disabled = true;
    try {
        const saved = await api('/api/v1/profiles', { method: 'POST', body: JSON.stringify({ profile: p, password: password || null, rememberPassword, expectedRevision: old?.profile.revision ?? 0 }) });
        state.selected = saved.profile.id;
        hideEditor();
        toast('配置已保存');
        await refresh();
    }
    catch (err) {
        toast(errorMessage(err), true);
    }
    finally {
        state.busy = false;
        $('#save-profile').disabled = false;
    }
});
if (state.token) {
    login().catch(() => logout());
}
