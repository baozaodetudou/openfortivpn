<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { VpnProfile } from '$lib/types';
  import { modalFocus } from '$lib/modal-focus';
  let { draft = $bindable(), password = $bindable(), rememberPassword = $bindable(), busy, credentialStoreName, platform, onSave, onClose }: {
    draft: VpnProfile; password: string; rememberPassword: boolean; busy: boolean; credentialStoreName: string; platform?: string;
    onSave: (event: SubmitEvent) => void; onClose: () => void;
  } = $props();
  onDestroy(() => { password = ''; });
</script>
    <div class="profile-modal" role="dialog" aria-modal="true" aria-label={draft.id ? "编辑 VPN 配置" : "新建 VPN 配置"} tabindex="-1" use:modalFocus={{ onClose, locked: busy }}>
    <form onsubmit={onSave}>
      <div class="modal-heading">
        <div><small>VPN PROFILE</small><h2>{draft.id ? "编辑配置" : "新建配置"}</h2></div>
        <button type="button" disabled={busy} onclick={onClose}>×</button>
      </div>

      <div class="form-grid">
        <label class="span-2">
          <span>配置名称</span>
          <input required maxlength="64" placeholder="例如：公司办公网" bind:value={draft.name} />
        </label>
        <label>
          <span>VPN 服务器</span>
          <input required placeholder="vpn.example.com" bind:value={draft.host} />
        </label>
        <label>
          <span>端口</span>
          <input required type="number" min="1" max="65535" bind:value={draft.port} />
        </label>
        <label>
          <span>用户名</span>
          <input autocomplete="username" bind:value={draft.username} />
        </label>
        <label class="span-2">
          <span>网关 DNS <em>可选</em></span>
          <input placeholder="留空使用系统 DNS，例如 223.5.5.5" maxlength="15" list="gateway-dns-options" bind:value={draft.gatewayDns} />
          <datalist id="gateway-dns-options">
            <option value="223.5.5.5">阿里 DNS</option>
            <option value="114.114.114.114">114 DNS</option>
          </datalist>
          <small class="field-help">仅用于连接前解析 VPN 服务器，通过 TCP 53 查询。可避开系统 Fake-IP；保留域名证书校验。内网域名通常应使用系统或企业 DNS。</small>
        </label>
        <label>
          <span>Realm</span>
          <input placeholder="可选" bind:value={draft.realm} />
        </label>
        <label class="span-2">
          <span>密码 <em>{rememberPassword ? credentialStoreName : "仅本次会话"}</em></span>
          <input
            type="password"
            autocomplete="current-password"
            maxlength="256"
            placeholder={draft.id
              ? rememberPassword
                ? "留空则保留已有凭据"
                : "留空则不更新当前会话密码"
              : "输入 VPN 密码"}
            bind:value={password}
          />
          <small class="field-help">
            {rememberPassword
              ? platform === "macos"
                ? "密码会写入当前用户专用的本机凭据文件；留空会保留已有凭据。"
                : "密码会写入操作系统安全凭据库；留空会保留已有凭据。"
              : "不会写入磁盘；取消保存会删除已有凭据，已有或本次输入的密码仍可用于当前会话。"}
          </small>
        </label>
        <label class="span-2">
          <span>受信任证书 SHA-256 <em>可选</em></span>
          <input
            maxlength="64"
            placeholder="64 位十六进制证书摘要"
            bind:value={draft.trustedCert}
          />
          <small class="field-help">
            首次连接遇到自签名证书时，应用会显示服务器指纹供你确认；也可以在核对后手动填写。
          </small>
        </label>
      </div>

      <fieldset>
        <legend>连接行为</legend>
        <div class="toggle-grid">
          <label class="toggle"><input type="checkbox" bind:checked={draft.setRoutes} /><span></span><b>设置路由</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.setDns} /><span></span><b>设置 DNS</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.pppdUsePeerdns} /><span></span><b>使用 Peer DNS</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.halfInternetRoutes} /><span></span><b>半默认路由</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.useSudo} /><span></span><b>使用系统 Helper</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={rememberPassword} /><span></span><b>保存密码到{credentialStoreName}</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.autoConnect} /><span></span><b>应用启动后自动连接</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.autoReconnect} /><span></span><b>意外断线自动重连</b></label>
        </div>
      </fieldset>

      <div class="modal-note">
        “应用启动后自动连接”要求 VPN 密码已保存；“意外断线自动重连”只处理非主动断开的连接。macOS/Linux 首次安装受限系统 Helper 后可无人值守连接。当前版本对修改路由或 DNS 的连接执行独占保护；请先完成断开及清理，再连接其他配置。
      </div>
      <div class="modal-actions">
        <button type="button" class="secondary-button" disabled={busy} onclick={onClose}>取消</button>
        <button type="submit" class="primary-button" disabled={busy}>{busy ? "保存中…" : "保存配置"}</button>
      </div>
    </form>
    </div>
<style>
  .profile-modal { width: min(650px, 94vw); max-height: 92vh; overflow-y: auto; padding: 22px; border: 1px solid var(--line-strong); border-radius: 17px; background: var(--modal-bg); box-shadow: 0 30px 90px var(--shadow); }
  .modal-heading { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; } .modal-heading small { color: var(--brand); font-size: 9px; font-weight: 800; letter-spacing: .14em; } .modal-heading h2 { margin: 4px 0 0; font-size: 19px; } .modal-heading button { width: 32px; height: 32px; border-radius: 9px; color: var(--muted); background: var(--panel-soft); cursor: pointer; font-size: 18px; }
  .form-grid { display: grid; grid-template-columns: 1fr 150px; gap: 13px; } .form-grid .span-2 { grid-column: span 2; } .form-grid label > span { display: block; margin: 0 0 6px 2px; color: var(--text-soft); font-size: 10px; font-weight: 650; } .form-grid em { margin-left: 6px; color: var(--muted); font-size: 8px; font-style: normal; font-weight: 500; }
  .form-grid input { width: 100%; padding: 10px 11px; border: 1px solid var(--line); border-radius: 9px; color: var(--text); background: var(--control-bg); font-size: 11px; transition: border-color .15s; } .form-grid input:focus { border-color: rgba(var(--brand-rgb),.45); } .form-grid input::placeholder { color: var(--muted-faint); }
  fieldset { margin: 18px 0 0; padding: 13px; border: 1px solid var(--line); border-radius: 11px; } legend { padding: 0 7px; color: var(--muted); font-size: 9px; font-weight: 700; text-transform: uppercase; }
  .toggle-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; } .toggle { display: flex; align-items: center; gap: 8px; cursor: pointer; } .toggle input { position: absolute; opacity: 0; pointer-events: none; } .toggle > span { position: relative; width: 28px; height: 16px; flex: 0 0 auto; border: 1px solid var(--line); border-radius: 999px; background: var(--panel-soft); transition: .18s; } .toggle > span::after { position: absolute; top: 2px; left: 2px; width: 10px; height: 10px; border-radius: 50%; background: var(--muted); content: ""; transition: .18s; } .toggle input:checked + span { border-color: rgba(var(--brand-rgb),.28); background: rgba(var(--brand-rgb),.28); } .toggle input:checked + span::after { left: 14px; background: var(--brand); } .toggle b { color: var(--text-soft); font-size: 9px; font-weight: 650; }
  .modal-note { margin-top: 14px; padding: 10px 11px; border-radius: 9px; color: var(--muted); background: rgba(112,167,255,.055); font-size: 9px; line-height: 1.55; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 9px; margin-top: 20px; }
  .field-help { display: block; margin: 6px 2px 0; color: var(--muted); font-size: 9px; line-height: 1.5; }
  .primary-button, .secondary-button { padding: 9px 15px; border-radius: 9px; cursor: pointer; font-size: 10px; font-weight: 700; }
  .primary-button { color: var(--brand-ink, #123425); background: var(--brand); }
  .secondary-button { color: var(--text-soft); border: 1px solid var(--line); background: var(--panel-soft); }
  button:disabled { opacity: .5; cursor: default; }
  .toggle input:focus-visible + span { outline: 2px solid var(--brand); outline-offset: 3px; }
  @media (max-width: 640px) { .toggle-grid { grid-template-columns: 1fr 1fr; } .form-grid { grid-template-columns: 1fr; } .form-grid .span-2 { grid-column: auto; } }
</style>
