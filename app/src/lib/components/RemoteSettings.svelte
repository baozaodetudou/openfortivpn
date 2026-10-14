<script lang="ts">
  import { modalFocus } from '$lib/modal-focus';
  import type { RemoteAccessStatus } from '$lib/types';
  let { remoteEnabled = $bindable(), remoteBindAddress = $bindable(), remotePort = $bindable(), remoteToken,
    remoteBusy, remoteError, remoteAccess, closeRemoteSettings, saveRemoteSettings, openRemoteAccessUrl,
    rotateRemoteToken, copyRemoteValue }: {
    remoteEnabled: boolean; remoteBindAddress: string; remotePort: number; remoteToken: string;
    remoteBusy: boolean; remoteError: string; remoteAccess: RemoteAccessStatus | null;
    closeRemoteSettings: () => void; saveRemoteSettings: (event: SubmitEvent) => void;
    openRemoteAccessUrl: () => void; rotateRemoteToken: () => void; copyRemoteValue: (value: string, label: string) => void;
  } = $props();
</script>
  <div class="modal-backdrop remote-backdrop" role="presentation">
    <div class="remote-modal" role="dialog" aria-modal="true" aria-label="HTTPS 远程控制" tabindex="-1" use:modalFocus={{ onClose: closeRemoteSettings, locked: remoteBusy }}>
    <form onsubmit={saveRemoteSettings}>
      <div class="modal-heading">
        <div><small>SECURE REMOTE ACCESS</small><h2>HTTPS 远程控制</h2></div>
        <button type="button" disabled={remoteBusy} onclick={closeRemoteSettings}>×</button>
      </div>

      <p class="remote-description">
        在浏览器中管理配置、连接、断开、重连和日志。服务始终使用 HTTPS 与 256 位访问令牌，默认只监听本机。
      </p>
      <label class="toggle remote-enable">
        <input type="checkbox" bind:checked={remoteEnabled} disabled={remoteBusy} />
        <span></span><b>启用远程控制服务</b>
      </label>
      <div class="remote-fields">
        <label><span>监听地址</span><input required disabled={remoteBusy || !remoteEnabled} bind:value={remoteBindAddress} placeholder="127.0.0.1" /></label>
        <label><span>HTTPS 端口</span><input required type="number" min="1" max="65535" disabled={remoteBusy || !remoteEnabled} bind:value={remotePort} /></label>
      </div>
      {#if remoteEnabled && remoteBindAddress !== "127.0.0.1" && remoteBindAddress !== "::1"}
        <div class="remote-warning">当前地址可能允许局域网或公网访问。请同时配置主机防火墙，并优先通过 Tailscale、WireGuard 或受控反向代理暴露服务。</div>
      {/if}
      {#if remoteAccess?.enabled}
        <dl class="remote-status">
          <div><dt>服务状态</dt><dd class:ready={remoteAccess.running}>{remoteAccess.running ? "正在运行" : "未运行"}</dd></div>
          <div><dt>访问地址</dt><dd>{remoteAccess.url}</dd></div>
          <div><dt>证书 SHA-256</dt><dd>{remoteAccess.certificateFingerprint || "启用后生成"}</dd></div>
        </dl>
        <div class="remote-actions-row">
          <button type="button" class="secondary-button" disabled={!remoteAccess.running || remoteBusy} onclick={openRemoteAccessUrl}>在浏览器打开</button>
          <button type="button" class="secondary-button" disabled={remoteBusy} onclick={rotateRemoteToken}>更新访问令牌</button>
        </div>
      {/if}
      {#if remoteToken}
        <section class="token-reveal">
          <strong>请立即保存新的访问令牌</strong>
          <p>关闭窗口后不会再次显示；可随时生成新令牌。</p>
          <code>{remoteToken}</code>
          <button type="button" class="secondary-button" onclick={() => copyRemoteValue(remoteToken, "访问令牌")}>复制令牌</button>
        </section>
      {/if}
      {#if remoteError}<div class="remote-error" role="alert">{remoteError}</div>{/if}
      <div class="modal-actions">
        <button type="button" class="secondary-button" disabled={remoteBusy} onclick={closeRemoteSettings}>{remoteToken ? "完成" : "取消"}</button>
        <button type="submit" class="primary-button" disabled={remoteBusy}>{remoteBusy ? "正在应用…" : "保存并应用"}</button>
      </div>
    </form>
    </div>
  </div>
