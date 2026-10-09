<script lang="ts">
  import { modalFocus } from '$lib/modal-focus';
  import type { CertificateNotice } from '$lib/types';
  let { tofuPrompt, tofuBusy, busy, tofuError, closeTofuPrompt, trustCertificateAndReconnect, formatFingerprint }: {
    tofuPrompt: CertificateNotice; tofuBusy: boolean; busy: boolean; tofuError: string;
    closeTofuPrompt: () => void; trustCertificateAndReconnect: () => void; formatFingerprint: (digest: string) => string;
  } = $props();
</script>
  <div class="modal-backdrop tofu-backdrop" role="presentation">
    <div
      class="tofu-modal"
      use:modalFocus={{ onClose: closeTofuPrompt, locked: tofuBusy || busy }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="tofu-title"
      aria-describedby="tofu-description"
    >
      <div class="tofu-icon" aria-hidden="true">!</div>
      <div class="tofu-heading">
        <small>首次使用信任（TOFU）</small>
        <h2 id="tofu-title">确认服务器证书</h2>
      </div>

      <p id="tofu-description" class="tofu-description">
        <b>{tofuPrompt.profileName}</b> 返回了系统尚未信任的证书。请确认这是你准备连接的服务器，并通过管理员提供的渠道核对指纹。
      </p>

      <dl class="tofu-server">
        <div><dt>服务器</dt><dd>{tofuPrompt.host}:{tofuPrompt.port}</dd></div>
        <div><dt>SHA-256 指纹</dt><dd>{formatFingerprint(tofuPrompt.digest)}</dd></div>
      </dl>

      <div class="tofu-warning">
        信任后，应用会保存此指纹并立即重连；以后证书发生变化时会再次阻止连接。若无法独立核对指纹，取消最安全，因为当前网络可能被冒充或拦截。
      </div>
      {#if tofuPrompt.reason}
        <p class="tofu-reason">引擎信息：{tofuPrompt.reason}</p>
      {/if}
      {#if tofuError}
        <div class="tofu-error" role="alert">{tofuError}</div>
      {/if}

      <div class="modal-actions">
        <button
          type="button"
          class="secondary-button"
          disabled={tofuBusy || busy}
          onclick={closeTofuPrompt}
        >取消</button>
        <button
          type="button"
          class="primary-button"
          disabled={tofuBusy || busy}
          onclick={trustCertificateAndReconnect}
        >{tofuBusy ? "正在保存并重连…" : "信任并重连"}</button>
      </div>
    </div>
  </div>
