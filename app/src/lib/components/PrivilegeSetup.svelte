<script lang="ts">
  import { onDestroy } from 'svelte';
  import { modalFocus } from '$lib/modal-focus';
  let { administratorPassword = $bindable(), privilegeBusy, privilegeError, closePrivilegeModal, unlockPrivileges }: {
    administratorPassword: string; privilegeBusy: boolean; privilegeError: string;
    closePrivilegeModal: () => void; unlockPrivileges: (event: SubmitEvent) => void;
  } = $props();
  onDestroy(() => { administratorPassword = ''; });
</script>
  <div class="modal-backdrop privilege-backdrop" role="presentation">
    <div
      class="privilege-modal"
      use:modalFocus={{ onClose: closePrivilegeModal, locked: privilegeBusy }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="privilege-title"
      aria-describedby="privilege-description privilege-storage-note"
    >
      <form onsubmit={unlockPrivileges}>
        <div class="privilege-icon" aria-hidden="true">◆</div>
        <div class="privilege-heading">
          <small>首次安装或必要更新</small>
          <h2 id="privilege-title">安装或更新系统 VPN Helper</h2>
        </div>

        <p id="privilege-description" class="privilege-description">
          OpenFortiVPN 需要管理员权限来创建网络接口、路由和 DNS 设置。首次安装或 helper 确实发生安全更新时需要输入一次<b>电脑管理员密码</b>，这不是 VPN 账号的密码。
        </p>

        <label class="privilege-password">
          <span>电脑管理员密码</span>
          <input
            type="password"
            name="openfortivpn-administrator-password"
            autocomplete="off"
            required
            disabled={privilegeBusy}
            bind:value={administratorPassword}
            placeholder="输入这台电脑的管理员密码"
          />
        </label>

        <div id="privilege-storage-note" class="privilege-note">
          密码只用于本次 helper 安装，提交后会立即从界面内存中清空。helper 只能启动固定 VPN 引擎和停止已验证的 VPN 进程，不能执行 shell 或任意命令；以后启动 App 和连接 VPN 都无需再次输入管理员密码。
        </div>
        {#if privilegeError}
          <div class="privilege-error" role="alert">{privilegeError}</div>
        {/if}

        <div class="modal-actions">
          <button
            type="button"
            class="secondary-button"
            disabled={privilegeBusy}
            onclick={closePrivilegeModal}
          >稍后</button>
          <button
            type="submit"
            class="primary-button"
            disabled={privilegeBusy || !administratorPassword}
          >{privilegeBusy ? "正在安装…" : "安装并继续"}</button>
        </div>
      </form>
    </div>
  </div>
