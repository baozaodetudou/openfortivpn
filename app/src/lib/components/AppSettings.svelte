<script lang="ts">
  import BackupPanel from '$lib/components/BackupPanel.svelte';
  import { modalFocus } from '$lib/modal-focus';
  import type { DesktopPreferences, PrivilegeStatus, RemoteAccessStatus } from '$lib/types';
  type ThemePreference = 'system' | 'dark' | 'light';
  type AccentPreference = 'mint' | 'blue' | 'violet' | 'amber';
  let { closeAppSettings, refresh, themeOptions, accentOptions, themePreference, accentPreference, uiScale, MIN_UI_SCALE, MAX_UI_SCALE, UI_SCALE_STEP, updateTheme, updateAccent, updateUiScale, stepUiScale, autostartLoading, autostartBusy, launchAtLogin, toggleAutostart, autostartError, desktopPreferences, desktopPreferencesLoading, desktopPreferencesBusy, toggleDesktopPreference, desktopPreferencesError, privilegeStatus, remoteAccess, openRemoteSettings, appearanceError, resetAppearance, quitApplication, activeCount, busy }: {
    closeAppSettings: () => void; refresh: () => Promise<void>;
    themeOptions: { value: ThemePreference; label: string; description: string }[];
    accentOptions: { value: AccentPreference; label: string }[];
    themePreference: ThemePreference; accentPreference: AccentPreference; uiScale: number;
    MIN_UI_SCALE: number; MAX_UI_SCALE: number; UI_SCALE_STEP: number;
    updateTheme: (value: ThemePreference) => void; updateAccent: (value: AccentPreference) => void;
    updateUiScale: (value: number) => void; stepUiScale: (direction: -1 | 1) => void;
    autostartLoading: boolean; autostartBusy: boolean; launchAtLogin: boolean;
    toggleAutostart: (event: Event) => void; autostartError: string;
    desktopPreferences: DesktopPreferences; desktopPreferencesLoading: boolean; desktopPreferencesBusy: boolean;
    toggleDesktopPreference: (key: keyof DesktopPreferences, event: Event) => void; desktopPreferencesError: string;
    privilegeStatus: PrivilegeStatus | null;
    remoteAccess: RemoteAccessStatus | null; openRemoteSettings: () => void;
    appearanceError: string; resetAppearance: () => void; quitApplication: () => void; activeCount: number; busy: boolean;
  } = $props();
</script>
  <div
    class="modal-backdrop settings-backdrop"
    role="presentation"
    onclick={(event) => {
      if (event.target === event.currentTarget) closeAppSettings();
    }}
  >
    <div
      class="settings-modal"
      use:modalFocus={{ onClose: closeAppSettings, locked: false }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="settings-title"
    >
      <div class="modal-heading settings-modal-heading">
        <div>
          <small>APP PREFERENCES</small>
          <h2 id="settings-title">外观与设置</h2>
          <p>调整界面阅读体验和应用启动行为，修改会立即生效。</p>
        </div>
        <button type="button" aria-label="关闭设置" onclick={closeAppSettings}>×</button>
      </div>
      <BackupPanel onRestored={refresh} />

      <div class="settings-content">
        <section class="settings-section appearance-section" aria-labelledby="appearance-title">
          <div class="settings-section-heading">
            <div>
              <span class="settings-section-icon" aria-hidden="true">◐</span>
              <div><h3 id="appearance-title">界面主题</h3><p>选择适合当前环境的明暗外观</p></div>
            </div>
          </div>
          <div class="theme-options">
            {#each themeOptions as option}
              <button
                type="button"
                class:active={themePreference === option.value}
                class="theme-option"
                aria-pressed={themePreference === option.value}
                onclick={() => updateTheme(option.value)}
              >
                <span class="theme-preview {option.value}" aria-hidden="true">
                  <i></i><i></i><i></i>
                </span>
                <span><b>{option.label}</b><small>{option.description}</small></span>
                <i class="selection-check" aria-hidden="true">✓</i>
              </button>
            {/each}
          </div>

          <div class="accent-setting">
            <div><b>强调色</b><small>用于按钮、状态和选中项</small></div>
            <div class="accent-options" aria-label="强调色">
              {#each accentOptions as option}
                <button
                  type="button"
                  class:active={accentPreference === option.value}
                  class="accent-option {option.value}"
                  aria-label={option.label}
                  aria-pressed={accentPreference === option.value}
                  title={option.label}
                  onclick={() => updateAccent(option.value)}
                ><span></span></button>
              {/each}
            </div>
          </div>
        </section>

        <section class="settings-section scale-section" aria-labelledby="scale-title">
          <div class="settings-section-heading">
            <div>
              <span class="settings-section-icon" aria-hidden="true">Aa</span>
              <div><h3 id="scale-title">界面缩放</h3><p>同时调整文字、卡片与操作区域</p></div>
            </div>
            <strong>{uiScale}%</strong>
          </div>
          <div class="scale-control">
            <button
              type="button"
              disabled={uiScale <= MIN_UI_SCALE}
              aria-label="缩小界面"
              onclick={() => stepUiScale(-1)}
            >−</button>
            <input
              type="range"
              min={MIN_UI_SCALE}
              max={MAX_UI_SCALE}
              step={UI_SCALE_STEP}
              value={uiScale}
              aria-label="界面缩放比例"
              oninput={(event) => updateUiScale(Number(event.currentTarget.value))}
            />
            <button
              type="button"
              disabled={uiScale >= MAX_UI_SCALE}
              aria-label="放大界面"
              onclick={() => stepUiScale(1)}
            >＋</button>
          </div>
          <div class="scale-presets" aria-label="常用缩放比例">
            {#each [90, 100, 110, 125] as scale}
              <button
                type="button"
                class:active={uiScale === scale}
                onclick={() => updateUiScale(scale)}
              >{scale}%</button>
            {/each}
          </div>
          <p class="shortcut-hint">快捷键：⌘/Ctrl + 加号、减号调整，⌘/Ctrl + 0 恢复 100%</p>
        </section>

        <section class="settings-section general-section" aria-labelledby="general-title">
          <div class="settings-section-heading">
            <div>
              <span class="settings-section-icon" aria-hidden="true">⌁</span>
              <div><h3 id="general-title">应用行为</h3><p>启动和后台连接相关选项</p></div>
            </div>
          </div>
          <label class:disabled={autostartLoading || autostartBusy} class="toggle setting-row">
            <div class="setting-row-copy">
              <b>登录时启动应用</b>
              <small>{autostartLoading ? "正在读取系统状态…" : "登录电脑后启动，并保持 VPN 后台能力"}</small>
            </div>
            <input
              type="checkbox"
              checked={launchAtLogin}
              disabled={autostartLoading || autostartBusy}
              onchange={toggleAutostart}
            />
            <span></span>
          </label>
          {#if autostartError}
            <p class="settings-error" role="alert">{autostartError}</p>
          {/if}
          <label class:disabled={desktopPreferencesLoading || desktopPreferencesBusy} class="toggle setting-row">
            <div class="setting-row-copy">
              <b>关闭窗口后驻留菜单栏</b>
              <small>点击关闭只隐藏窗口，VPN 和自动重连继续运行</small>
            </div>
            <input
              type="checkbox"
              checked={desktopPreferences.closeToTray}
              disabled={desktopPreferencesLoading || desktopPreferencesBusy}
              onchange={(event) => toggleDesktopPreference("closeToTray", event)}
            />
            <span></span>
          </label>
          <label class:disabled={desktopPreferencesLoading || desktopPreferencesBusy} class="toggle setting-row">
            <div class="setting-row-copy">
              <b>登录启动时在后台运行</b>
              <small>开机登录后不弹出主窗口，可从系统菜单栏打开</small>
            </div>
            <input
              type="checkbox"
              checked={desktopPreferences.startMinimized}
              disabled={desktopPreferencesLoading || desktopPreferencesBusy}
              onchange={(event) => toggleDesktopPreference("startMinimized", event)}
            />
            <span></span>
          </label>
          {#if desktopPreferencesError}
            <p class="settings-error" role="alert">{desktopPreferencesError}</p>
          {/if}
          <div class="system-setting-row">
            <span class="system-status-dot ready"></span>
            <span>
              <b>系统菜单栏 / 托盘</b>
              <small>常驻显示连接状态，并提供连接、重连、断开和退出操作</small>
            </span>
          </div>
          <div class="system-setting-row">
            <span class:ready={!privilegeStatus?.required || privilegeStatus?.ready} class="system-status-dot"></span>
            <span>
              <b>系统 VPN Helper</b>
              <small>{privilegeStatus?.required && !privilegeStatus.ready ? "需要在连接时安装或更新" : "已就绪，日常连接无需管理员密码"}</small>
            </span>
          </div>
          <button type="button" class="system-setting-row remote-setting-row" onclick={openRemoteSettings}>
            <span class:ready={remoteAccess?.running} class="system-status-dot"></span>
            <span>
              <b>HTTPS 远程控制</b>
              <small>{remoteAccess?.running ? "服务正在运行" : remoteAccess?.enabled ? "服务启动失败" : "未启用"}</small>
            </span>
            <i aria-hidden="true">管理 ›</i>
          </button>
        </section>
      </div>

      {#if appearanceError}<div class="settings-error-banner" role="alert">{appearanceError}</div>{/if}
      <div class="settings-footer">
        <button type="button" class="reset-settings" onclick={resetAppearance}>恢复默认外观</button>
        <div class="settings-footer-actions">
          <button type="button" class="danger-ghost quit-application" onclick={quitApplication}>
            {activeCount ? "断开 VPN 并退出" : "退出应用"}
          </button>
          <button type="button" class="primary-button" onclick={closeAppSettings}>完成</button>
        </div>
      </div>
    </div>
  </div>
