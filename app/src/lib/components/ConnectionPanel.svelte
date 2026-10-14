<script lang="ts">
  import AuthenticationPanel from '$lib/components/AuthenticationPanel.svelte';
  import type { ProfileView, InstanceView, InstanceStatus, AuthenticationChallenge } from '$lib/types';
  let { selectedProfile, selectedInstance, selectedChallenge, selectedConnectionActive, credentialStoreName,
    busy, copyConfig, deleteProfile, statusLabel, formatTime, submitAuthentication, stopInstance }: {
    selectedProfile: ProfileView; selectedInstance: InstanceView | undefined; selectedChallenge: AuthenticationChallenge | null;
    selectedConnectionActive: boolean; credentialStoreName: string; busy: boolean;
    copyConfig: (profile: ProfileView) => void; deleteProfile: (profile: ProfileView) => void;
    statusLabel: Record<InstanceStatus, string>; formatTime: (timestamp: number) => string;
    submitAuthentication: (challenge: AuthenticationChallenge, response: string) => Promise<void>;
    stopInstance: (instance: InstanceView) => Promise<void>;
  } = $props();
</script>
      <section class="overview-grid">
        <article class="panel connection-card">
          <div class="panel-heading">
            <div><small>当前配置</small><h2>{selectedProfile.profile.name}</h2></div>
            <span class:ready={selectedProfile.hasSecret} class="secret-state">
              {selectedProfile.passwordStored
                ? `密码已存${credentialStoreName}`
                : selectedProfile.hasSecret
                  ? "密码仅本次会话"
                  : "需要密码"}
            </span>
          </div>
          <div class="endpoint">
            <span class="endpoint-lock">◆</span>
            <div>
              <small>VPN Gateway</small>
              <strong>{selectedProfile.profile.host}:{selectedProfile.profile.port}</strong>
            </div>
          </div>
          <dl class="profile-facts">
            <div><dt>用户名</dt><dd>{selectedProfile.profile.username || "—"}</dd></div>
            <div><dt>Realm</dt><dd>{selectedProfile.profile.realm || "默认"}</dd></div>
            <div><dt>路由</dt><dd>{selectedProfile.profile.setRoutes ? "启用" : "禁用"}</dd></div>
            <div><dt>DNS</dt><dd>{selectedProfile.profile.setDns ? "启用" : "禁用"}</dd></div>
            <div><dt>应用启动后自动连接</dt><dd>{selectedProfile.profile.autoConnect ? "启用" : "关闭"}</dd></div>
            <div><dt>意外断线自动重连</dt><dd>{selectedProfile.profile.autoReconnect ? "启用" : "关闭"}</dd></div>
            <div><dt>{credentialStoreName}</dt><dd>{selectedProfile.passwordStored ? "已保存密码" : "未保存"}</dd></div>
          </dl>
          <div class="card-actions">
            <button class="ghost-button" onclick={() => copyConfig(selectedProfile!)}>
              复制配置
            </button>
            <button
              class="danger-ghost"
              disabled={busy}
              onclick={() => deleteProfile(selectedProfile!)}
            >
              {selectedConnectionActive ? "断开并删除" : "删除"}
            </button>
          </div>
        </article>

        <article class="panel instance-panel">
          <div class="panel-heading">
            <div><small>连接状态</small><h2>当前连接</h2></div>
            {#if selectedInstance}
              <span class="connection-status {selectedInstance.status}">
                <span class="status-dot {selectedInstance.status}"></span>
                {statusLabel[selectedInstance.status]}
              </span>
            {/if}
          </div>
          {#if selectedInstance}
            <dl class="instance-facts">
              <div><dt>PID</dt><dd>{selectedInstance.pid || "—"}</dd></div>
              <div><dt>Adapter</dt><dd>{selectedInstance.adapterName || "—"}</dd></div>
              <div><dt>开始时间</dt><dd>{formatTime(selectedInstance.startedAt)}</dd></div>
              <div><dt>结束时间</dt><dd>{selectedInstance.endedAt ? formatTime(selectedInstance.endedAt) : "—"}</dd></div>
              <div class="instance-message">
                <dt>Message</dt><dd>{selectedInstance.message || "—"}</dd>
              </div>
            </dl>
          {:else}
            <div class="empty-state compact">
              <span>⌁</span><p>这个配置还没有连接记录</p>
            </div>
          {/if}
          {#if selectedChallenge && selectedInstance}
            {#key `${selectedChallenge.attemptId}:${selectedChallenge.requestId}`}
              <AuthenticationPanel challenge={selectedChallenge} onSubmit={submitAuthentication} onCancel={() => stopInstance(selectedInstance!)} />
            {/key}
          {/if}
        </article>
      </section>
