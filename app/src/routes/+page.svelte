<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { onMount } from "svelte";
  import type {
    EngineInfo,
    InstanceStatus,
    InstanceView,
    LogEvent,
    ProfileView,
    VpnProfile,
  } from "$lib/types";

  const blankProfile = (): VpnProfile => ({
    id: "",
    name: "",
    host: "",
    port: 443,
    username: "",
    realm: "",
    trustedCert: "",
    setRoutes: true,
    setDns: true,
    pppdUsePeerdns: false,
    halfInternetRoutes: false,
    useSudo: true,
  });

  let profiles = $state<ProfileView[]>([]);
  let instances = $state<InstanceView[]>([]);
  let logs = $state<LogEvent[]>([]);
  let engine = $state<EngineInfo | null>(null);
  let selectedProfileId = $state("");
  let selectedInstanceId = $state("");
  let draft = $state<VpnProfile>(blankProfile());
  let password = $state("");
  let editing = $state(false);
  let loading = $state(true);
  let busy = $state(false);
  let errorMessage = $state("");
  let successMessage = $state("");

  let selectedProfile = $derived(
    profiles.find((entry) => entry.profile.id === selectedProfileId) ?? null,
  );
  let profileInstances = $derived(
    instances.filter((instance) => instance.profileId === selectedProfileId),
  );
  let visibleLogs = $derived(
    logs.filter(
      (entry) => !selectedInstanceId || entry.instanceId === selectedInstanceId,
    ),
  );
  let activeCount = $derived(
    instances.filter((instance) => isActive(instance.status)).length,
  );
  let connectedCount = $derived(
    instances.filter((instance) => instance.status === "connected").length,
  );

  const isActive = (status: InstanceStatus) =>
    ["starting", "connecting", "connected", "disconnecting"].includes(status);

  const statusLabel: Record<InstanceStatus, string> = {
    starting: "启动中",
    connecting: "连接中",
    connected: "已连接",
    disconnecting: "断开中",
    disconnected: "已断开",
    failed: "失败",
  };

  function showError(error: unknown) {
    successMessage = "";
    errorMessage = error instanceof Error ? error.message : String(error);
  }

  function showSuccess(message: string) {
    errorMessage = "";
    successMessage = message;
    window.setTimeout(() => {
      if (successMessage === message) successMessage = "";
    }, 2600);
  }

  function upsertProfile(view: ProfileView) {
    const index = profiles.findIndex(
      (entry) => entry.profile.id === view.profile.id,
    );
    if (index === -1) profiles = [...profiles, view];
    else profiles = profiles.map((entry, position) =>
      position === index ? view : entry,
    );
    profiles = [...profiles].sort((left, right) =>
      left.profile.name.localeCompare(right.profile.name, "zh-CN"),
    );
  }

  function upsertInstance(view: InstanceView) {
    const index = instances.findIndex((instance) => instance.id === view.id);
    if (index === -1) instances = [view, ...instances];
    else instances = instances.map((instance, position) =>
      position === index ? view : instance,
    );
    if (!selectedInstanceId && view.profileId === selectedProfileId) {
      selectedInstanceId = view.id;
    }
  }

  async function refresh() {
    loading = true;
    try {
      const [profileList, instanceList, engineState] = await Promise.all([
        invoke<ProfileView[]>("list_profiles"),
        invoke<InstanceView[]>("list_instances"),
        invoke<EngineInfo>("engine_info"),
      ]);
      profiles = profileList;
      instances = instanceList;
      engine = engineState;
      if (!selectedProfileId && profiles.length > 0) {
        selectedProfileId = profiles[0].profile.id;
      }
    } catch (error) {
      showError(error);
    } finally {
      loading = false;
    }
  }

  function selectProfile(profileId: string) {
    selectedProfileId = profileId;
    selectedInstanceId =
      instances.find((instance) => instance.profileId === profileId)?.id ?? "";
  }

  function createProfile() {
    draft = blankProfile();
    password = "";
    editing = true;
  }

  function editProfile(view: ProfileView) {
    draft = { ...view.profile };
    password = "";
    editing = true;
  }

  async function saveProfile(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    try {
      const saved = await invoke<ProfileView>("save_profile", {
        input: {
          profile: { ...draft, port: Number(draft.port) },
          password: password || null,
        },
      });
      upsertProfile(saved);
      selectedProfileId = saved.profile.id;
      editing = false;
      password = "";
      showSuccess("配置已保存");
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function deleteProfile(view: ProfileView) {
    if (!window.confirm(`确定删除“${view.profile.name}”吗？`)) return;
    busy = true;
    try {
      await invoke("delete_profile", { profileId: view.profile.id });
      profiles = profiles.filter(
        (entry) => entry.profile.id !== view.profile.id,
      );
      if (selectedProfileId === view.profile.id) {
        selectedProfileId = profiles[0]?.profile.id ?? "";
      }
      showSuccess("配置已删除");
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function startProfile(view: ProfileView) {
    if (!view.hasSecret) {
      editProfile(view);
      showError("请重新输入密码；密码只保留在当前应用会话中");
      return;
    }
    busy = true;
    try {
      const instance = await invoke<InstanceView>("start_profile", {
        profileId: view.profile.id,
      });
      upsertInstance(instance);
      selectedInstanceId = instance.id;
      showSuccess("连接进程已启动");
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function stopInstance(instance: InstanceView) {
    try {
      await invoke("stop_instance", { instanceId: instance.id });
    } catch (error) {
      showError(error);
    }
  }

  async function copyConfig(view: ProfileView) {
    try {
      const config = await invoke<string>("export_profile_config", {
        profileId: view.profile.id,
      });
      await navigator.clipboard.writeText(config);
      showSuccess("无密码配置已复制");
    } catch (error) {
      showError(error);
    }
  }

  function formatTime(timestamp: number) {
    if (!timestamp) return "—";
    return new Intl.DateTimeFormat("zh-CN", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(new Date(timestamp * 1000));
  }

  function profileActiveCount(profileId: string) {
    return instances.filter(
      (instance) => instance.profileId === profileId && isActive(instance.status),
    ).length;
  }

  onMount(() => {
    const unlisteners: UnlistenFn[] = [];
    void refresh();
    void listen<InstanceView>("vpn-instance-changed", ({ payload }) => {
      upsertInstance(payload);
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<LogEvent>("vpn-log", ({ payload }) => {
      logs = [...logs.slice(-399), payload];
    }).then((unlisten) => unlisteners.push(unlisten));

    return () => unlisteners.forEach((unlisten) => unlisten());
  });
</script>

<svelte:head>
  <title>OpenFortiVPN Manager</title>
</svelte:head>

<div class="app-shell">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark"><span></span></div>
      <div>
        <strong>OpenFortiVPN</strong>
        <small>Connection Manager</small>
      </div>
    </div>

    <div class:available={engine?.available} class="engine-state">
      <span class="engine-dot"></span>
      <div>
        <b>{engine?.available ? "引擎就绪" : "引擎不可用"}</b>
        <small>{engine?.version || engine?.path || "正在检测…"}</small>
      </div>
    </div>

    <div class="section-heading">
      <span>VPN 配置</span>
      <span class="count">{profiles.length}</span>
    </div>

    <nav class="profile-list" aria-label="VPN 配置列表">
      {#if loading}
        <div class="sidebar-empty">正在加载配置…</div>
      {:else if profiles.length === 0}
        <div class="sidebar-empty">还没有配置</div>
      {:else}
        {#each profiles as item (item.profile.id)}
          <button
            class:active={selectedProfileId === item.profile.id}
            class="profile-item"
            onclick={() => selectProfile(item.profile.id)}
          >
            <span class="profile-icon">{item.profile.name.slice(0, 1).toUpperCase()}</span>
            <span class="profile-copy">
              <b>{item.profile.name}</b>
              <small>{item.profile.host}:{item.profile.port}</small>
            </span>
            {#if profileActiveCount(item.profile.id) > 0}
              <span class="active-pulse" title="连接运行中"></span>
            {/if}
          </button>
        {/each}
      {/if}
    </nav>

    <button class="add-profile" onclick={createProfile}>
      <span>＋</span> 新建配置
    </button>

    <div class="sidebar-footer">
      <span>{engine?.platform ?? "desktop"}</span>
      <span>v0.1.0</span>
    </div>
  </aside>

  <main class="content">
    <header class="topbar">
      <div>
        <p>控制台</p>
        <h1>{selectedProfile?.profile.name ?? "VPN 配置管理"}</h1>
      </div>
      <div class="topbar-actions">
        <button class="icon-button" title="刷新" onclick={refresh}>↻</button>
        {#if selectedProfile}
          <button class="secondary-button" onclick={() => editProfile(selectedProfile!)}>
            编辑配置
          </button>
          <button
            class="primary-button"
            disabled={busy || !engine?.available}
            onclick={() => startProfile(selectedProfile!)}
          >
            连接
          </button>
        {/if}
      </div>
    </header>

    {#if errorMessage}
      <div class="notice error">
        <span>!</span><b>{errorMessage}</b>
        <button onclick={() => (errorMessage = "")}>×</button>
      </div>
    {/if}
    {#if successMessage}
      <div class="notice success"><span>✓</span><b>{successMessage}</b></div>
    {/if}

    <section class="metrics">
      <article>
        <span class="metric-icon green">⌁</span>
        <div><small>已连接</small><strong>{connectedCount}</strong></div>
      </article>
      <article>
        <span class="metric-icon blue">◫</span>
        <div><small>运行实例</small><strong>{activeCount}</strong></div>
      </article>
      <article>
        <span class="metric-icon amber">◇</span>
        <div><small>配置数量</small><strong>{profiles.length}</strong></div>
      </article>
    </section>

    {#if selectedProfile}
      <section class="overview-grid">
        <article class="panel connection-card">
          <div class="panel-heading">
            <div><small>当前配置</small><h2>{selectedProfile.profile.name}</h2></div>
            <span class:ready={selectedProfile.hasSecret} class="secret-state">
              {selectedProfile.hasSecret ? "密码已载入" : "需要密码"}
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
              删除
            </button>
          </div>
        </article>

        <article class="panel instance-panel">
          <div class="panel-heading">
            <div><small>进程管理</small><h2>连接实例</h2></div>
            <span class="count-badge">{profileInstances.length}</span>
          </div>
          <div class="instance-list">
            {#if profileInstances.length === 0}
              <div class="empty-state compact">
                <span>⌁</span><p>这个配置还没有启动过</p>
              </div>
            {:else}
              {#each profileInstances as instance (instance.id)}
                <button
                  class:selected={selectedInstanceId === instance.id}
                  class="instance-row"
                  onclick={() => (selectedInstanceId = instance.id)}
                >
                  <span class="status-dot {instance.status}"></span>
                  <span class="instance-copy">
                    <b>{statusLabel[instance.status]}</b>
                    <small>PID {instance.pid} · {instance.adapterName}</small>
                  </span>
                  <time>{formatTime(instance.startedAt)}</time>
                  {#if isActive(instance.status)}
                    <span
                      class="stop-button"
                      role="button"
                      tabindex="0"
                      onclick={(event) => {
                        event.stopPropagation();
                        void stopInstance(instance);
                      }}
                      onkeydown={(event) => {
                        if (event.key === "Enter") void stopInstance(instance);
                      }}
                    >停止</span>
                  {/if}
                </button>
              {/each}
            {/if}
          </div>
        </article>
      </section>

      <section class="panel log-panel">
        <div class="panel-heading log-heading">
          <div><small>诊断</small><h2>实时日志</h2></div>
          <div class="log-actions">
            <span>{selectedInstanceId ? "已筛选当前实例" : "全部实例"}</span>
            <button onclick={() => (logs = [])}>清空</button>
          </div>
        </div>
        <div class="terminal" aria-live="polite">
          {#if visibleLogs.length === 0}
            <div class="terminal-empty">连接后将在这里显示 openfortivpn 输出</div>
          {:else}
            {#each visibleLogs as entry}
              <div class:error-line={entry.stream === "stderr"} class="log-line">
                <time>{formatTime(entry.timestamp)}</time>
                <span>{entry.line}</span>
              </div>
            {/each}
          {/if}
        </div>
      </section>
    {:else}
      <section class="panel welcome-state">
        <div class="welcome-icon"><span></span></div>
        <h2>创建第一个 VPN 配置</h2>
        <p>保存服务器、账号、路由与 DNS 设置，然后从这里启动和管理多个连接实例。</p>
        <button class="primary-button" onclick={createProfile}>新建配置</button>
      </section>
    {/if}
  </main>
</div>

{#if editing}
  <div
    class="modal-backdrop"
    role="presentation"
    onclick={(event) => {
      if (event.target === event.currentTarget && !busy) editing = false;
    }}
  >
    <form class="profile-modal" onsubmit={saveProfile}>
      <div class="modal-heading">
        <div><small>VPN PROFILE</small><h2>{draft.id ? "编辑配置" : "新建配置"}</h2></div>
        <button type="button" disabled={busy} onclick={() => (editing = false)}>×</button>
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
        <label>
          <span>Realm</span>
          <input placeholder="可选" bind:value={draft.realm} />
        </label>
        <label class="span-2">
          <span>密码 <em>仅保留在当前会话</em></span>
          <input
            type="password"
            autocomplete="current-password"
            placeholder={draft.id ? "留空则保持当前会话中的密码" : "输入 VPN 密码"}
            bind:value={password}
          />
        </label>
        <label class="span-2">
          <span>受信任证书 SHA-256 <em>可选</em></span>
          <input
            maxlength="64"
            placeholder="64 位十六进制证书摘要"
            bind:value={draft.trustedCert}
          />
        </label>
      </div>

      <fieldset>
        <legend>连接行为</legend>
        <div class="toggle-grid">
          <label class="toggle"><input type="checkbox" bind:checked={draft.setRoutes} /><span></span><b>设置路由</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.setDns} /><span></span><b>设置 DNS</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.pppdUsePeerdns} /><span></span><b>使用 Peer DNS</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.halfInternetRoutes} /><span></span><b>半默认路由</b></label>
          <label class="toggle"><input type="checkbox" bind:checked={draft.useSudo} /><span></span><b>使用 sudo -n</b></label>
        </div>
      </fieldset>

      <div class="modal-note">
        Windows 会继承应用管理员权限；Linux/macOS 的 sudo 模式要求已有凭据缓存或受限 sudoers 规则。
      </div>
      <div class="modal-actions">
        <button type="button" class="secondary-button" disabled={busy} onclick={() => (editing = false)}>取消</button>
        <button type="submit" class="primary-button" disabled={busy}>{busy ? "保存中…" : "保存配置"}</button>
      </div>
    </form>
  </div>
{/if}

<style>
  .app-shell { display: grid; grid-template-columns: 276px minmax(0, 1fr); min-height: 100vh; }
  .sidebar { position: sticky; top: 0; display: flex; flex-direction: column; height: 100vh; padding: 24px 18px 16px; border-right: 1px solid var(--line); background: rgba(8, 18, 32, .92); backdrop-filter: blur(20px); }
  .brand { display: flex; gap: 12px; align-items: center; padding: 0 8px 24px; }
  .brand strong, .brand small { display: block; } .brand strong { font-size: 15px; letter-spacing: .01em; } .brand small { margin-top: 3px; color: var(--muted); font-size: 11px; }
  .brand-mark { display: grid; place-items: center; width: 38px; height: 38px; border: 1px solid rgba(94,232,177,.35); border-radius: 12px; background: linear-gradient(145deg, rgba(94,232,177,.17), rgba(42,115,119,.09)); box-shadow: inset 0 1px rgba(255,255,255,.08); }
  .brand-mark span { width: 17px; height: 17px; border: 2px solid var(--brand); border-radius: 50% 50% 48% 52%; transform: rotate(-20deg); }
  .engine-state { display: flex; gap: 10px; align-items: center; margin-bottom: 25px; padding: 11px 12px; border: 1px solid var(--line); border-radius: 12px; background: rgba(255,255,255,.025); }
  .engine-state b, .engine-state small { display: block; overflow: hidden; max-width: 190px; text-overflow: ellipsis; white-space: nowrap; } .engine-state b { font-size: 12px; } .engine-state small { margin-top: 3px; color: var(--muted); font-size: 10px; }
  .engine-dot { width: 8px; height: 8px; flex: 0 0 auto; border-radius: 50%; background: var(--danger); box-shadow: 0 0 0 4px rgba(255,124,141,.1); } .engine-state.available .engine-dot { background: var(--brand); box-shadow: 0 0 0 4px rgba(94,232,177,.1); }
  .section-heading { display: flex; align-items: center; justify-content: space-between; padding: 0 8px 9px; color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
  .count { display: grid; place-items: center; min-width: 22px; height: 18px; border-radius: 999px; background: var(--panel-soft); color: #b9c5d8; }
  .profile-list { display: flex; flex: 1; flex-direction: column; gap: 5px; overflow-y: auto; margin: 0 -4px; padding: 0 4px; }
  .profile-item { display: flex; align-items: center; width: 100%; padding: 10px; border: 1px solid transparent; border-radius: 12px; color: var(--text); background: transparent; cursor: pointer; text-align: left; transition: .16s ease; }
  .profile-item:hover { background: rgba(255,255,255,.035); } .profile-item.active { border-color: rgba(94,232,177,.2); background: var(--brand-soft); }
  .profile-icon { display: grid; place-items: center; width: 34px; height: 34px; flex: 0 0 auto; border-radius: 10px; color: var(--brand); background: rgba(94,232,177,.1); font-size: 12px; font-weight: 800; }
  .profile-copy { min-width: 0; margin-left: 10px; } .profile-copy b, .profile-copy small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; } .profile-copy b { font-size: 12px; } .profile-copy small { margin-top: 4px; color: var(--muted); font-size: 10px; }
  .active-pulse { width: 7px; height: 7px; margin-left: auto; border-radius: 50%; background: var(--brand); box-shadow: 0 0 10px rgba(94,232,177,.7); }
  .sidebar-empty { padding: 20px 10px; color: var(--muted); font-size: 11px; text-align: center; }
  .add-profile { display: flex; justify-content: center; gap: 8px; align-items: center; width: 100%; margin-top: 14px; padding: 10px 12px; border: 1px dashed var(--line-strong); border-radius: 11px; color: #bbcadc; background: transparent; cursor: pointer; font-size: 11px; font-weight: 700; } .add-profile:hover { border-color: rgba(94,232,177,.45); color: var(--brand); background: var(--brand-soft); }
  .sidebar-footer { display: flex; justify-content: space-between; padding: 17px 8px 0; color: #52637c; font-size: 9px; text-transform: uppercase; }
  .content { min-width: 0; padding: 30px 34px 36px; }
  .topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; } .topbar p { margin: 0 0 4px; color: var(--brand); font-size: 9px; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; } .topbar h1 { margin: 0; font-size: 23px; letter-spacing: -.025em; }
  .topbar-actions { display: flex; gap: 9px; align-items: center; }
  .primary-button, .secondary-button, .icon-button, .ghost-button, .danger-ghost { border-radius: 10px; cursor: pointer; font-size: 11px; font-weight: 750; transition: .16s ease; }
  .primary-button { padding: 10px 18px; color: #03130d; background: var(--brand); box-shadow: 0 8px 24px rgba(45,204,145,.17); } .primary-button:hover { background: #79f3c3; transform: translateY(-1px); }
  .secondary-button { padding: 9px 15px; border: 1px solid var(--line); color: #c7d2e3; background: var(--panel); } .secondary-button:hover { border-color: var(--line-strong); background: var(--panel-soft); }
  .icon-button { width: 36px; height: 36px; border: 1px solid var(--line); color: var(--muted); background: var(--panel); font-size: 18px; }
  .notice { display: flex; align-items: center; gap: 10px; margin: -8px 0 18px; padding: 10px 13px; border-radius: 10px; font-size: 11px; } .notice span { display: grid; place-items: center; width: 20px; height: 20px; border-radius: 50%; } .notice b { font-weight: 650; } .notice button { margin-left: auto; color: inherit; background: transparent; cursor: pointer; font-size: 18px; }
  .notice.error { border: 1px solid rgba(255,124,141,.24); color: #ffc3cb; background: rgba(255,124,141,.08); } .notice.error span { background: rgba(255,124,141,.14); } .notice.success { border: 1px solid rgba(94,232,177,.2); color: #a8f3d5; background: rgba(94,232,177,.08); } .notice.success span { background: rgba(94,232,177,.14); }
  .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 14px; } .metrics article { display: flex; align-items: center; gap: 13px; padding: 14px 16px; border: 1px solid var(--line); border-radius: 13px; background: rgba(13,24,40,.74); } .metrics small, .metrics strong { display: block; } .metrics small { color: var(--muted); font-size: 10px; } .metrics strong { margin-top: 2px; font-size: 20px; }
  .metric-icon { display: grid; place-items: center; width: 36px; height: 36px; border-radius: 10px; font-size: 16px; } .metric-icon.green { color: var(--brand); background: rgba(94,232,177,.1); } .metric-icon.blue { color: var(--blue); background: rgba(112,167,255,.1); } .metric-icon.amber { color: var(--warning); background: rgba(246,200,108,.1); }
  .overview-grid { display: grid; grid-template-columns: minmax(310px, .9fr) minmax(360px, 1.1fr); gap: 14px; margin-bottom: 14px; }
  .panel { border: 1px solid var(--line); border-radius: 14px; background: rgba(13,24,40,.78); box-shadow: 0 16px 40px rgba(0,0,0,.1); }
  .connection-card, .instance-panel { min-height: 286px; padding: 18px; }
  .panel-heading { display: flex; align-items: flex-start; justify-content: space-between; } .panel-heading small { color: var(--muted); font-size: 9px; font-weight: 700; letter-spacing: .11em; text-transform: uppercase; } .panel-heading h2 { margin: 4px 0 0; font-size: 15px; }
  .secret-state { padding: 5px 8px; border-radius: 999px; color: var(--warning); background: rgba(246,200,108,.09); font-size: 9px; font-weight: 750; } .secret-state.ready { color: var(--brand); background: var(--brand-soft); }
  .endpoint { display: flex; align-items: center; gap: 12px; margin: 18px 0 16px; padding: 13px; border: 1px solid var(--line); border-radius: 11px; background: rgba(255,255,255,.02); } .endpoint-lock { display: grid; place-items: center; width: 32px; height: 32px; border-radius: 9px; color: var(--brand); background: var(--brand-soft); font-size: 11px; } .endpoint small, .endpoint strong { display: block; } .endpoint small { color: var(--muted); font-size: 9px; } .endpoint strong { margin-top: 4px; font-family: "SFMono-Regular", Consolas, monospace; font-size: 11px; }
  .profile-facts { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin: 0; } .profile-facts div { min-width: 0; } .profile-facts dt { margin-bottom: 3px; color: var(--muted); font-size: 9px; } .profile-facts dd { overflow: hidden; margin: 0; color: #c9d4e4; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
  .card-actions { display: flex; gap: 8px; margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--line); } .ghost-button, .danger-ghost { padding: 7px 10px; border: 1px solid var(--line); background: transparent; } .ghost-button { color: #b8c5d8; } .danger-ghost { margin-left: auto; color: var(--danger); } .ghost-button:hover, .danger-ghost:hover { background: rgba(255,255,255,.035); }
  .count-badge { display: grid; place-items: center; min-width: 26px; height: 22px; border-radius: 8px; color: var(--muted); background: var(--panel-soft); font-size: 10px; font-weight: 700; }
  .instance-list { display: flex; flex-direction: column; gap: 6px; max-height: 214px; margin-top: 14px; overflow-y: auto; }
  .instance-row { display: grid; grid-template-columns: 10px minmax(0,1fr) auto auto; gap: 10px; align-items: center; width: 100%; padding: 10px; border: 1px solid transparent; border-radius: 10px; color: var(--text); background: rgba(255,255,255,.02); cursor: pointer; text-align: left; } .instance-row:hover, .instance-row.selected { border-color: var(--line-strong); background: rgba(255,255,255,.04); }
  .status-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); } .status-dot.connected { background: var(--brand); box-shadow: 0 0 8px rgba(94,232,177,.65); } .status-dot.connecting, .status-dot.starting { background: var(--warning); } .status-dot.failed { background: var(--danger); }
  .instance-copy { min-width: 0; } .instance-copy b, .instance-copy small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; } .instance-copy b { font-size: 10px; } .instance-copy small { margin-top: 3px; color: var(--muted); font-family: monospace; font-size: 8px; } .instance-row time { color: var(--muted); font-size: 9px; }
  .stop-button { padding: 5px 7px; border-radius: 7px; color: var(--danger); background: rgba(255,124,141,.08); font-size: 9px; font-weight: 750; }
  .empty-state.compact { display: grid; place-items: center; padding: 44px 12px; color: var(--muted); } .empty-state.compact span { font-size: 24px; } .empty-state.compact p { margin: 8px 0 0; font-size: 10px; }
  .log-panel { overflow: hidden; } .log-heading { padding: 15px 18px 12px; } .log-actions { display: flex; gap: 10px; align-items: center; color: var(--muted); font-size: 9px; } .log-actions button { padding: 5px 8px; border-radius: 7px; color: #aebdd1; background: var(--panel-soft); cursor: pointer; font-size: 9px; }
  .terminal { height: 178px; overflow: auto; padding: 12px 16px 16px; border-top: 1px solid var(--line); background: rgba(2,8,15,.58); font: 10px/1.65 "SFMono-Regular", Consolas, monospace; } .terminal-empty { display: grid; height: 100%; place-items: center; color: #53637a; } .log-line { display: grid; grid-template-columns: 66px minmax(0,1fr); gap: 10px; color: #a9b8cb; } .log-line time { color: #4f6078; } .log-line.error-line span { color: #e4b2b9; }
  .welcome-state { display: grid; min-height: 490px; place-items: center; align-content: center; padding: 40px; text-align: center; } .welcome-state h2 { margin: 20px 0 8px; font-size: 20px; } .welcome-state p { max-width: 440px; margin: 0 0 22px; color: var(--muted); font-size: 12px; line-height: 1.7; }
  .welcome-icon { display: grid; place-items: center; width: 72px; height: 72px; border: 1px solid rgba(94,232,177,.25); border-radius: 24px; background: var(--brand-soft); } .welcome-icon span { width: 28px; height: 28px; border: 3px solid var(--brand); border-radius: 50%; }
  .modal-backdrop { position: fixed; z-index: 30; inset: 0; display: grid; place-items: center; padding: 24px; background: rgba(2,7,13,.74); backdrop-filter: blur(10px); }
  .profile-modal { width: min(650px, 94vw); max-height: 92vh; overflow-y: auto; padding: 22px; border: 1px solid var(--line-strong); border-radius: 17px; background: #0c1727; box-shadow: 0 30px 90px rgba(0,0,0,.5); }
  .modal-heading { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; } .modal-heading small { color: var(--brand); font-size: 9px; font-weight: 800; letter-spacing: .14em; } .modal-heading h2 { margin: 4px 0 0; font-size: 19px; } .modal-heading button { width: 32px; height: 32px; border-radius: 9px; color: var(--muted); background: var(--panel-soft); cursor: pointer; font-size: 18px; }
  .form-grid { display: grid; grid-template-columns: 1fr 150px; gap: 13px; } .form-grid .span-2 { grid-column: span 2; } .form-grid label > span { display: block; margin: 0 0 6px 2px; color: #b8c4d5; font-size: 10px; font-weight: 650; } .form-grid em { margin-left: 6px; color: var(--muted); font-size: 8px; font-style: normal; font-weight: 500; }
  .form-grid input { width: 100%; padding: 10px 11px; border: 1px solid var(--line); border-radius: 9px; color: var(--text); background: rgba(3,10,18,.56); font-size: 11px; transition: border-color .15s; } .form-grid input:focus { border-color: rgba(94,232,177,.45); } .form-grid input::placeholder { color: #4f6077; }
  fieldset { margin: 18px 0 0; padding: 13px; border: 1px solid var(--line); border-radius: 11px; } legend { padding: 0 7px; color: var(--muted); font-size: 9px; font-weight: 700; text-transform: uppercase; }
  .toggle-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; } .toggle { display: flex; align-items: center; gap: 8px; cursor: pointer; } .toggle input { position: absolute; opacity: 0; pointer-events: none; } .toggle span { position: relative; width: 28px; height: 16px; flex: 0 0 auto; border-radius: 999px; background: #28374b; transition: .18s; } .toggle span::after { position: absolute; top: 3px; left: 3px; width: 10px; height: 10px; border-radius: 50%; background: #8695aa; content: ""; transition: .18s; } .toggle input:checked + span { background: rgba(94,232,177,.28); } .toggle input:checked + span::after { left: 15px; background: var(--brand); } .toggle b { color: #acb9ca; font-size: 9px; font-weight: 650; }
  .modal-note { margin-top: 14px; padding: 10px 11px; border-radius: 9px; color: #8292a9; background: rgba(112,167,255,.055); font-size: 9px; line-height: 1.55; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 9px; margin-top: 20px; }
  @media (max-width: 1000px) { .app-shell { grid-template-columns: 238px minmax(0,1fr); } .content { padding: 26px 24px; } .overview-grid { grid-template-columns: 1fr; } .toggle-grid { grid-template-columns: repeat(2, 1fr); } }
</style>
