<script lang="ts">
  import "$lib/styles/manager.css";
  import CertificatePrompt from "$lib/components/CertificatePrompt.svelte";
  import PrivilegeSetup from "$lib/components/PrivilegeSetup.svelte";
  import RemoteSettings from "$lib/components/RemoteSettings.svelte";
  import ConnectionPanel from "$lib/components/ConnectionPanel.svelte";
  import ProfileEditor from "$lib/components/ProfileEditor.svelte";
  import AppSettings from "$lib/components/AppSettings.svelte";
  import { invoke, isTauri, loadManagerSnapshot, managerEvents } from "$lib/services/desktop";
  import { compareInstances, mergeInstance, mergeProfile, mergeLogEvents, errorText, SnapshotAuthority } from "$lib/services/manager-state";
  import { CertificatePrompts, LatestRequest, ProfileController, connectionActive as isActive } from "$lib/services/profile-controller";
  import {
    disable as disableAutostart,
    enable as enableAutostart,
    isEnabled as isAutostartEnabled,
  } from "@tauri-apps/plugin-autostart";
  import { AppearanceController, desktopAppearanceQueue, APPEARANCE_STORAGE_KEY, MIN_UI_SCALE, MAX_UI_SCALE, UI_SCALE_STEP, type ThemePreference, type AccentPreference } from "$lib/services/appearance";
  import { AutostartController, DesktopPreferencesController } from "$lib/services/desktop-settings";
  import { RemoteSettingsController } from "$lib/services/remote-settings";
  import LogViewer from "$lib/components/LogViewer.svelte";
  import RecoveryPanel from "$lib/components/RecoveryPanel.svelte";
  import type { RecoveryNotice } from "$lib/types";
  import { onMount } from "svelte";
  import type {
    AppExitBlocked,
    AuthenticationChallenge,
    AutoConnectError,
    DesktopPreferences,
    EngineInfo,
    InstanceStatus,
    InstanceView,
    LogEvent,
    PrivilegeStatus,
    ProfileView,
    RemoteAccessError,
    RemoteAccessStatus,
    TrayActionError,
    VpnEngineEvent,
    VpnProfile,
  } from "$lib/types";

  type TofuPrompt = import("$lib/types").CertificateNotice;

  const themeOptions: Array<{
    value: ThemePreference;
    label: string;
    description: string;
  }> = [
    { value: "system", label: "跟随系统", description: "自动适配电脑外观" },
    { value: "dark", label: "深色", description: "弱光环境更舒适" },
    { value: "light", label: "浅色", description: "明亮清晰的界面" },
  ];
  const accentOptions: Array<{
    value: AccentPreference;
    label: string;
  }> = [
    { value: "mint", label: "薄荷绿" },
    { value: "blue", label: "海湾蓝" },
    { value: "violet", label: "星云紫" },
    { value: "amber", label: "琥珀橙" },
  ];

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
    autoConnect: false,
    autoReconnect: true,
  });

  let profiles = $state<ProfileView[]>([]);
  let instances = $state<InstanceView[]>([]);
  let logs = $state<LogEvent[]>([]);
  let engine = $state<EngineInfo | null>(null);
  let selectedProfileId = $state("");
  let draft = $state<VpnProfile>(blankProfile());
  let password = $state("");
  let rememberPassword = $state(true);
  let editing = $state(false);
  let loading = $state(true);
  let busy = $state(false);
  let errorMessage = $state("");
  let recoveryRecords = $state<RecoveryNotice[]>([]);
  let authChallenges = $state<AuthenticationChallenge[]>([]);
  let successMessage = $state("");
  let tofuPrompt = $state<TofuPrompt | null>(null);
  let tofuBusy = $state(false);
  let tofuError = $state("");
  let launchAtLogin = $state(false);
  let autostartLoading = $state(true);
  let autostartBusy = $state(false);
  let autostartError = $state("");
  let privilegeStatus = $state<PrivilegeStatus | null>(null);
  let privilegeModalOpen = $state(false);
  let administratorPassword = $state("");
  let privilegeBusy = $state(false);
  let privilegeError = $state("");
  let pendingPrivilegeProfileId = $state("");
  let remoteAccess = $state<RemoteAccessStatus | null>(null);
  let remoteSettingsOpen = $state(false);
  let remoteEnabled = $state(false);
  let remoteBindAddress = $state("127.0.0.1");
  let remotePort = $state(18443);
  let remoteToken = $state("");
  let remoteBusy = $state(false);
  let remoteError = $state("");
  let settingsOpen = $state(false);
  let themePreference = $state<ThemePreference>("system");
  let accentPreference = $state<AccentPreference>("mint");
  let uiScale = $state(100);
  let appearanceError = $state("");
  let desktopPreferences = $state<DesktopPreferences>({
    closeToTray: true,
    startMinimized: true,
  });
  let desktopPreferencesLoading = $state(true);
  let desktopPreferencesBusy = $state(false);
  let desktopPreferencesError = $state("");
  const snapshots = new SnapshotAuthority();
  const authRequests = new LatestRequest(() => snapshots.alive());
  const recoveryRequests = new LatestRequest(() => snapshots.alive());
  const certificates = new CertificatePrompts(() => snapshots.alive());
  const profileCommands = new ProfileController(invoke, () => snapshots.alive());
  let appearance: AppearanceController | null = null;
  const autostartSettings = new AutostartController({
    isEnabled: isAutostartEnabled, enable: enableAutostart, disable: disableAutostart,
  }, state => {
    launchAtLogin = state.value;
    autostartLoading = state.loading;
    autostartBusy = state.busy;
    autostartError = state.error;
  });
  const desktopSettings = new DesktopPreferencesController(invoke, state => {
    desktopPreferences = state.value;
    desktopPreferencesLoading = state.loading;
    desktopPreferencesBusy = state.busy;
    desktopPreferencesError = state.error;
  });
  const remoteSettings = new RemoteSettingsController({
    invoke, copy: value => navigator.clipboard.writeText(value),
    loadOpener: async () => {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      return openUrl;
    },
  }, state => {
    remoteAccess = state.status;
    remoteSettingsOpen = state.open;
    remoteBusy = state.busy;
    remoteError = state.error;
    remoteToken = state.token;
  });


  function latestInstanceForProfile(profileId: string) {
    return (
      instances
        .filter((instance) => instance.profileId === profileId)
        .sort(compareInstances)[0] ?? null
    );
  }

  function latestInstancesForProfiles() {
    return profiles.flatMap((entry) => {
      const instance = latestInstanceForProfile(entry.profile.id);
      return instance ? [instance] : [];
    });
  }

  let selectedProfile = $derived(
    profiles.find((entry) => entry.profile.id === selectedProfileId) ?? null,
  );
  let selectedInstance = $derived(
    latestInstanceForProfile(selectedProfileId),
  );
  let selectedChallenge = $derived(authChallenges.find((challenge) => challenge.profileId === selectedProfileId && challenge.attemptId === selectedInstance?.id && selectedInstance.status !== "disconnecting") ?? null);
  async function refreshAuthentication() {
    if (!snapshots.alive()) return;
    const sequence = authRequests.begin();
    try { const current = await invoke<AuthenticationChallenge[]>("authentication_challenges"); if (authRequests.current(sequence)) authChallenges = current; }
    catch { if (authRequests.current(sequence)) authChallenges = []; }
  }
  async function submitAuthentication(challenge: AuthenticationChallenge, response: string) {
    if (!snapshots.alive()) return;
    await invoke("respond_to_authentication", { response: { profileId: challenge.profileId, attemptId: challenge.attemptId, requestId: challenge.requestId, response } });
    await refreshAuthentication();
  }
  let latestInstances = $derived(latestInstancesForProfiles());
  let visibleLogs = $derived(
    selectedInstance
      ? logs.filter((entry) => entry.instanceId === selectedInstance.id)
      : [],
  );
  let activeCount = $derived(
    latestInstances.filter((instance) => isActive(instance.status)).length,
  );
  let connectedCount = $derived(
    latestInstances.filter((instance) => instance.status === "connected").length,
  );
  let selectedConnectionActive = $derived(
    selectedInstance ? isActive(selectedInstance.status) : false,
  );
  let selectedAuthenticationFailed = $derived(
    selectedInstance?.message.includes("VPN 身份验证失败") ?? false,
  );
  let activeRouteOwners = $derived(
    profiles.filter(
      (entry) =>
        entry.profile.setRoutes &&
        profileHasActiveConnection(entry.profile.id),
    ).length,
  );
  let activeDnsOwners = $derived(
    profiles.filter(
      (entry) =>
        entry.profile.setDns && profileHasActiveConnection(entry.profile.id),
    ).length,
  );
  let parallelNetworkWarning = $derived(
    activeCount > 1 && (activeRouteOwners > 1 || activeDnsOwners > 1),
  );
  let credentialStoreName = $derived(
    engine?.platform === "macos" ? "本机凭据文件" : "系统凭据库",
  );

  const statusLabel: Record<InstanceStatus, string> = {
    starting: "启动中",
    connecting: "连接中",
    connected: "已连接",
    disconnecting: "断开中",
    disconnected: "已断开",
    failed: "失败",
  };

  function showError(error: unknown) {
    if (!snapshots.alive()) return;
    successMessage = "";
    errorMessage = errorText(error);
  }

  function showSuccess(message: string) {
    if (!snapshots.alive()) return;
    errorMessage = "";
    successMessage = message;
    window.setTimeout(() => {
      if (snapshots.alive() && successMessage === message) successMessage = "";
    }, 2600);
  }

  function updateTheme(value: ThemePreference) { appearance?.update({ theme: value }); }
  function updateAccent(value: AccentPreference) { appearance?.update({ accent: value }); }
  function updateUiScale(value: number) { appearance?.update({ scale: value }); }
  function stepUiScale(direction: -1 | 1) { appearance?.step(direction); }
  function resetAppearance() { appearance?.reset(); }

  function openAppSettings() {
    if (!snapshots.alive()) return;
    appearance?.clearError();
    settingsOpen = true;
  }

  function closeAppSettings() {
    if (!snapshots.alive()) return;
    settingsOpen = false;
    appearance?.clearError();
  }

  function handleAppearanceShortcut(event: KeyboardEvent) {
    if (!event.metaKey && !event.ctrlKey) return;
    if (event.key === "0") {
      event.preventDefault();
      updateUiScale(100);
    } else if (event.key === "+" || event.key === "=") {
      event.preventDefault();
      stepUiScale(1);
    } else if (event.key === "-") {
      event.preventDefault();
      stepUiScale(-1);
    }
  }

  function upsertProfile(view: ProfileView) { if (!snapshots.alive()) return; snapshots.changed("profiles"); profiles = mergeProfile(profiles, view); }
  function upsertInstance(view: InstanceView) { if (snapshots.alive()) instances = mergeInstance(instances, view); }
  function mergeLogs(entries: LogEvent[]) { if (snapshots.alive()) logs = mergeLogEvents(logs, entries); }

  function isVpnCredentialError(message: string) {
    return [
      "VPN 密码已不存在",
      "VPN 密码无法使用",
      "当前没有可用的 VPN 密码",
      "无法从系统凭据库读取密码",
      "本机凭据文件中的 VPN 密码无法使用",
      "本机凭据存储中的 VPN 密码",
    ].some((fragment) => message.includes(fragment));
  }

  function formatFingerprint(digest: string) {
    return digest
      .toUpperCase()
      .match(/.{1,2}/g)
      ?.join(":") ?? digest.toUpperCase();
  }

  function closeTofuPrompt() {
    tofuPrompt = certificates.close();
    tofuError = "";
  }

  async function handleEngineEvent(event: VpnEngineEvent) {
    if (!snapshots.alive() || event.payload.event !== "cert_error") return;
    if (!latestInstanceForProfile(event.profileId)) {
      try { (await invoke<InstanceView[]>("list_instances")).forEach(upsertInstance); }
      catch (error) { showError(error); return; }
    }
    if (!snapshots.alive()) return;
    tofuPrompt = certificates.receive(event, latestInstanceForProfile(event.profileId) ?? undefined,
      profiles.find(entry => entry.profile.id === event.profileId));
  }

  async function trustCertificateAndReconnect() {
    const prompt = tofuPrompt;
    if (!snapshots.alive() || !prompt || tofuBusy || busy) return;

    tofuBusy = true;
    busy = true;
    tofuError = "";
    try {
      const saved = await profileCommands.trust(prompt,
        () => profiles.find(entry => entry.profile.id === prompt.profileId),
        snapshot => snapshot.forEach(upsertInstance));
      upsertProfile(saved);

      const instance = await invoke<InstanceView>("start_profile", {
        profileId: prompt.profileId,
      });
      if (!snapshots.alive()) return;
      upsertInstance(instance);
      selectedProfileId = prompt.profileId;
      closeTofuPrompt();
      showSuccess("已信任服务器证书并重新连接");
    } catch (error) {
      if (snapshots.alive()) tofuError = errorText(error);
    } finally {
      if (snapshots.alive()) { tofuBusy = false; busy = false; }
    }
  }

  async function refresh() {
    const ticket = snapshots.begin();
    const remoteTicket = remoteSettings.snapshotTicket();
    if (!snapshots.current(ticket)) return;
    loading = true;
    try {
      const snapshot = await loadManagerSnapshot();
      if (!snapshots.current(ticket)) return;
      if (snapshots.accepts(ticket, "profiles")) profiles = snapshot.profiles;
      snapshot.instances.forEach(upsertInstance);
      mergeLogs(snapshot.logs);
      engine = snapshot.engine;
      if (snapshots.accepts(ticket, "privilege")) privilegeStatus = snapshot.privilege;
      if (snapshots.accepts(ticket, "remote")) remoteSettings.receiveSnapshot(remoteTicket, snapshot.remote);
      if (snapshots.accepts(ticket, "recovery")) recoveryRecords = snapshot.recovery;
      await refreshAuthentication();
      if (!snapshots.current(ticket)) return;
      if (!selectedProfileId && profiles.length > 0) {
        selectedProfileId = profiles[0].profile.id;
      }
    } catch (error) {
      if (snapshots.current(ticket)) showError(error);
    } finally {
      if (snapshots.current(ticket)) loading = false;
    }
  }

  function selectProfile(profileId: string) {
    if (!snapshots.alive()) return;
    selectedProfileId = profileId;
  }

  function createProfile() {
    if (!snapshots.alive()) return;
    draft = blankProfile();
    password = "";
    rememberPassword = true;
    editing = true;
  }

  function editProfile(view: ProfileView) {
    if (!snapshots.alive()) return;
    const instance = latestInstanceForProfile(view.profile.id);
    if (instance && isActive(instance.status)) {
      showError("请先断开这个配置的连接，再编辑配置");
      return;
    }
    draft = {
      ...view.profile,
      autoConnect: view.profile.autoConnect ?? false,
      autoReconnect: view.profile.autoReconnect ?? true,
    };
    password = "";
    rememberPassword = Boolean(view.passwordStored);
    editing = true;
  }

  async function saveProfile(event: SubmitEvent) {
    event.preventDefault();
    if (!snapshots.alive()) return;
    const existing = profiles.find((entry) => entry.profile.id === draft.id);
    const willHaveStoredPassword =
      rememberPassword && (password.length > 0 || Boolean(existing?.passwordStored));
    if (draft.autoConnect && !willHaveStoredPassword) {
      showError(
        "要启用“应用启动后自动连接”，请输入密码并勾选“保存密码到本机凭据存储”，或保留这个配置已有的凭据。",
      );
      return;
    }

    busy = true;
    try {
      const saved = await profileCommands.save(draft, password || null, rememberPassword);
      upsertProfile(saved);
      selectedProfileId = saved.profile.id;
      editing = false;
      password = "";
      rememberPassword = false;
      showSuccess("配置已保存");
    } catch (error) {
      showError(error);
    } finally {
      if (snapshots.alive()) busy = false;
    }
  }

  async function deleteProfile(view: ProfileView) {
    if (!snapshots.alive()) return;
    const instance = latestInstanceForProfile(view.profile.id);
    const active = Boolean(instance && isActive(instance.status));
    if (
      !window.confirm(
        active
          ? `“${view.profile.name}”仍在连接。确定取消自动重连、断开 VPN，并删除配置和已保存密码吗？`
          : `确定删除“${view.profile.name}”及其已保存密码吗？`,
      )
    ) return;
    busy = true;
    try {
      await profileCommands.delete(view);
      snapshots.changed("profiles");
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
      if (snapshots.alive()) busy = false;
    }
  }

  async function startProfile(view: ProfileView) {
    if (!snapshots.alive()) return;
    const currentInstance = latestInstanceForProfile(view.profile.id);
    if (currentInstance && isActive(currentInstance.status)) return;

    if (!view.hasSecret && !view.passwordStored) {
      editProfile(view);
      showError("该配置没有可用的 VPN 密码，请在配置编辑器中输入并保存后再连接");
      return;
    }

    if (view.profile.useSudo) {
      let currentPrivilegeStatus: PrivilegeStatus;
      try {
        currentPrivilegeStatus = await invoke<PrivilegeStatus>(
          "privilege_status",
        );
        if (!snapshots.alive()) return;
        snapshots.changed("privilege");
        privilegeStatus = currentPrivilegeStatus;
      } catch (error) {
        showError(`无法确认管理员权限状态：${errorText(error)}`);
        return;
      }

      if (currentPrivilegeStatus.required && !currentPrivilegeStatus.ready) {
        privilegeError = "";
        pendingPrivilegeProfileId = view.profile.id;
        privilegeModalOpen = true;
        return;
      }
    }

    busy = true;
    try {
      const instance = await invoke<InstanceView>("start_profile", {
        profileId: view.profile.id,
      });
      upsertInstance(instance);
      showSuccess(
        instance.status === "connected"
          ? "该配置已经连接"
          : instance.status === "starting" || instance.status === "connecting"
            ? "连接正在进行"
            : "连接进程已启动",
      );
    } catch (error) {
      if (!snapshots.alive()) return;
      const message = errorText(error);
      showError(message);
      if (isVpnCredentialError(message)) {
        try {
          const profileList = await invoke<ProfileView[]>("list_profiles");
          if (!snapshots.alive()) return;
          snapshots.changed("profiles");
          profiles = profileList;
          const current = profileList.find(
            (entry) => entry.profile.id === view.profile.id,
          );
          if (current) {
            editProfile(current);
            showError("已打开配置编辑器，请重新输入并保存 VPN 密码");
          }
        } catch {
          // Keep the original connection error visible.
        }
      }
    } finally {
      if (snapshots.alive()) busy = false;
    }
  }

  async function stopInstance(instance: InstanceView) {
    if (!snapshots.alive()) return;
    if (instance.status === "disconnecting") return;
    busy = true;
    try {
      await invoke("stop_instance", {
        instanceId: instance.id,
        profileId: instance.profileId,
      });
      showSuccess("正在断开连接");
    } catch (error) {
      showError(error);
    } finally {
      if (snapshots.alive()) busy = false;
    }
  }

  async function reconnectProfile(view: ProfileView, instance: InstanceView) {
    if (!snapshots.alive()) return;
    if (busy || !isActive(instance.status) || instance.status === "disconnecting") {
      return;
    }

    busy = true;
    try {
      const nextInstance = await invoke<InstanceView>("reconnect_profile", {
        profileId: view.profile.id,
      });
      upsertInstance(nextInstance);
      showSuccess("连接已重新启动");
    } catch (error) {
      showError(error);
    } finally {
      if (snapshots.alive()) busy = false;
    }
  }

  async function copyConfig(view: ProfileView) {
    if (!snapshots.alive()) return;
    try {
      const config = await invoke<string>("export_profile_config", {
        profileId: view.profile.id,
      });
      if (!snapshots.alive()) return;
      await navigator.clipboard.writeText(config);
      showSuccess("无密码配置已复制");
    } catch (error) {
      showError(error);
    }
  }

  async function exportDiagnostics() {
    if (!snapshots.alive()) return;
    try {
      const report = await invoke<Record<string, unknown>>("diagnostic_report");
      if (!snapshots.alive()) return;
      const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `openfortivpn-diagnostics-${Date.now()}.json`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      showSuccess("诊断已导出，仅包含运行统计，不含配置身份或原始日志");
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

  function profileHasActiveConnection(profileId: string) {
    const instance = latestInstanceForProfile(profileId);
    return instance ? isActive(instance.status) : false;
  }

  function toggleAutostart(event: Event) {
    void autostartSettings.update((event.currentTarget as HTMLInputElement).checked);
  }
  function toggleDesktopPreference(key: keyof DesktopPreferences, event: Event) {
    void desktopSettings.set(key, (event.currentTarget as HTMLInputElement).checked);
  }

  async function handleTrayActionError(error: TrayActionError) {
    if (!snapshots.alive()) return;
    if (error.profileId) selectedProfileId = error.profileId;
    showError(error.message);
    if (error.profileId && isVpnCredentialError(error.message)) {
      try {
        const profileList = await invoke<ProfileView[]>("list_profiles");
        if (!snapshots.alive()) return;
        snapshots.changed("profiles");
        profiles = profileList;
        const profile = profileList.find(
          (entry) => entry.profile.id === error.profileId,
        );
        if (profile) {
          editProfile(profile);
          showError("已打开配置编辑器，请重新输入并保存 VPN 密码");
        }
      } catch {
        // Keep the original tray action error visible.
      }
    }
    if (error.message.includes("系统 helper")) {
      try {
        const currentPrivilegeStatus = await invoke<PrivilegeStatus>("privilege_status");
        if (!snapshots.alive()) return;
        privilegeStatus = currentPrivilegeStatus;
        snapshots.changed("privilege");
        if (privilegeStatus.required && !privilegeStatus.ready) {
          pendingPrivilegeProfileId = error.profileId ?? "";
          privilegeModalOpen = true;
        }
      } catch {
        // Keep the original tray action error visible.
      }
    }
  }

  function quitApplication() {
    if (snapshots.alive()) void invoke("quit_app").catch(showError);
  }

  function openRemoteSettings() {
    if (!snapshots.alive()) return;
    settingsOpen = false;
    const input = remoteSettings.open();
    if (input) {
      remoteEnabled = input.enabled;
      remoteBindAddress = input.bindAddress;
      remotePort = input.port;
    }
  }
  function closeRemoteSettings() { remoteSettings.close(); }
  async function saveRemoteSettings(event: SubmitEvent) {
    event.preventDefault();
    const input = { enabled: remoteEnabled, bindAddress: remoteBindAddress, port: remotePort };
    if (await remoteSettings.configure(input)) showSuccess(input.enabled ? "HTTPS 远程访问已启动" : "远程访问已关闭");
  }
  async function rotateRemoteToken() {
    if (remoteBusy || !window.confirm("更新令牌后，所有已登录的远程浏览器都需要重新登录。继续吗？")) return;
    await remoteSettings.rotateToken();
  }
  async function copyRemoteValue(value: string, label: string) {
    if (await remoteSettings.copyToken(value)) showSuccess(`${label}已复制`);
  }
  function openRemoteAccessUrl() { void remoteSettings.openUrl(); }

  function closePrivilegeModal() {
    if (privilegeBusy) return;
    administratorPassword = "";
    privilegeError = "";
    pendingPrivilegeProfileId = "";
    privilegeModalOpen = false;
  }

  async function unlockPrivileges(event: SubmitEvent) {
    event.preventDefault();
    if (!snapshots.alive() || privilegeBusy || !administratorPassword) return;

    privilegeBusy = true;
    privilegeError = "";
    const pendingProfileId = pendingPrivilegeProfileId;
    try {
      const status = await invoke<PrivilegeStatus>("unlock_privileges", {
        password: administratorPassword,
      });
      if (!snapshots.alive()) return;
      snapshots.changed("privilege");
      privilegeStatus = status;
      if (status.required && !status.ready) {
        throw new Error("系统未确认 helper 安装状态，请检查密码后重试");
      }
      privilegeModalOpen = false;
      pendingPrivilegeProfileId = "";
      showSuccess("系统 VPN helper 已安装，今后连接不再要求管理员密码");
      const pendingProfile = profiles.find(
        (entry) => entry.profile.id === pendingProfileId,
      );
      if (pendingProfile) await startProfile(pendingProfile);
    } catch (error) {
      if (snapshots.alive()) privilegeError = `安装失败：${errorText(error)}`;
    } finally {
      if (snapshots.alive()) { administratorPassword = ""; privilegeBusy = false; }
    }
  }

  onMount(() => {
    const events = managerEvents(showError);
    appearance = new AppearanceController({
      read: () => window.localStorage.getItem(APPEARANCE_STORAGE_KEY),
      write: value => window.localStorage.setItem(APPEARANCE_STORAGE_KEY, value),
      render: preferences => {
        const theme = preferences.theme === "system"
          ? window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"
          : preferences.theme;
        document.documentElement.dataset.theme = theme;
        document.documentElement.dataset.accent = preferences.accent;
        document.querySelector('meta[name="theme-color"]')
          ?.setAttribute("content", theme === "light" ? "#edf3f7" : "#07101d");
        document.body.style.removeProperty("zoom");
      },
      native: isTauri() ? desktopAppearanceQueue.bind({
        setZoom: async scale => {
          const { getCurrentWebview } = await import("@tauri-apps/api/webview");
          if (snapshots.alive()) await getCurrentWebview().setZoom(scale);
        },
        setTheme: async theme => {
          const { getCurrentWindow } = await import("@tauri-apps/api/window");
          if (snapshots.alive()) await getCurrentWindow().setTheme(theme);
        },
      }, () => snapshots.alive()) : undefined,
    }, state => {
      themePreference = state.preferences.theme;
      accentPreference = state.preferences.accent;
      uiScale = state.preferences.scale;
      appearanceError = state.error;
    });
    appearance.initialize();
    const systemTheme = window.matchMedia("(prefers-color-scheme: light)");
    const handleSystemThemeChange = () => appearance?.systemThemeChanged();
    systemTheme.addEventListener("change", handleSystemThemeChange);
    window.addEventListener("keydown", handleAppearanceShortcut);
    void refresh();
    void autostartSettings.refresh();
    void desktopSettings.refresh();
    events.add<InstanceView>("vpn-instance-changed", (payload) => {
      upsertInstance(payload);
      if (payload.status === "failed") {
        snapshots.changed("recovery");
        const sequence = recoveryRequests.begin();
        void invoke<RecoveryNotice[]>("list_recovery_records").then((records) => {
          if (recoveryRequests.current(sequence)) recoveryRecords = records;
        }).catch((error) => { if (recoveryRequests.current(sequence)) showError(error); });
      }
    });
    events.add<ProfileView[]>("vpn-profiles-changed", (payload) => {
      snapshots.changed("profiles");
      profiles = payload;
    });
    events.add<LogEvent>("vpn-log", (payload) => {
      mergeLogs([payload]);
    });
    events.add<VpnEngineEvent>("vpn-engine-event", (payload) => {
      void handleEngineEvent(payload);
    });
    events.add("vpn-authentication-changed", () => { void refreshAuthentication(); });
    events.add<AutoConnectError>("vpn-autoconnect-error", (payload) => {
      showError(`“${payload.profileName}”自动连接失败：${payload.message}`);
    });
    events.add<PrivilegeStatus>("vpn-privilege-changed", (payload) => {
      snapshots.changed("privilege");
      privilegeStatus = payload;
      if (!payload.required || payload.ready) {
        administratorPassword = "";
        privilegeError = "";
        pendingPrivilegeProfileId = "";
        privilegeModalOpen = false;
      }
    });
    events.add<RemoteAccessError>("remote-access-error", (payload) => {
      snapshots.changed("remote");
      remoteSettings.serviceFailed();
      showError(`远程访问服务异常：${payload.message}`);
    });
    events.add<RemoteAccessStatus>("remote-access-changed", (payload) => {
      snapshots.changed("remote");
      remoteSettings.receiveStatus(payload);
    });
    events.add<AppExitBlocked>("vpn-exit-blocked", (payload) => {
      privilegeError = payload.message;
      privilegeModalOpen = Boolean(privilegeStatus?.required);
      showError(payload.message);
    });
    events.add<TrayActionError>("vpn-tray-action-error", (payload) => {
      void handleTrayActionError(payload);
    });

    return () => {
      systemTheme.removeEventListener("change", handleSystemThemeChange);
      window.removeEventListener("keydown", handleAppearanceShortcut);
      events.dispose();
      snapshots.dispose();
      appearance?.dispose();
      autostartSettings.dispose();
      desktopSettings.dispose();
      remoteSettings.dispose();
      certificates.dispose();
      tofuPrompt = null;
      authChallenges = [];
      password = "";
      administratorPassword = "";
      remoteToken = "";
    };
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
            {#if profileHasActiveConnection(item.profile.id)}
              <span class="active-pulse" title="连接运行中"></span>
            {/if}
          </button>
        {/each}
      {/if}
    </nav>

    <button class="add-profile" onclick={createProfile}>
      <span>＋</span> 新建配置
    </button>

    <section class="sidebar-utilities" aria-label="应用工具">
      <button class="utility-button" onclick={openAppSettings}>
        <span class="utility-icon" aria-hidden="true">⚙</span>
        <span class="utility-copy">
          <b>外观与设置</b>
          <small>{uiScale}% · {themePreference === "system" ? "跟随系统" : themePreference === "dark" ? "深色" : "浅色"}</small>
        </span>
        <span class="utility-arrow" aria-hidden="true">›</span>
      </button>
      <button class="utility-button" onclick={openRemoteSettings}>
        <span class:online={remoteAccess?.running} class="remote-dot"></span>
        <span class="utility-copy">
          <b>HTTPS 远程控制</b>
          <small>{remoteAccess?.running ? "运行中" : remoteAccess?.enabled ? "启动失败" : "未启用"}</small>
        </span>
        <span class="utility-arrow" aria-hidden="true">›</span>
      </button>
    </section>

    <div class="sidebar-footer">
      <span>{engine?.platform ?? "desktop"}</span>
      <span>v0.1.6</span>
    </div>
  </aside>

  <main class="content">
    <header class="topbar">
      <div>
        <p>控制台</p>
        <h1>{selectedProfile?.profile.name ?? "VPN 配置管理"}</h1>
      </div>
      <div class="topbar-actions">
        <button class="icon-button" title="刷新" aria-label="刷新" onclick={refresh}>↻</button>
        <button class="icon-button settings-shortcut" title="外观与设置" aria-label="打开外观与设置" onclick={openAppSettings}>⚙</button>
        {#if selectedProfile}
          <button
            class="secondary-button"
            disabled={busy || selectedConnectionActive}
            onclick={() => editProfile(selectedProfile!)}
          >
            编辑配置
          </button>
          {#if selectedConnectionActive && selectedInstance}
            <button
              class="secondary-button"
              disabled={busy || selectedInstance.status === "disconnecting"}
              onclick={() => reconnectProfile(selectedProfile!, selectedInstance!)}
            >
              重新连接
            </button>
            <button
              class="primary-button disconnect-button"
              disabled={busy || selectedInstance.status === "disconnecting"}
              onclick={() => stopInstance(selectedInstance!)}
            >
              {selectedInstance.status === "disconnecting" ? "断开中…" : "断开"}
            </button>
          {:else}
            {#if selectedAuthenticationFailed}
              <button
                class="secondary-button"
                disabled={busy}
                onclick={() => editProfile(selectedProfile!)}
              >编辑配置和密码</button>
            {/if}
            <button
              class="primary-button"
              disabled={busy || !engine?.available}
              onclick={() => startProfile(selectedProfile!)}
            >
              连接
            </button>
          {/if}
        {/if}
      </div>
    </header>

    <RecoveryPanel records={recoveryRecords} onRecovered={refresh} />
    {#if errorMessage}
      <div class="notice error">
        <span>!</span><b>{errorMessage}</b>
        <button onclick={() => (errorMessage = "")}>×</button>
      </div>
    {/if}
    {#if successMessage}
      <div class="notice success"><span>✓</span><b>{successMessage}</b></div>
    {/if}
    {#if parallelNetworkWarning}
      <div class="notice warning">
        <span>!</span>
        <b>
          当前有 {activeCount} 个 VPN 同时运行；{activeRouteOwners > 1
            ? `${activeRouteOwners} 个配置正在设置路由`
            : "路由由一个配置管理"}，{activeDnsOwners > 1
            ? `${activeDnsOwners} 个配置正在设置 DNS`
            : "DNS 由一个配置管理"}。若无法同时访问，请让两个网关下发不重叠的分流路由，并只让一个 VPN 接管默认路由或全局 DNS。
        </b>
      </div>
    {/if}

    <section class="metrics">
      <article>
        <span class="metric-icon green">⌁</span>
        <div><small>已连接</small><strong>{connectedCount}</strong></div>
      </article>
      <article>
        <span class="metric-icon blue">◫</span>
        <div><small>活动连接</small><strong>{activeCount}</strong></div>
      </article>
      <article>
        <span class="metric-icon amber">◇</span>
        <div><small>配置数量</small><strong>{profiles.length}</strong></div>
      </article>
    </section>

    {#if selectedProfile}
      <ConnectionPanel {selectedProfile} {selectedInstance} {selectedChallenge} {selectedConnectionActive} {credentialStoreName} {busy} {copyConfig} {deleteProfile} {statusLabel} {formatTime} {submitAuthentication} {stopInstance} />

      <section class="panel log-panel">
        <div class="panel-heading log-heading">
          <div><small>诊断</small><h2>实时日志</h2></div>
          <div class="log-actions">
            <span>{selectedInstance ? "已筛选当前连接" : "当前配置暂无连接"}</span>
            <button onclick={() => (logs = [])}>清空</button>
            <button onclick={exportDiagnostics}>导出诊断</button>
          </div>
        </div>
        <LogViewer logs={visibleLogs} {formatTime} />
      </section>
    {:else}
      <section class="panel welcome-state">
        <div class="welcome-icon"><span></span></div>
        <h2>创建第一个 VPN 配置</h2>
        <p>保存服务器、账号、路由与 DNS 设置。每个配置独立管理；当前安全模式一次连接一个 VPN。</p>
        <button class="primary-button" onclick={createProfile}>新建配置</button>
      </section>
    {/if}
  </main>
</div>

{#if settingsOpen}
  <AppSettings {closeAppSettings} {refresh} {themeOptions} {accentOptions} {themePreference} {accentPreference} {uiScale} {MIN_UI_SCALE} {MAX_UI_SCALE} {UI_SCALE_STEP} {updateTheme} {updateAccent} {updateUiScale} {stepUiScale} {autostartLoading} {autostartBusy} {launchAtLogin} {toggleAutostart} {autostartError} {desktopPreferences} {desktopPreferencesLoading} {desktopPreferencesBusy} {toggleDesktopPreference} {desktopPreferencesError} {privilegeStatus} {remoteAccess} {openRemoteSettings} {appearanceError} {resetAppearance} {quitApplication} {activeCount} {busy} />
{/if}

{#if remoteSettingsOpen}
  <RemoteSettings bind:remoteEnabled bind:remoteBindAddress bind:remotePort {remoteToken} {remoteBusy} {remoteError} {remoteAccess} {closeRemoteSettings} {saveRemoteSettings} {openRemoteAccessUrl} {rotateRemoteToken} {copyRemoteValue} />
{/if}

{#if privilegeModalOpen && privilegeStatus?.required}
  <PrivilegeSetup bind:administratorPassword {privilegeBusy} {privilegeError} {closePrivilegeModal} {unlockPrivileges} />
{/if}

{#if editing}
  <div class="modal-backdrop" role="presentation" onclick={(event) => { if (event.target === event.currentTarget && !busy) { password = ''; editing = false; } }}>
    <ProfileEditor bind:draft bind:password bind:rememberPassword {busy} {credentialStoreName} platform={engine?.platform} onSave={saveProfile} onClose={() => { password = ''; editing = false; }} />
  </div>
{/if}

{#if tofuPrompt}
  <CertificatePrompt {tofuPrompt} {tofuBusy} {busy} {tofuError} {closeTofuPrompt} {trustCertificateAndReconnect} {formatFingerprint} />
{/if}
