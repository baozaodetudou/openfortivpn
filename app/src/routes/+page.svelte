<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import {
    disable as disableAutostart,
    enable as enableAutostart,
    isEnabled as isAutostartEnabled,
  } from "@tauri-apps/plugin-autostart";
  import { onMount } from "svelte";
  import type {
    AppExitBlocked,
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
    RemoteAccessUpdate,
    TrayActionError,
    VpnEngineEvent,
    VpnProfile,
  } from "$lib/types";

  type TofuPrompt = {
    key: string;
    instanceId: string;
    profileId: string;
    profileName: string;
    host: string;
    port: number;
    digest: string;
    reason: string;
  };

  type ThemePreference = "system" | "dark" | "light";
  type AccentPreference = "mint" | "blue" | "violet" | "amber";

  type AppearancePreferences = {
    theme: ThemePreference;
    accent: AccentPreference;
    scale: number;
  };

  const APPEARANCE_STORAGE_KEY = "openfortivpn-manager.appearance.v1";
  const MIN_UI_SCALE = 80;
  const MAX_UI_SCALE = 150;
  const UI_SCALE_STEP = 5;
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
  let successMessage = $state("");
  let tofuPrompt = $state<TofuPrompt | null>(null);
  let tofuQueue = $state<TofuPrompt[]>([]);
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
  const seenCertificateEvents = new Set<string>();
  const pendingCertificates = new Set<string>();

  function isActive(status: InstanceStatus) {
    return ["starting", "connecting", "connected", "disconnecting"].includes(
      status,
    );
  }

  function latestInstanceForProfile(profileId: string) {
    return (
      instances
        .filter((instance) => instance.profileId === profileId)
        .sort((left, right) => {
          const generationDifference =
            right.profileGeneration - left.profileGeneration;
          if (generationDifference !== 0) return generationDifference;
          const startedAtDifference = right.startedAt - left.startedAt;
          if (startedAtDifference !== 0) return startedAtDifference;
          return right.id.localeCompare(left.id);
        })[0] ?? null
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

  function isThemePreference(value: unknown): value is ThemePreference {
    return value === "system" || value === "dark" || value === "light";
  }

  function isAccentPreference(value: unknown): value is AccentPreference {
    return value === "mint" || value === "blue" || value === "violet" || value === "amber";
  }

  function clampUiScale(value: number) {
    if (!Number.isFinite(value)) return 100;
    const stepped = Math.round(value / UI_SCALE_STEP) * UI_SCALE_STEP;
    return Math.min(MAX_UI_SCALE, Math.max(MIN_UI_SCALE, stepped));
  }

  function readAppearancePreferences(): AppearancePreferences {
    try {
      const raw = window.localStorage.getItem(APPEARANCE_STORAGE_KEY);
      if (!raw) return { theme: "system", accent: "mint", scale: 100 };
      const value = JSON.parse(raw) as Partial<AppearancePreferences>;
      return {
        theme: isThemePreference(value.theme) ? value.theme : "system",
        accent: isAccentPreference(value.accent) ? value.accent : "mint",
        scale: clampUiScale(Number(value.scale)),
      };
    } catch {
      return { theme: "system", accent: "mint", scale: 100 };
    }
  }

  function resolvedTheme() {
    if (themePreference !== "system") return themePreference;
    return window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark";
  }

  function applyThemeAttributes() {
    const theme = resolvedTheme();
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.accent = accentPreference;
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", theme === "light" ? "#edf3f7" : "#07101d");
  }

  async function applyAppearancePreferences(persist = true) {
    applyThemeAttributes();
    appearanceError = "";
    if (persist) {
      try {
        window.localStorage.setItem(
          APPEARANCE_STORAGE_KEY,
          JSON.stringify({
            theme: themePreference,
            accent: accentPreference,
            scale: uiScale,
          } satisfies AppearancePreferences),
        );
      } catch (error) {
        appearanceError = `无法保存外观设置：${errorText(error)}`;
      }
    }

    if (!isTauri()) {
      document.body.style.removeProperty("zoom");
      return;
    }

    document.body.style.removeProperty("zoom");
    try {
      const { getCurrentWebview } = await import("@tauri-apps/api/webview");
      await getCurrentWebview().setZoom(uiScale / 100);
    } catch (error) {
      appearanceError = `无法应用界面缩放：${errorText(error)}`;
    }

    try {
      const { getCurrentWindow } = await import("@tauri-apps/api/window");
      await getCurrentWindow().setTheme(
        themePreference === "system" ? null : themePreference,
      );
    } catch (error) {
      appearanceError ||= `无法同步系统窗口主题：${errorText(error)}`;
    }
  }

  function updateTheme(value: ThemePreference) {
    themePreference = value;
    void applyAppearancePreferences();
  }

  function updateAccent(value: AccentPreference) {
    accentPreference = value;
    void applyAppearancePreferences();
  }

  function updateUiScale(value: number) {
    uiScale = clampUiScale(value);
    void applyAppearancePreferences();
  }

  function stepUiScale(direction: -1 | 1) {
    updateUiScale(uiScale + direction * UI_SCALE_STEP);
  }

  function resetAppearance() {
    themePreference = "system";
    accentPreference = "mint";
    uiScale = 100;
    void applyAppearancePreferences();
  }

  function openAppSettings() {
    appearanceError = "";
    settingsOpen = true;
  }

  function closeAppSettings() {
    settingsOpen = false;
    appearanceError = "";
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
    const current = instances.find(
      (instance) => instance.profileId === view.profileId,
    );
    if (
      current &&
      (view.profileGeneration < current.profileGeneration ||
        (view.profileGeneration === current.profileGeneration &&
          (view.id !== current.id || view.revision <= current.revision)))
    ) {
      return;
    }

    const merged = [
      ...instances.filter((instance) => instance.profileId !== view.profileId),
      view,
    ];
    instances = merged.sort((left, right) => {
      const generationDifference =
        right.profileGeneration - left.profileGeneration;
      if (generationDifference !== 0) return generationDifference;
      const startedAtDifference = right.startedAt - left.startedAt;
      if (startedAtDifference !== 0) return startedAtDifference;
      return right.id.localeCompare(left.id);
    });
  }

  function mergeLogs(entries: LogEvent[]) {
    const merged = new Map<string, LogEvent>();
    for (const entry of [...logs, ...entries]) {
      merged.set(
        `${entry.instanceId}:${entry.timestamp}:${entry.stream}:${entry.line}`,
        entry,
      );
    }
    logs = [...merged.values()]
      .sort((left, right) => left.timestamp - right.timestamp)
      .slice(-400);
  }

  function errorText(error: unknown) {
    return error instanceof Error ? error.message : String(error);
  }

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
    if (tofuPrompt) pendingCertificates.delete(tofuPrompt.key);
    const [next, ...remaining] = tofuQueue;
    tofuQueue = remaining;
    tofuPrompt = next ?? null;
    tofuError = "";
  }

  function enqueueTofuPrompt(prompt: TofuPrompt) {
    if (pendingCertificates.has(prompt.key)) return;
    pendingCertificates.add(prompt.key);
    if (tofuPrompt) tofuQueue = [...tofuQueue, prompt];
    else tofuPrompt = prompt;
  }

  async function handleEngineEvent(event: VpnEngineEvent) {
    const { payload, instanceId } = event;
    const digest =
      typeof payload.digest === "string" ? payload.digest.toLowerCase() : "";
    if (payload.event !== "cert_error" || !/^[0-9a-f]{64}$/.test(digest)) {
      return;
    }

    const eventKey = `${instanceId}:${digest}`;
    if (seenCertificateEvents.has(eventKey)) return;
    seenCertificateEvents.add(eventKey);

    let profileId = event.profileId;
    if (!profileId) {
      let instance = instances.find((entry) => entry.id === instanceId);
      try {
        if (!instance) {
          const latestInstances = await invoke<InstanceView[]>("list_instances");
          latestInstances.forEach(upsertInstance);
          instance = latestInstances.find((entry) => entry.id === instanceId);
        }
        profileId = instance?.profileId ?? "";
      } catch (error) {
        showError(error);
        return;
      }
    }

    const profile = profiles.find(
      (entry) => entry.profile.id === profileId,
    );
    if (!profile) {
      showError("收到服务器证书，但无法找到对应的 VPN 配置");
      return;
    }

    enqueueTofuPrompt({
      key: `${profile.profile.id}:${digest}`,
      instanceId,
      profileId: profile.profile.id,
      profileName: profile.profile.name,
      host: profile.profile.host,
      port: profile.profile.port,
      digest,
      reason: typeof payload.reason === "string" ? payload.reason : "",
    });
  }

  async function trustCertificateAndReconnect() {
    const prompt = tofuPrompt;
    if (!prompt || tofuBusy || busy) return;

    tofuBusy = true;
    busy = true;
    tofuError = "";
    try {
      await waitForProfileToStop(prompt.profileId);
      const current = profiles.find(
        (entry) => entry.profile.id === prompt.profileId,
      );
      if (!current) throw new Error("对应的 VPN 配置已不存在");

      const saved = await invoke<ProfileView>("save_profile", {
        input: {
          profile: { ...current.profile, trustedCert: prompt.digest },
          password: null,
          rememberPassword: Boolean(current.passwordStored),
        },
      });
      upsertProfile(saved);

      const instance = await invoke<InstanceView>("start_profile", {
        profileId: prompt.profileId,
      });
      upsertInstance(instance);
      selectedProfileId = prompt.profileId;
      closeTofuPrompt();
      showSuccess("已信任服务器证书并重新连接");
    } catch (error) {
      tofuError = errorText(error);
    } finally {
      tofuBusy = false;
      busy = false;
    }
  }

  async function refresh() {
    loading = true;
    try {
      const [profileList, instanceList, logList, engineState, currentPrivilegeStatus, currentRemoteAccess] = await Promise.all([
        invoke<ProfileView[]>("list_profiles"),
        invoke<InstanceView[]>("list_instances"),
        invoke<LogEvent[]>("list_logs", { instanceId: null, limit: 400 }),
        invoke<EngineInfo>("engine_info"),
        invoke<PrivilegeStatus>("privilege_status"),
        invoke<RemoteAccessStatus>("remote_access_status"),
      ]);
      profiles = profileList;
      instanceList.forEach(upsertInstance);
      mergeLogs(logList);
      engine = engineState;
      privilegeStatus = currentPrivilegeStatus;
      remoteAccess = currentRemoteAccess;
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
  }

  function createProfile() {
    draft = blankProfile();
    password = "";
    rememberPassword = true;
    editing = true;
  }

  function editProfile(view: ProfileView) {
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
      const saved = await invoke<ProfileView>("save_profile", {
        input: {
          profile: { ...draft, port: Number(draft.port) },
          password: password || null,
          rememberPassword,
        },
      });
      upsertProfile(saved);
      selectedProfileId = saved.profile.id;
      editing = false;
      password = "";
      rememberPassword = false;
      showSuccess("配置已保存");
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function deleteProfile(view: ProfileView) {
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
      const message = errorText(error);
      showError(message);
      if (isVpnCredentialError(message)) {
        try {
          const profileList = await invoke<ProfileView[]>("list_profiles");
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
      busy = false;
    }
  }

  async function stopInstance(instance: InstanceView) {
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
      busy = false;
    }
  }

  async function waitForProfileToStop(profileId: string) {
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      const snapshot = await invoke<InstanceView[]>("list_instances");
      snapshot.forEach(upsertInstance);
      const instance = snapshot.find((entry) => entry.profileId === profileId);
      if (!instance || !isActive(instance.status)) return instance ?? null;
      await new Promise<void>((resolve) => window.setTimeout(resolve, 250));
    }
    throw new Error("等待旧连接断开超时，请确认进程状态后重试");
  }

  async function reconnectProfile(view: ProfileView, instance: InstanceView) {
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
      busy = false;
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

  function profileHasActiveConnection(profileId: string) {
    const instance = latestInstanceForProfile(profileId);
    return instance ? isActive(instance.status) : false;
  }

  async function refreshAutostart() {
    autostartLoading = true;
    autostartError = "";
    try {
      launchAtLogin = await isAutostartEnabled();
    } catch (error) {
      autostartError = `无法读取登录启动状态：${errorText(error)}`;
    } finally {
      autostartLoading = false;
    }
  }

  async function toggleAutostart(event: Event) {
    if (autostartLoading || autostartBusy) return;

    const next = (event.currentTarget as HTMLInputElement).checked;
    const previous = launchAtLogin;
    autostartBusy = true;
    autostartError = "";
    try {
      if (next) await enableAutostart();
      else await disableAutostart();

      launchAtLogin = await isAutostartEnabled();
      if (launchAtLogin !== next) {
        throw new Error("系统未能更新登录启动设置");
      }
    } catch (error) {
      launchAtLogin = previous;
      autostartError = `无法${next ? "启用" : "关闭"}登录时启动：${errorText(error)}`;
    } finally {
      autostartBusy = false;
    }
  }

  async function refreshDesktopPreferences() {
    desktopPreferencesLoading = true;
    desktopPreferencesError = "";
    try {
      desktopPreferences = await invoke<DesktopPreferences>(
        "get_desktop_preferences",
      );
    } catch (error) {
      desktopPreferencesError = `无法读取后台运行设置：${errorText(error)}`;
    } finally {
      desktopPreferencesLoading = false;
    }
  }

  async function toggleDesktopPreference(
    key: keyof DesktopPreferences,
    event: Event,
  ) {
    if (desktopPreferencesLoading || desktopPreferencesBusy) return;
    const previous = desktopPreferences;
    const next = {
      ...desktopPreferences,
      [key]: (event.currentTarget as HTMLInputElement).checked,
    };
    desktopPreferencesBusy = true;
    desktopPreferencesError = "";
    desktopPreferences = next;
    try {
      desktopPreferences = await invoke<DesktopPreferences>(
        "update_desktop_preferences",
        { preferences: next },
      );
    } catch (error) {
      desktopPreferences = previous;
      desktopPreferencesError = `无法保存后台运行设置：${errorText(error)}`;
    } finally {
      desktopPreferencesBusy = false;
    }
  }

  async function handleTrayActionError(error: TrayActionError) {
    if (error.profileId) selectedProfileId = error.profileId;
    showError(error.message);
    if (error.profileId && isVpnCredentialError(error.message)) {
      try {
        const profileList = await invoke<ProfileView[]>("list_profiles");
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
        privilegeStatus = await invoke<PrivilegeStatus>("privilege_status");
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
    void invoke("quit_app");
  }

  function openRemoteSettings() {
    settingsOpen = false;
    remoteEnabled = remoteAccess?.enabled ?? false;
    remoteBindAddress = remoteAccess?.bindAddress ?? "127.0.0.1";
    remotePort = remoteAccess?.port ?? 18443;
    remoteToken = "";
    remoteError = "";
    remoteSettingsOpen = true;
  }

  function closeRemoteSettings() {
    if (remoteBusy) return;
    remoteToken = "";
    remoteError = "";
    remoteSettingsOpen = false;
  }

  async function saveRemoteSettings(event: SubmitEvent) {
    event.preventDefault();
    if (remoteBusy) return;
    remoteBusy = true;
    remoteError = "";
    try {
      const update = await invoke<RemoteAccessUpdate>("configure_remote_access", {
        input: {
          enabled: remoteEnabled,
          bindAddress: remoteBindAddress.trim(),
          port: Number(remotePort),
        },
      });
      remoteAccess = update.status;
      remoteToken = update.token ?? "";
      showSuccess(remoteEnabled ? "HTTPS 远程访问已启动" : "远程访问已关闭");
      if (!update.token) closeRemoteSettings();
    } catch (error) {
      remoteError = errorText(error);
    } finally {
      remoteBusy = false;
    }
  }

  async function rotateRemoteToken() {
    if (remoteBusy || !window.confirm("更新令牌后，所有已登录的远程浏览器都需要重新登录。继续吗？")) return;
    remoteBusy = true;
    remoteError = "";
    try {
      const update = await invoke<RemoteAccessUpdate>("rotate_remote_access_token");
      remoteAccess = update.status;
      remoteToken = update.token ?? "";
    } catch (error) {
      remoteError = errorText(error);
    } finally {
      remoteBusy = false;
    }
  }

  async function copyRemoteValue(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      showSuccess(`${label}已复制`);
    } catch (error) {
      remoteError = `复制失败：${errorText(error)}`;
    }
  }

  async function openRemoteAccessUrl() {
    if (!remoteAccess?.running) return;
    try {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await openUrl(remoteAccess.url);
    } catch (error) {
      remoteError = `无法打开浏览器：${errorText(error)}`;
    }
  }

  function closePrivilegeModal() {
    if (privilegeBusy) return;
    administratorPassword = "";
    privilegeError = "";
    pendingPrivilegeProfileId = "";
    privilegeModalOpen = false;
  }

  async function unlockPrivileges(event: SubmitEvent) {
    event.preventDefault();
    if (privilegeBusy || !administratorPassword) return;

    privilegeBusy = true;
    privilegeError = "";
    const pendingProfileId = pendingPrivilegeProfileId;
    try {
      const status = await invoke<PrivilegeStatus>("unlock_privileges", {
        password: administratorPassword,
      });
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
      privilegeError = `安装失败：${errorText(error)}`;
    } finally {
      administratorPassword = "";
      privilegeBusy = false;
    }
  }

  onMount(() => {
    const unlisteners: UnlistenFn[] = [];
    const preferences = readAppearancePreferences();
    themePreference = preferences.theme;
    accentPreference = preferences.accent;
    uiScale = preferences.scale;
    void applyAppearancePreferences(false);
    const systemTheme = window.matchMedia("(prefers-color-scheme: light)");
    const handleSystemThemeChange = () => {
      if (themePreference === "system") applyThemeAttributes();
    };
    systemTheme.addEventListener("change", handleSystemThemeChange);
    window.addEventListener("keydown", handleAppearanceShortcut);
    void refresh();
    void refreshAutostart();
    void refreshDesktopPreferences();
    void listen<InstanceView>("vpn-instance-changed", ({ payload }) => {
      upsertInstance(payload);
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<ProfileView[]>("vpn-profiles-changed", ({ payload }) => {
      profiles = payload;
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<LogEvent>("vpn-log", ({ payload }) => {
      mergeLogs([payload]);
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<VpnEngineEvent>("vpn-engine-event", ({ payload }) => {
      void handleEngineEvent(payload);
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<AutoConnectError>("vpn-autoconnect-error", ({ payload }) => {
      showError(`“${payload.profileName}”自动连接失败：${payload.message}`);
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<PrivilegeStatus>("vpn-privilege-changed", ({ payload }) => {
      privilegeStatus = payload;
      if (!payload.required || payload.ready) {
        administratorPassword = "";
        privilegeError = "";
        pendingPrivilegeProfileId = "";
        privilegeModalOpen = false;
      }
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<RemoteAccessError>("remote-access-error", ({ payload }) => {
      if (remoteAccess) remoteAccess = { ...remoteAccess, running: false };
      showError(`远程访问服务异常：${payload.message}`);
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<RemoteAccessStatus>("remote-access-changed", ({ payload }) => {
      remoteAccess = payload;
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<AppExitBlocked>("vpn-exit-blocked", ({ payload }) => {
      privilegeError = payload.message;
      privilegeModalOpen = Boolean(privilegeStatus?.required);
      showError(payload.message);
    }).then((unlisten) => unlisteners.push(unlisten));
    void listen<TrayActionError>("vpn-tray-action-error", ({ payload }) => {
      void handleTrayActionError(payload);
    }).then((unlisten) => unlisteners.push(unlisten));

    return () => {
      systemTheme.removeEventListener("change", handleSystemThemeChange);
      window.removeEventListener("keydown", handleAppearanceShortcut);
      unlisteners.forEach((unlisten) => unlisten());
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
      <span>v0.1.5</span>
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
        </article>
      </section>

      <section class="panel log-panel">
        <div class="panel-heading log-heading">
          <div><small>诊断</small><h2>实时日志</h2></div>
          <div class="log-actions">
            <span>{selectedInstance ? "已筛选当前连接" : "当前配置暂无连接"}</span>
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
        <p>保存服务器、账号、路由与 DNS 设置。一个配置一个连接，多个配置可同时连接。</p>
        <button class="primary-button" onclick={createProfile}>新建配置</button>
      </section>
    {/if}
  </main>
</div>

{#if settingsOpen}
  <div
    class="modal-backdrop settings-backdrop"
    role="presentation"
    onclick={(event) => {
      if (event.target === event.currentTarget) closeAppSettings();
    }}
  >
    <div
      class="settings-modal"
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
{/if}

{#if remoteSettingsOpen}
  <div class="modal-backdrop remote-backdrop" role="presentation">
    <form class="remote-modal" onsubmit={saveRemoteSettings}>
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
{/if}

{#if privilegeModalOpen && privilegeStatus?.required}
  <div class="modal-backdrop privilege-backdrop" role="presentation">
    <div
      class="privilege-modal"
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
{/if}

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
              ? engine?.platform === "macos"
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
        “应用启动后自动连接”要求 VPN 密码已保存；“意外断线自动重连”只处理非主动断开的连接。macOS/Linux 首次安装受限系统 Helper 后可无人值守连接。不同配置可同时连接，但多个默认路由或全局 DNS 配置可能互相冲突，建议并发 VPN 使用不重叠的分流路由。
      </div>
      <div class="modal-actions">
        <button type="button" class="secondary-button" disabled={busy} onclick={() => (editing = false)}>取消</button>
        <button type="submit" class="primary-button" disabled={busy}>{busy ? "保存中…" : "保存配置"}</button>
      </div>
    </form>
  </div>
{/if}

{#if tofuPrompt}
  <div class="modal-backdrop tofu-backdrop" role="presentation">
    <div
      class="tofu-modal"
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
{/if}

<style>
  .app-shell { display: grid; grid-template-columns: 276px minmax(0, 1fr); min-height: 100vh; }
  .sidebar { position: sticky; top: 0; display: flex; flex-direction: column; height: 100vh; padding: 24px 18px 16px; border-right: 1px solid var(--line); background: var(--sidebar-bg); backdrop-filter: blur(20px); }
  .brand { display: flex; gap: 12px; align-items: center; padding: 0 8px 24px; }
  .brand strong, .brand small { display: block; } .brand strong { font-size: 15px; letter-spacing: .01em; } .brand small { margin-top: 3px; color: var(--muted); font-size: 11px; }
  .brand-mark { display: grid; place-items: center; width: 38px; height: 38px; border: 1px solid rgba(var(--brand-rgb),.35); border-radius: 12px; background: linear-gradient(145deg, rgba(var(--brand-rgb),.17), rgba(var(--brand-rgb),.05)); box-shadow: inset 0 1px rgba(255,255,255,.08); }
  .brand-mark span { width: 17px; height: 17px; border: 2px solid var(--brand); border-radius: 50% 50% 48% 52%; transform: rotate(-20deg); }
  .engine-state { display: flex; gap: 10px; align-items: center; margin-bottom: 25px; padding: 11px 12px; border: 1px solid var(--line); border-radius: 12px; background: var(--panel-subtle); }
  .engine-state b, .engine-state small { display: block; overflow: hidden; max-width: 190px; text-overflow: ellipsis; white-space: nowrap; } .engine-state b { font-size: 12px; } .engine-state small { margin-top: 3px; color: var(--muted); font-size: 10px; }
  .engine-dot { width: 8px; height: 8px; flex: 0 0 auto; border-radius: 50%; background: var(--danger); box-shadow: 0 0 0 4px rgba(255,124,141,.1); } .engine-state.available .engine-dot { background: var(--brand); box-shadow: 0 0 0 4px rgba(var(--brand-rgb),.1); }
  .section-heading { display: flex; align-items: center; justify-content: space-between; padding: 0 8px 9px; color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
  .count { display: grid; place-items: center; min-width: 22px; height: 18px; border-radius: 999px; background: var(--panel-soft); color: var(--text-soft); }
  .profile-list { display: flex; flex: 1; flex-direction: column; gap: 5px; overflow-y: auto; margin: 0 -4px; padding: 0 4px; }
  .profile-item { display: flex; align-items: center; width: 100%; padding: 10px; border: 1px solid transparent; border-radius: 12px; color: var(--text); background: transparent; cursor: pointer; text-align: left; transition: .16s ease; }
  .profile-item:hover { background: var(--panel-hover); } .profile-item.active { border-color: rgba(var(--brand-rgb),.24); background: var(--brand-soft); }
  .profile-icon { display: grid; place-items: center; width: 34px; height: 34px; flex: 0 0 auto; border-radius: 10px; color: var(--brand); background: var(--brand-soft); font-size: 12px; font-weight: 800; }
  .profile-copy { min-width: 0; margin-left: 10px; } .profile-copy b, .profile-copy small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; } .profile-copy b { font-size: 12px; } .profile-copy small { margin-top: 4px; color: var(--muted); font-size: 10px; }
  .active-pulse { width: 7px; height: 7px; margin-left: auto; border-radius: 50%; background: var(--brand); box-shadow: 0 0 10px rgba(var(--brand-rgb),.7); }
  .sidebar-empty { padding: 20px 10px; color: var(--muted); font-size: 11px; text-align: center; }
  .add-profile { display: flex; justify-content: center; gap: 8px; align-items: center; width: 100%; margin-top: 14px; padding: 10px 12px; border: 1px dashed var(--line-strong); border-radius: 11px; color: var(--text-soft); background: transparent; cursor: pointer; font-size: 11px; font-weight: 700; } .add-profile:hover { border-color: rgba(var(--brand-rgb),.45); color: var(--brand); background: var(--brand-soft); }
  .sidebar-utilities { display: grid; gap: 5px; margin-top: 13px; padding-top: 12px; border-top: 1px solid var(--line); }
  .utility-button { display: grid; grid-template-columns: 28px minmax(0,1fr) auto; gap: 9px; align-items: center; width: 100%; padding: 8px; border: 1px solid transparent; border-radius: 11px; color: var(--text-soft); background: transparent; cursor: pointer; text-align: left; transition: .16s ease; }
  .utility-button:hover { border-color: var(--line); background: var(--panel-hover); }
  .utility-icon { display: grid; width: 28px; height: 28px; place-items: center; border-radius: 9px; color: var(--brand); background: var(--brand-soft); font-size: 13px; }
  .utility-copy { min-width: 0; } .utility-copy b, .utility-copy small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; } .utility-copy b { font-size: 9px; } .utility-copy small { margin-top: 3px; color: var(--muted-soft); font-size: 8px; }
  .utility-arrow { color: var(--muted-faint); font-size: 16px; }
  .remote-dot { width: 8px; height: 8px; margin-left: 10px; border-radius: 50%; background: var(--muted-faint); } .remote-dot.online { background: var(--brand); box-shadow: 0 0 8px rgba(var(--brand-rgb),.6); }
  .sidebar-footer { display: flex; justify-content: space-between; padding: 14px 8px 0; color: var(--muted-faint); font-size: 9px; text-transform: uppercase; }
  .content { min-width: 0; padding: 30px 34px 36px; }
  .topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; } .topbar p { margin: 0 0 4px; color: var(--brand); font-size: 9px; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; } .topbar h1 { margin: 0; font-size: 23px; letter-spacing: -.025em; }
  .topbar-actions { display: flex; gap: 9px; align-items: center; }
  .primary-button, .secondary-button, .icon-button, .ghost-button, .danger-ghost { border-radius: 10px; cursor: pointer; font-size: 11px; font-weight: 750; transition: .16s ease; }
  .primary-button { padding: 10px 18px; color: var(--brand-contrast); background: var(--brand); box-shadow: 0 8px 24px rgba(var(--brand-strong-rgb),.17); } .primary-button:not(:disabled):hover { background: var(--brand-hover); transform: translateY(-1px); }
  .primary-button.disconnect-button { color: #fff1f3; background: rgba(255,124,141,.82); box-shadow: 0 8px 24px rgba(255,124,141,.13); }
  .secondary-button { padding: 9px 15px; border: 1px solid var(--line); color: var(--text-soft); background: var(--panel); } .secondary-button:not(:disabled):hover { border-color: var(--line-strong); background: var(--panel-soft); }
  .icon-button { width: 36px; height: 36px; border: 1px solid var(--line); color: var(--muted); background: var(--panel); font-size: 18px; }
  .primary-button:disabled, .secondary-button:disabled, .ghost-button:disabled, .danger-ghost:disabled { cursor: not-allowed; opacity: .48; transform: none; }
  .notice { display: flex; align-items: center; gap: 10px; margin: -8px 0 18px; padding: 10px 13px; border-radius: 10px; font-size: 11px; } .notice span { display: grid; place-items: center; width: 20px; height: 20px; border-radius: 50%; } .notice b { font-weight: 650; } .notice button { margin-left: auto; color: inherit; background: transparent; cursor: pointer; font-size: 18px; }
  .notice.error { border: 1px solid rgba(255,124,141,.24); color: var(--danger-text); background: rgba(255,124,141,.08); } .notice.error span { background: rgba(255,124,141,.14); } .notice.success { border: 1px solid rgba(var(--brand-rgb),.2); color: var(--brand-strong); background: rgba(var(--brand-rgb),.08); } .notice.success span { background: rgba(var(--brand-rgb),.14); }
  .notice.warning { border: 1px solid rgba(246,200,108,.22); color: var(--warning-text); background: rgba(246,200,108,.07); line-height: 1.55; } .notice.warning span { flex: 0 0 auto; background: rgba(246,200,108,.14); }
  .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 14px; } .metrics article { display: flex; align-items: center; gap: 13px; padding: 14px 16px; border: 1px solid var(--line); border-radius: 13px; background: var(--panel-translucent); } .metrics small, .metrics strong { display: block; } .metrics small { color: var(--muted); font-size: 10px; } .metrics strong { margin-top: 2px; font-size: 20px; }
  .metric-icon { display: grid; place-items: center; width: 36px; height: 36px; border-radius: 10px; font-size: 16px; } .metric-icon.green { color: var(--brand); background: var(--brand-soft); } .metric-icon.blue { color: var(--blue); background: rgba(112,167,255,.1); } .metric-icon.amber { color: var(--warning); background: rgba(246,200,108,.1); }
  .overview-grid { display: grid; grid-template-columns: minmax(310px, .9fr) minmax(360px, 1.1fr); gap: 14px; margin-bottom: 14px; }
  .panel { border: 1px solid var(--line); border-radius: 14px; background: var(--panel-translucent); box-shadow: 0 16px 40px color-mix(in srgb, var(--shadow) 24%, transparent); }
  .connection-card, .instance-panel { min-height: 286px; padding: 18px; }
  .panel-heading { display: flex; align-items: flex-start; justify-content: space-between; } .panel-heading small { color: var(--muted); font-size: 9px; font-weight: 700; letter-spacing: .11em; text-transform: uppercase; } .panel-heading h2 { margin: 4px 0 0; font-size: 15px; }
  .secret-state { padding: 5px 8px; border-radius: 999px; color: var(--warning); background: rgba(246,200,108,.09); font-size: 9px; font-weight: 750; } .secret-state.ready { color: var(--brand); background: var(--brand-soft); }
  .endpoint { display: flex; align-items: center; gap: 12px; margin: 18px 0 16px; padding: 13px; border: 1px solid var(--line); border-radius: 11px; background: var(--panel-subtle); } .endpoint-lock { display: grid; place-items: center; width: 32px; height: 32px; border-radius: 9px; color: var(--brand); background: var(--brand-soft); font-size: 11px; } .endpoint small, .endpoint strong { display: block; } .endpoint small { color: var(--muted); font-size: 9px; } .endpoint strong { margin-top: 4px; font-family: "SFMono-Regular", Consolas, monospace; font-size: 11px; }
  .profile-facts { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin: 0; } .profile-facts div { min-width: 0; } .profile-facts dt { margin-bottom: 3px; color: var(--muted); font-size: 9px; } .profile-facts dd { overflow: hidden; margin: 0; color: var(--text-soft); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
  .card-actions { display: flex; gap: 8px; margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--line); } .ghost-button, .danger-ghost { padding: 7px 10px; border: 1px solid var(--line); background: transparent; } .ghost-button { color: var(--text-soft); } .danger-ghost { margin-left: auto; color: var(--danger); } .ghost-button:hover, .danger-ghost:hover { background: var(--panel-hover); }
  .connection-status { display: flex; gap: 6px; align-items: center; padding: 5px 8px; border-radius: 999px; color: var(--muted); background: var(--panel-soft); font-size: 9px; font-weight: 750; } .connection-status.connected { color: var(--brand); background: var(--brand-soft); } .connection-status.starting, .connection-status.connecting, .connection-status.disconnecting { color: var(--warning); background: rgba(246,200,108,.09); } .connection-status.failed { color: var(--danger); background: rgba(255,124,141,.08); }
  .status-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); } .status-dot.connected { background: var(--brand); box-shadow: 0 0 8px rgba(var(--brand-rgb),.65); } .status-dot.connecting, .status-dot.starting { background: var(--warning); } .status-dot.failed { background: var(--danger); }
  .status-dot.disconnecting { background: var(--warning); }
  .instance-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin: 18px 0 0; } .instance-facts div { min-width: 0; padding: 11px 12px; border: 1px solid var(--line); border-radius: 10px; background: var(--panel-subtle); } .instance-facts dt { margin-bottom: 5px; color: var(--muted); font-size: 9px; } .instance-facts dd { overflow: hidden; margin: 0; color: var(--text-soft); font: 10px/1.5 "SFMono-Regular", Consolas, monospace; text-overflow: ellipsis; white-space: nowrap; } .instance-facts .instance-message { grid-column: 1 / -1; } .instance-facts .instance-message dd { overflow-wrap: anywhere; white-space: normal; }
  .empty-state.compact { display: grid; place-items: center; padding: 44px 12px; color: var(--muted); } .empty-state.compact span { font-size: 24px; } .empty-state.compact p { margin: 8px 0 0; font-size: 10px; }
  .log-panel { overflow: hidden; } .log-heading { padding: 15px 18px 12px; } .log-actions { display: flex; gap: 10px; align-items: center; color: var(--muted); font-size: 9px; } .log-actions button { padding: 5px 8px; border-radius: 7px; color: #aebdd1; background: var(--panel-soft); cursor: pointer; font-size: 9px; }
  .terminal { height: 178px; overflow: auto; padding: 12px 16px 16px; border-top: 1px solid var(--line); color-scheme: dark; background: var(--terminal-bg); font: 10px/1.65 "SFMono-Regular", Consolas, monospace; } .terminal-empty { display: grid; height: 100%; place-items: center; color: #697a8f; } .log-line { display: grid; grid-template-columns: 66px minmax(0,1fr); gap: 10px; color: #a9b8cb; } .log-line time { color: #66768d; } .log-line.error-line span { color: #e4b2b9; }
  .welcome-state { display: grid; min-height: 490px; place-items: center; align-content: center; padding: 40px; text-align: center; } .welcome-state h2 { margin: 20px 0 8px; font-size: 20px; } .welcome-state p { max-width: 440px; margin: 0 0 22px; color: var(--muted); font-size: 12px; line-height: 1.7; }
  .welcome-icon { display: grid; place-items: center; width: 72px; height: 72px; border: 1px solid rgba(var(--brand-rgb),.25); border-radius: 24px; background: var(--brand-soft); } .welcome-icon span { width: 28px; height: 28px; border: 3px solid var(--brand); border-radius: 50%; }
  .modal-backdrop { position: fixed; z-index: 30; inset: 0; display: grid; place-items: center; padding: 24px; background: var(--backdrop); backdrop-filter: blur(10px); }
  .profile-modal { width: min(650px, 94vw); max-height: 92vh; overflow-y: auto; padding: 22px; border: 1px solid var(--line-strong); border-radius: 17px; background: var(--modal-bg); box-shadow: 0 30px 90px var(--shadow); }
  .modal-heading { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; } .modal-heading small { color: var(--brand); font-size: 9px; font-weight: 800; letter-spacing: .14em; } .modal-heading h2 { margin: 4px 0 0; font-size: 19px; } .modal-heading button { width: 32px; height: 32px; border-radius: 9px; color: var(--muted); background: var(--panel-soft); cursor: pointer; font-size: 18px; }
  .form-grid { display: grid; grid-template-columns: 1fr 150px; gap: 13px; } .form-grid .span-2 { grid-column: span 2; } .form-grid label > span { display: block; margin: 0 0 6px 2px; color: var(--text-soft); font-size: 10px; font-weight: 650; } .form-grid em { margin-left: 6px; color: var(--muted); font-size: 8px; font-style: normal; font-weight: 500; }
  .form-grid input { width: 100%; padding: 10px 11px; border: 1px solid var(--line); border-radius: 9px; color: var(--text); background: var(--control-bg); font-size: 11px; transition: border-color .15s; } .form-grid input:focus { border-color: rgba(var(--brand-rgb),.45); } .form-grid input::placeholder { color: var(--muted-faint); }
  .field-help { display: block; margin: 7px 2px 0; color: var(--muted-soft); font-size: 9px; line-height: 1.55; }
  fieldset { margin: 18px 0 0; padding: 13px; border: 1px solid var(--line); border-radius: 11px; } legend { padding: 0 7px; color: var(--muted); font-size: 9px; font-weight: 700; text-transform: uppercase; }
  .toggle-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; } .toggle { display: flex; align-items: center; gap: 8px; cursor: pointer; } .toggle input { position: absolute; opacity: 0; pointer-events: none; } .toggle > span { position: relative; width: 28px; height: 16px; flex: 0 0 auto; border: 1px solid var(--line); border-radius: 999px; background: var(--panel-soft); transition: .18s; } .toggle > span::after { position: absolute; top: 2px; left: 2px; width: 10px; height: 10px; border-radius: 50%; background: var(--muted); content: ""; transition: .18s; } .toggle input:checked + span { border-color: rgba(var(--brand-rgb),.28); background: rgba(var(--brand-rgb),.28); } .toggle input:checked + span::after { left: 14px; background: var(--brand); } .toggle b { color: var(--text-soft); font-size: 9px; font-weight: 650; }
  .modal-note { margin-top: 14px; padding: 10px 11px; border-radius: 9px; color: var(--muted); background: rgba(112,167,255,.055); font-size: 9px; line-height: 1.55; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 9px; margin-top: 20px; }
  .settings-backdrop { z-index: 58; display: block; overflow-y: auto; }
  .settings-modal { width: min(760px, 94vw); max-height: 92vh; overflow-y: auto; margin: 0 auto; padding: 25px; border: 1px solid var(--line-strong); border-radius: 20px; background: var(--modal-bg); box-shadow: 0 32px 100px var(--shadow); }
  .settings-modal-heading { margin-bottom: 18px; padding-bottom: 18px; border-bottom: 1px solid var(--line); }
  .settings-modal-heading p { margin: 7px 0 0; color: var(--muted); font-size: 10px; }
  .settings-content { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(260px, .8fr); gap: 14px; }
  .settings-section { min-width: 0; padding: 17px; border: 1px solid var(--line); border-radius: 14px; background: var(--panel-subtle); }
  .appearance-section { grid-row: span 2; }
  .settings-section-heading { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 15px; }
  .settings-section-heading > div { display: flex; gap: 10px; align-items: center; }
  .settings-section-heading h3, .settings-section-heading p { margin: 0; } .settings-section-heading h3 { color: var(--text); font-size: 12px; } .settings-section-heading p { margin-top: 3px; color: var(--muted); font-size: 8px; }
  .settings-section-heading > strong { color: var(--brand); font-size: 13px; }
  .settings-section-icon { display: grid; width: 31px; height: 31px; flex: 0 0 auto; place-items: center; border: 1px solid rgba(var(--brand-rgb),.16); border-radius: 9px; color: var(--brand); background: var(--brand-soft); font-size: 10px; font-weight: 800; }
  .theme-options { display: grid; gap: 7px; }
  .theme-option { display: grid; grid-template-columns: 62px minmax(0,1fr) 20px; gap: 11px; align-items: center; width: 100%; padding: 9px; border: 1px solid var(--line); border-radius: 11px; color: var(--text); background: var(--panel); cursor: pointer; text-align: left; transition: .16s ease; }
  .theme-option:hover { border-color: var(--line-strong); transform: translateY(-1px); } .theme-option.active { border-color: rgba(var(--brand-rgb),.42); background: var(--brand-soft); }
  .theme-option > span:nth-child(2) { min-width: 0; } .theme-option b, .theme-option small { display: block; } .theme-option b { font-size: 10px; } .theme-option small { margin-top: 3px; color: var(--muted); font-size: 8px; }
  .theme-preview { position: relative; display: grid; grid-template-columns: 18px 1fr; grid-template-rows: 11px 1fr; width: 62px; height: 39px; overflow: hidden; border: 1px solid rgba(80,100,120,.22); border-radius: 7px; background: #f5f7fa; box-shadow: 0 4px 10px rgba(0,0,0,.08); }
  .theme-preview i:first-child { grid-row: 1 / -1; background: #132033; } .theme-preview i:nth-child(2) { background: #e3e9ef; } .theme-preview i:nth-child(3) { margin: 4px; border-radius: 3px; background: #fff; }
  .theme-preview.dark { background: #0a1422; } .theme-preview.dark i:first-child { background: #07101d; } .theme-preview.dark i:nth-child(2) { background: #17263a; } .theme-preview.dark i:nth-child(3) { background: #223148; }
  .theme-preview.system::after { position: absolute; inset: 0 0 0 50%; background: rgba(7,16,29,.9); content: ""; clip-path: inset(0 0 0 0); }
  .selection-check { display: grid; width: 18px; height: 18px; place-items: center; border: 1px solid var(--line); border-radius: 50%; color: transparent; font-size: 9px; font-style: normal; } .theme-option.active .selection-check { border-color: var(--brand); color: var(--brand-contrast); background: var(--brand); }
  .accent-setting { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 13px; padding-top: 13px; border-top: 1px solid var(--line); } .accent-setting b, .accent-setting small { display: block; } .accent-setting b { color: var(--text-soft); font-size: 9px; } .accent-setting small { margin-top: 3px; color: var(--muted); font-size: 8px; }
  .accent-options { display: flex; gap: 7px; }
  .accent-option { display: grid; width: 27px; height: 27px; place-items: center; border: 1px solid transparent; border-radius: 9px; background: transparent; cursor: pointer; } .accent-option span { width: 15px; height: 15px; border-radius: 50%; box-shadow: inset 0 0 0 1px rgba(0,0,0,.1); } .accent-option.mint span { background: #5ee8b1; } .accent-option.blue span { background: #70a7ff; } .accent-option.violet span { background: #ae91ff; } .accent-option.amber span { background: #f2b85b; } .accent-option.active { border-color: var(--line-strong); background: var(--panel-soft); } .accent-option.active span { box-shadow: 0 0 0 3px var(--modal-bg), 0 0 0 5px currentColor; }
  .accent-option.mint { color: #5ee8b1; } .accent-option.blue { color: #70a7ff; } .accent-option.violet { color: #ae91ff; } .accent-option.amber { color: #f2b85b; }
  .scale-control { display: grid; grid-template-columns: 31px minmax(0,1fr) 31px; gap: 9px; align-items: center; }
  .scale-control button { width: 31px; height: 31px; border: 1px solid var(--line); border-radius: 9px; color: var(--text-soft); background: var(--panel); cursor: pointer; font-size: 16px; } .scale-control button:hover:not(:disabled) { border-color: rgba(var(--brand-rgb),.4); color: var(--brand); }
  .scale-control input { width: 100%; accent-color: var(--brand); cursor: pointer; }
  .scale-presets { display: grid; grid-template-columns: repeat(4,1fr); gap: 6px; margin-top: 10px; } .scale-presets button { padding: 6px 3px; border: 1px solid var(--line); border-radius: 7px; color: var(--muted); background: var(--panel); cursor: pointer; font-size: 8px; } .scale-presets button.active { border-color: rgba(var(--brand-rgb),.4); color: var(--brand); background: var(--brand-soft); }
  .shortcut-hint { margin: 10px 0 0; color: var(--muted-soft); font-size: 8px; line-height: 1.5; }
  .setting-row { justify-content: flex-end; width: 100%; padding: 10px 0; } .setting-row.disabled { cursor: wait; opacity: .58; } .setting-row-copy { min-width: 0; margin-right: auto; } .setting-row-copy b, .setting-row-copy small { display: block; } .setting-row-copy b { font-size: 9px; } .setting-row-copy small { margin-top: 3px; color: var(--muted); font-size: 8px; }
  .settings-error { margin: 8px 0; color: var(--danger-text); font-size: 8px; line-height: 1.45; overflow-wrap: anywhere; }
  .system-setting-row { display: grid; grid-template-columns: 8px minmax(0,1fr) auto; gap: 9px; align-items: center; width: 100%; padding: 10px 0; border-top: 1px solid var(--line); color: var(--text-soft); background: transparent; text-align: left; } .system-setting-row b, .system-setting-row small { display: block; } .system-setting-row b { font-size: 9px; } .system-setting-row small { margin-top: 3px; color: var(--muted); font-size: 8px; line-height: 1.45; } .system-setting-row i { color: var(--brand); font-size: 8px; font-style: normal; }
  .system-status-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--warning); } .system-status-dot.ready { background: var(--brand); box-shadow: 0 0 7px rgba(var(--brand-rgb),.5); }
  .remote-setting-row { cursor: pointer; } .remote-setting-row:hover b { color: var(--brand); }
  .settings-error-banner { margin-top: 13px; padding: 9px 11px; border: 1px solid rgba(255,124,141,.24); border-radius: 9px; color: var(--danger-text); background: rgba(255,124,141,.08); font-size: 9px; }
  .settings-footer { display: flex; justify-content: space-between; align-items: center; margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--line); }
  .settings-footer-actions { display: flex; gap: 8px; align-items: center; }
  .quit-application { margin-left: 0; padding: 9px 12px; }
  .reset-settings { color: var(--muted); background: transparent; cursor: pointer; font-size: 9px; } .reset-settings:hover { color: var(--brand); }
  .privilege-backdrop { z-index: 50; }
  .remote-backdrop { z-index: 55; }
  .remote-modal { width: min(620px, 94vw); max-height: 92vh; overflow-y: auto; padding: 24px; border: 1px solid rgba(var(--brand-rgb),.28); border-radius: 17px; background: var(--modal-bg); box-shadow: 0 30px 90px var(--shadow); }
  .remote-description { margin: -4px 0 17px; color: var(--text-soft); font-size: 10px; line-height: 1.7; }
  .remote-enable { width: fit-content; margin-bottom: 15px; }
  .remote-fields { display: grid; grid-template-columns: 1fr 150px; gap: 12px; }
  .remote-fields label > span { display: block; margin: 0 0 6px 2px; color: var(--text-soft); font-size: 10px; font-weight: 650; }
  .remote-fields input { width: 100%; padding: 10px 11px; border: 1px solid var(--line); border-radius: 9px; color: var(--text); background: var(--control-bg); font-size: 11px; }
  .remote-fields input:disabled { opacity: .48; }
  .remote-warning { margin-top: 12px; padding: 10px 11px; border: 1px solid rgba(246,200,108,.18); border-radius: 9px; color: var(--warning-text); background: rgba(246,200,108,.06); font-size: 9px; line-height: 1.6; }
  .remote-status { overflow: hidden; margin: 16px 0 0; border: 1px solid var(--line); border-radius: 10px; }
  .remote-status div { display: grid; grid-template-columns: 110px minmax(0,1fr); gap: 12px; padding: 10px 12px; } .remote-status div + div { border-top: 1px solid var(--line); }
  .remote-status dt { color: var(--muted); font-size: 9px; } .remote-status dd { overflow-wrap: anywhere; margin: 0; color: var(--text-soft); font: 9px/1.55 "SFMono-Regular", Consolas, monospace; } .remote-status dd.ready { color: var(--brand); }
  .remote-actions-row { display: flex; gap: 8px; margin-top: 12px; }
  .token-reveal { margin-top: 14px; padding: 13px; border: 1px solid rgba(var(--brand-rgb),.22); border-radius: 10px; background: rgba(var(--brand-rgb),.06); }
  .token-reveal strong { color: var(--brand-strong); font-size: 10px; } .token-reveal p { margin: 5px 0 9px; color: var(--muted); font-size: 9px; }
  .token-reveal code { display: block; overflow-wrap: anywhere; margin-bottom: 10px; color: var(--brand); font-size: 11px; }
  .remote-error { margin-top: 12px; padding: 10px 11px; border: 1px solid rgba(255,124,141,.24); border-radius: 9px; color: var(--danger-text); background: rgba(255,124,141,.08); font-size: 10px; }
  .privilege-modal { width: min(500px, 94vw); padding: 25px; border: 1px solid rgba(112,167,255,.3); border-radius: 17px; background: var(--modal-bg); box-shadow: 0 30px 90px var(--shadow); }
  .privilege-icon { display: grid; width: 42px; height: 42px; place-items: center; margin-bottom: 16px; border-radius: 13px; color: #07111f; background: var(--blue); font-size: 17px; box-shadow: 0 8px 24px rgba(112,167,255,.17); }
  .privilege-heading small { color: var(--blue); font-size: 9px; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
  .privilege-heading h2 { margin: 5px 0 0; font-size: 20px; }
  .privilege-description { margin: 16px 0; color: var(--text-soft); font-size: 11px; line-height: 1.7; }
  .privilege-description b { color: var(--text); }
  .privilege-password span { display: block; margin: 0 0 7px 2px; color: var(--text-soft); font-size: 10px; font-weight: 650; }
  .privilege-password input { width: 100%; padding: 11px 12px; border: 1px solid var(--line); border-radius: 9px; color: var(--text); background: var(--control-bg); font-size: 11px; transition: border-color .15s; }
  .privilege-password input:focus { border-color: rgba(112,167,255,.55); }
  .privilege-password input::placeholder { color: var(--muted-faint); }
  .privilege-note { margin-top: 13px; padding: 11px 12px; border: 1px solid rgba(112,167,255,.16); border-radius: 9px; color: var(--blue-text); background: rgba(112,167,255,.055); font-size: 9px; line-height: 1.65; }
  .privilege-error { margin-top: 12px; padding: 10px 11px; border: 1px solid rgba(255,124,141,.24); border-radius: 9px; color: var(--danger-text); background: rgba(255,124,141,.08); font-size: 10px; line-height: 1.5; }
  .tofu-backdrop { z-index: 40; }
  .tofu-modal { width: min(560px, 94vw); padding: 25px; border: 1px solid rgba(246,200,108,.32); border-radius: 17px; background: var(--modal-bg); box-shadow: 0 30px 90px var(--shadow); }
  .tofu-icon { display: grid; width: 42px; height: 42px; place-items: center; margin-bottom: 16px; border-radius: 13px; color: #171006; background: var(--warning); font-size: 20px; font-weight: 900; box-shadow: 0 8px 24px rgba(246,200,108,.16); }
  .tofu-heading small { color: var(--warning); font-size: 9px; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
  .tofu-heading h2 { margin: 5px 0 0; font-size: 20px; }
  .tofu-description { margin: 16px 0; color: var(--text-soft); font-size: 11px; line-height: 1.7; }
  .tofu-description b { color: var(--text); }
  .tofu-server { margin: 0; overflow: hidden; border: 1px solid var(--line); border-radius: 11px; background: var(--control-bg); }
  .tofu-server div { display: grid; grid-template-columns: 105px minmax(0,1fr); gap: 12px; padding: 12px 13px; }
  .tofu-server div + div { border-top: 1px solid var(--line); }
  .tofu-server dt { color: var(--muted); font-size: 9px; }
  .tofu-server dd { overflow-wrap: anywhere; margin: 0; color: var(--text-soft); font: 10px/1.6 "SFMono-Regular", Consolas, monospace; }
  .tofu-warning { margin-top: 14px; padding: 11px 12px; border: 1px solid rgba(246,200,108,.17); border-radius: 9px; color: var(--warning-text); background: rgba(246,200,108,.06); font-size: 9px; line-height: 1.65; }
  .tofu-reason { margin: 10px 2px 0; color: var(--muted-soft); font-size: 9px; line-height: 1.5; }
  .tofu-error { margin-top: 12px; padding: 10px 11px; border: 1px solid rgba(255,124,141,.24); border-radius: 9px; color: var(--danger-text); background: rgba(255,124,141,.08); font-size: 10px; line-height: 1.5; }
  @media (max-width: 1000px) { .app-shell { grid-template-columns: 238px minmax(0,1fr); } .content { padding: 26px 24px; } .overview-grid { grid-template-columns: 1fr; } .toggle-grid { grid-template-columns: repeat(2, 1fr); } .settings-content { grid-template-columns: 1fr; } .appearance-section { grid-row: auto; } }
</style>
