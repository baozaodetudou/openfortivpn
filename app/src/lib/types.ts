export type VpnProfile = {
  id: string;
  revision?: number;
  name: string;
  host: string;
  port: number;
  username: string;
  realm: string;
  trustedCert: string;
  setRoutes: boolean;
  setDns: boolean;
  pppdUsePeerdns: boolean;
  halfInternetRoutes: boolean;
  useSudo: boolean;
  autoConnect: boolean;
  autoReconnect: boolean;
};

export type ProfileView = {
  profile: VpnProfile;
  hasSecret: boolean;
  passwordStored: boolean;
};

export type RecoveryNotice = { instanceId: string; profileId: string; message: string };
export type AuthenticationChallenge = {
  profileId: string;
  attemptId: string;
  requestId: string;
  prompt: string;
  expiresAtMs: number;
  maxResponseBytes: number;
};

export type InstanceStatus =
  | "starting"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "disconnected"
  | "failed";

export type InstanceView = {
  id: string;
  profileGeneration: number;
  attemptSequence?: number;
  revision: number;
  profileId: string;
  profileName: string;
  adapterName: string;
  status: InstanceStatus;
  message: string;
  pid: number;
  startedAt: number;
  endedAt: number | null;
  exitCode: number | null;
};

export type EngineInfo = {
  platform: string;
  path: string;
  available: boolean;
  version: string;
  requiresElevation: boolean;
};

export type LogEvent = {
  id: number;
  instanceId: string;
  stream: "stdout" | "stderr" | "manager";
  line: string;
  timestamp: number;
};

export type VpnEnginePayload = {
  event: string;
  digest?: string;
  reason?: string;
  [key: string]: unknown;
};

export type VpnEngineEvent = {
  instanceId: string;
  profileId: string;
  profileRevision: number;
  host: string;
  port: number;
  payload: VpnEnginePayload;
};

export type AutoConnectError = {
  profileId: string;
  profileName: string;
  message: string;
};

export type PrivilegeStatus = {
  required: boolean;
  ready: boolean;
  platform: string;
};

export type RemoteAccessStatus = {
  enabled: boolean;
  running: boolean;
  bindAddress: string;
  port: number;
  url: string;
  certificateFingerprint: string;
  tokenConfigured: boolean;
};

export type RemoteAccessUpdate = {
  status: RemoteAccessStatus;
  token: string | null;
};

export type RemoteAccessError = {
  message: string;
};

export type AppExitBlocked = {
  message: string;
};

export type DesktopPreferences = {
  closeToTray: boolean;
  startMinimized: boolean;
};

export type TrayActionError = {
  profileId: string | null;
  message: string;
};

export type CertificateNotice = {
    key: string;
    instanceId: string;
    profileId: string;
    profileName: string;
    profileRevision: number;
    host: string;
    port: number;
    digest: string;
    reason: string;
  };
