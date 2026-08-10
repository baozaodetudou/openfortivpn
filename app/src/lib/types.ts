export type VpnProfile = {
  id: string;
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
  instanceId: string;
  stream: "stdout" | "stderr";
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
