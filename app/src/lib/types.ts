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
};

export type ProfileView = {
  profile: VpnProfile;
  hasSecret: boolean;
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
