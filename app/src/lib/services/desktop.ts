import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { EventSubscriptions, type Subscribe } from "./manager-state";
import type { ProfileView, InstanceView, LogEvent, EngineInfo, PrivilegeStatus, RemoteAccessStatus, RecoveryNotice } from "../types";

export { invoke, isTauri };

export async function loadManagerSnapshot() {
  const [profiles, instances, logs, engine, privilege, remote, recovery] = await Promise.all([
    invoke<ProfileView[]>("list_profiles"),
    invoke<InstanceView[]>("list_instances"),
    invoke<LogEvent[]>("list_logs", { instanceId: null, limit: 400 }),
    invoke<EngineInfo>("engine_info"),
    invoke<PrivilegeStatus>("privilege_status"),
    invoke<RemoteAccessStatus>("remote_access_status"),
    invoke<RecoveryNotice[]>("list_recovery_records"),
  ]);
  return { profiles, instances, logs, engine, privilege, remote, recovery };
}

export function managerEvents(onError: (error: unknown) => void) {
  const subscribe: Subscribe = isTauri() ? (name, handler) => listen(name, handler) : async () => () => {};
  return new EventSubscriptions(subscribe, onError);
}
