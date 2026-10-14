import type { CertificateNotice, InstanceStatus, InstanceView, ProfileView, VpnEngineEvent, VpnProfile } from "../types";

export type Invoke = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

export function connectionActive(status: InstanceStatus): boolean {
  return ["starting", "connecting", "connected", "disconnecting"].includes(status);
}

/** Independent refreshes share one sequence and reject replies after disposal. */
export class LatestRequest {
  private sequence = 0;
  constructor(private alive: () => boolean) {}
  begin(): number { return ++this.sequence; }
  current(sequence: number): boolean { return this.alive() && sequence === this.sequence; }
}

/** Certificate prompts are bounded and belong to the exact launched target. */
export class CertificatePrompts {
  private seen = new Set<string>();
  private queue: CertificateNotice[] = [];
  constructor(private alive: () => boolean, private limit = 64, private seenLimit = 512) {}
  receive(event: VpnEngineEvent, instance: InstanceView | undefined, view: ProfileView | undefined): CertificateNotice | null {
    if (!this.alive() || !instance || !view || event.payload.event !== "cert_error" ||
        event.instanceId !== instance.id || event.profileId !== instance.profileId ||
        event.profileId !== view.profile.id || event.profileRevision !== (view.profile.revision ?? 0) ||
        event.host !== view.profile.host || event.port !== view.profile.port) return this.current();
    const digest = typeof event.payload.digest === "string" ? event.payload.digest.toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(digest)) return this.current();
    const eventKey = `${instance.id}:${digest}`;
    const key = `${view.profile.id}:${digest}`;
    if (this.seen.has(eventKey) || this.queue.some(prompt => prompt.key === key) || this.queue.length >= this.limit) return this.current();
    this.seen.add(eventKey);
    while (this.seen.size > this.seenLimit) this.seen.delete(this.seen.values().next().value!);
    this.queue.push({ key, instanceId: instance.id, profileId: view.profile.id, profileName: view.profile.name,
      profileRevision: view.profile.revision ?? 0, host: view.profile.host, port: view.profile.port, digest,
      reason: typeof event.payload.reason === "string" ? event.payload.reason : "" });
    return this.current();
  }
  current(): CertificateNotice | null { return this.queue[0] ?? null; }
  close(): CertificateNotice | null { this.queue.shift(); return this.current(); }
  dispose(): void { this.queue = []; this.seen.clear(); }
}

/** Own command payloads and waiting; no passwords are retained in this service. */
export class ProfileController {
  constructor(private invoke: Invoke, private alive: () => boolean) {}
  private checkAlive(): void { if (!this.alive()) throw new Error("页面已关闭，操作已取消"); }
  async save(profile: VpnProfile, password: string | null, rememberPassword: boolean): Promise<ProfileView> {
    this.checkAlive();
    const result = await this.invoke<ProfileView>("save_profile", { input: {
      profile: { ...profile, port: Number(profile.port) }, password, rememberPassword, expectedRevision: profile.revision ?? 0,
    } });
    this.checkAlive();
    return result;
  }
  async delete(view: ProfileView): Promise<void> {
    this.checkAlive();
    await this.invoke("delete_profile", { profileId: view.profile.id, expectedRevision: view.profile.revision ?? 0, stopFirst: true });
    this.checkAlive();
  }
  async waitUntilStopped(profileId: string, instanceId: string, update: (snapshot: InstanceView[]) => void): Promise<InstanceView> {
    this.checkAlive();
    // Only the backend owns wait/reap and cleanup proof. A failed UI status
    // can precede process exit and cannot authorize a certificate write.
    const instance = await this.invoke<InstanceView>("await_profile_stopped", { profileId, instanceId });
    this.checkAlive();
    update([instance]);
    return instance;
  }
  async trust(prompt: CertificateNotice, current: () => ProfileView | undefined, update: (snapshot: InstanceView[]) => void): Promise<ProfileView> {
    const instance = await this.waitUntilStopped(prompt.profileId, prompt.instanceId, update);
    const view = current();
    if (!view || !instance || instance.id !== prompt.instanceId ||
        (view.profile.revision ?? 0) !== prompt.profileRevision ||
        view.profile.host !== prompt.host || view.profile.port !== prompt.port) {
      throw new Error("证书提示对应的连接或配置已改变，请重新连接后确认");
    }
    return this.save({ ...view.profile, trustedCert: prompt.digest }, null, view.passwordStored);
  }
}
