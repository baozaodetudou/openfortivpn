import { errorText } from "./manager-state";
import type { Invoke } from "./profile-controller";
import type { RemoteAccessStatus, RemoteAccessUpdate } from "../types";

export type RemoteInput = { enabled: boolean; bindAddress: string; port: number };
export type RemoteSettingsState = {
  status: RemoteAccessStatus | null;
  open: boolean;
  busy: boolean;
  error: string;
  token: string;
};
export interface RemoteSettingsPort {
  invoke: Invoke;
  copy(value: string): Promise<void>;
  loadOpener(): Promise<(url: string) => Promise<void>>;
}

/** Status is authoritative independently of the modal; secrets belong to one modal session. */
export class RemoteSettingsController {
  private state: RemoteSettingsState = { status: null, open: false, busy: false, error: "", token: "" };
  private revision = 0;
  private session = 0;
  private operation = 0;
  private disposed = false;
  constructor(private port: RemoteSettingsPort, private publish: (state: RemoteSettingsState) => void) {}
  private emit(): void {
    if (!this.disposed) this.publish({ ...this.state, status: this.state.status ? { ...this.state.status } : null });
  }
  snapshotTicket(): number { return this.revision; }
  receiveSnapshot(ticket: number, status: RemoteAccessStatus): void {
    if (!this.disposed && !this.state.busy && ticket === this.revision) {
      this.state.status = { ...status };
      this.emit();
    }
  }
  receiveStatus(status: RemoteAccessStatus): void {
    if (this.disposed) return;
    ++this.revision;
    this.state.status = { ...status };
    this.emit();
  }
  serviceFailed(): void {
    if (this.disposed) return;
    ++this.revision;
    if (this.state.status) this.state.status = { ...this.state.status, running: false };
    this.emit();
  }
  open(): RemoteInput | null {
    if (this.disposed) return null;
    ++this.session;
    this.state.open = true;
    this.state.token = "";
    this.state.error = "";
    this.emit();
    return { enabled: this.state.status?.enabled ?? false,
      bindAddress: this.state.status?.bindAddress ?? "127.0.0.1", port: this.state.status?.port ?? 18443 };
  }
  close(): void {
    if (this.disposed) return;
    ++this.session;
    this.state.open = false;
    this.state.token = "";
    this.state.error = "";
    this.emit();
  }
  private visible(session: number): boolean { return !this.disposed && this.state.open && session === this.session; }
  private async apply(command: string, args?: Record<string, unknown>): Promise<boolean> {
    if (this.disposed || !this.state.open || this.state.busy) return false;
    const session = this.session;
    const operation = ++this.operation;
    const revision = ++this.revision;
    this.state.busy = true;
    this.state.error = "";
    this.state.token = "";
    this.emit();
    try {
      const update = await this.port.invoke<RemoteAccessUpdate>(command, args);
      if (this.disposed || operation !== this.operation) return false;
      // An event received after submission can describe a later backend state.
      if (this.revision === revision) this.state.status = { ...update.status };
      if (!this.visible(session)) return false;
      this.state.token = update.token ?? "";
      if (!update.token && command === "configure_remote_access") this.state.open = false;
      return true;
    } catch (error) {
      if (this.visible(session)) this.state.error = errorText(error);
      return false;
    } finally {
      if (!this.disposed && operation === this.operation) {
        ++this.revision;
        this.state.busy = false;
        this.emit();
      }
    }
  }
  configure(input: RemoteInput): Promise<boolean> {
    return this.apply("configure_remote_access", { input: {
      enabled: input.enabled, bindAddress: input.bindAddress.trim(), port: Number(input.port),
    } });
  }
  rotateToken(): Promise<boolean> { return this.apply("rotate_remote_access_token"); }
  async copyToken(value: string): Promise<boolean> {
    if (this.disposed || !this.state.open || !this.state.token || value !== this.state.token) return false;
    const session = this.session;
    try {
      await this.port.copy(value);
      return this.visible(session) && this.state.token === value;
    } catch (error) {
      if (this.visible(session) && this.state.token === value) { this.state.error = `复制失败：${errorText(error)}`; this.emit(); }
      return false;
    }
  }
  async openUrl(): Promise<void> {
    if (this.disposed || !this.state.open || !this.state.status?.running) return;
    const session = this.session;
    const url = this.state.status.url;
    try {
      const openUrl = await this.port.loadOpener();
      if (this.visible(session) && this.state.status?.running && this.state.status.url === url) await openUrl(url);
    }
    catch (error) {
      if (this.visible(session)) { this.state.error = `无法打开浏览器：${errorText(error)}`; this.emit(); }
    }
  }
  dispose(): void {
    if (this.disposed) return;
    this.close();
    this.disposed = true;
    ++this.revision;
  }
}
