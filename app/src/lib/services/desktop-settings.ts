import { errorText } from "./manager-state";
import type { Invoke } from "./profile-controller";
import type { DesktopPreferences } from "../types";

export type SettingState<T> = { value: T; loading: boolean; busy: boolean; error: string };
export interface AutostartPort {
  isEnabled(): Promise<boolean>;
  enable(): Promise<void>;
  disable(): Promise<void>;
}

/** A remounted page reads only after a previously submitted native write settles. */
export class SettingsOperationQueue {
  private tail: Promise<unknown> = Promise.resolve();
  run<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.tail.then(operation);
    this.tail = result.catch(() => {});
    return result;
  }
}
const autostartOperations = new SettingsOperationQueue();
const desktopOperations = new SettingsOperationQueue();

/** Reads belong to a generation; a write invalidates all reads started before it. */
class SettingController<T> {
  private generation = 0;
  private disposed = false;
  private initialized = false;
  private state: SettingState<T>;
  constructor(initial: T, private read: () => Promise<T>, private write: (value: T) => Promise<T>,
    private readFailure: string, private writeFailure: (value: T) => string,
    private publish: (state: SettingState<T>) => void, private operations: SettingsOperationQueue) {
    this.state = { value: initial, loading: true, busy: false, error: "" };
  }
  private current(generation: number): boolean { return !this.disposed && generation === this.generation; }
  private emit(): void { if (!this.disposed) this.publish({ ...this.state }); }
  async refresh(): Promise<void> {
    if (this.disposed || this.state.busy) return;
    const generation = ++this.generation;
    this.state.loading = true;
    this.state.error = "";
    this.emit();
    try {
      const value = await this.operations.run(() => this.current(generation) ? this.read() : Promise.resolve(this.state.value));
      if (this.current(generation)) this.state.value = value;
    } catch (error) {
      if (this.current(generation)) this.state.error = `${this.readFailure}${errorText(error)}`;
    } finally {
      if (this.current(generation)) { this.initialized = true; this.state.loading = false; this.emit(); }
    }
  }
  async update(value: T): Promise<void> {
    if (this.disposed || !this.initialized || this.state.busy) return;
    const generation = ++this.generation;
    const previous = this.state.value;
    this.state = { value, loading: false, busy: true, error: "" };
    this.emit();
    try {
      const result = await this.operations.run(() => this.current(generation) ? this.write(value) : Promise.resolve(previous));
      if (this.current(generation)) this.state.value = result;
    } catch (error) {
      if (this.current(generation)) {
        this.state.value = previous;
        this.state.error = `${this.writeFailure(value)}${errorText(error)}`;
      }
    } finally {
      if (this.current(generation)) { this.state.busy = false; this.emit(); }
    }
  }
  value(): T { return this.state.value; }
  dispose(): void { this.disposed = true; ++this.generation; }
}

export class AutostartController extends SettingController<boolean> {
  constructor(port: AutostartPort, publish: (state: SettingState<boolean>) => void, operations = autostartOperations) {
    super(false, () => port.isEnabled(), async value => {
      if (value) await port.enable(); else await port.disable();
      const observed = await port.isEnabled();
      if (observed !== value) throw new Error("系统未能更新登录启动设置");
      return observed;
    }, "无法读取登录启动状态：", value => `无法${value ? "启用" : "关闭"}登录时启动：`, publish, operations);
  }
}

export class DesktopPreferencesController extends SettingController<DesktopPreferences> {
  constructor(invoke: Invoke, publish: (state: SettingState<DesktopPreferences>) => void, operations = desktopOperations) {
    super({ closeToTray: true, startMinimized: true }, () => invoke("get_desktop_preferences"),
      value => invoke("update_desktop_preferences", { preferences: { ...value } }),
      "无法读取后台运行设置：", () => "无法保存后台运行设置：", publish, operations);
  }
  set(key: keyof DesktopPreferences, value: boolean): Promise<void> {
    return this.update({ ...this.value(), [key]: value });
  }
}
