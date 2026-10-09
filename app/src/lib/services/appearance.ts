import { errorText } from "./manager-state";

export type ThemePreference = "system" | "dark" | "light";
export type AccentPreference = "mint" | "blue" | "violet" | "amber";
export type AppearancePreferences = { theme: ThemePreference; accent: AccentPreference; scale: number };
export type AppearanceState = { preferences: AppearancePreferences; error: string };
export const APPEARANCE_STORAGE_KEY = "openfortivpn-manager.appearance.v1";
export const MIN_UI_SCALE = 80;
export const MAX_UI_SCALE = 150;
export const UI_SCALE_STEP = 5;

export interface AppearancePort {
  read(): string | null;
  write(value: string): void;
  render(preferences: AppearancePreferences): void;
  native?: {
    setZoom(scale: number): Promise<void>;
    setTheme(theme: "dark" | "light" | null): Promise<void>;
  };
}

/** Keep in-flight native ownership across page teardown and remount. */
export class NativeAppearanceQueue {
  private tail: Promise<void> = Promise.resolve();
  bind(native: NonNullable<AppearancePort["native"]>, alive: () => boolean): NonNullable<AppearancePort["native"]> {
    const run = (operation: () => Promise<void>): Promise<void> => {
      const result = this.tail.then(() => { if (alive()) return operation(); });
      this.tail = result.catch(() => {});
      return result;
    };
    return { setZoom: scale => run(() => native.setZoom(scale)), setTheme: theme => run(() => native.setTheme(theme)) };
  }
}
export const desktopAppearanceQueue = new NativeAppearanceQueue();

const defaults = (): AppearancePreferences => ({ theme: "system", accent: "mint", scale: 100 });
export function clampUiScale(value: number): number {
  if (!Number.isFinite(value)) return 100;
  return Math.min(MAX_UI_SCALE, Math.max(MIN_UI_SCALE, Math.round(value / UI_SCALE_STEP) * UI_SCALE_STEP));
}
function parsePreferences(raw: string | null): AppearancePreferences {
  if (!raw) return defaults();
  const value: unknown = JSON.parse(raw);
  if (!value || typeof value !== "object") return defaults();
  const stored = value as Partial<AppearancePreferences>;
  return {
    theme: ["system", "dark", "light"].includes(stored.theme ?? "") ? stored.theme! : "system",
    accent: ["mint", "blue", "violet", "amber"].includes(stored.accent ?? "") ? stored.accent! : "mint",
    scale: clampUiScale(typeof stored.scale === "number" ? stored.scale : 100),
  };
}

/** Native writes stay ordered; quick changes replace queued work with the newest intent. */
export class AppearanceController {
  private state: AppearanceState = { preferences: defaults(), error: "" };
  private revision = 0;
  private disposed = false;
  private pending: { revision: number; preferences: AppearancePreferences } | null = null;
  private running: Promise<void> | null = null;
  constructor(private port: AppearancePort, private publish: (state: AppearanceState) => void) {}
  private emit(): void {
    if (!this.disposed) this.publish({ ...this.state, preferences: { ...this.state.preferences } });
  }
  initialize(): void {
    if (this.disposed) return;
    try { this.state.preferences = parsePreferences(this.port.read()); }
    catch { this.state.preferences = defaults(); }
    this.apply(false);
  }
  update(patch: Partial<AppearancePreferences>): void {
    if (this.disposed) return;
    this.state.preferences = { ...this.state.preferences, ...patch,
      scale: clampUiScale(patch.scale ?? this.state.preferences.scale) };
    this.apply(true);
  }
  step(direction: -1 | 1): void { this.update({ scale: this.state.preferences.scale + direction * UI_SCALE_STEP }); }
  reset(): void { this.update(defaults()); }
  clearError(): void { if (!this.disposed) { this.state.error = ""; this.emit(); } }
  systemThemeChanged(): void {
    if (!this.disposed && this.state.preferences.theme === "system") this.port.render({ ...this.state.preferences });
  }
  private apply(persist: boolean): void {
    const revision = ++this.revision;
    const preferences = { ...this.state.preferences };
    this.state.error = "";
    this.port.render(preferences);
    if (persist) {
      try { this.port.write(JSON.stringify(preferences)); }
      catch (error) { this.state.error = `无法保存外观设置：${errorText(error)}`; }
    }
    this.emit();
    if (!this.port.native) return;
    this.pending = { revision, preferences };
    if (!this.running) {
      this.running = Promise.resolve().then(async () => {
        do { await this.drain(); } while (!this.disposed && this.pending);
        this.running = null;
      });
    }
  }
  private async drain(): Promise<void> {
    while (!this.disposed && this.pending) {
      const next = this.pending;
      this.pending = null;
      let errorMessage = "";
      try { await this.port.native!.setZoom(next.preferences.scale / 100); }
      catch (error) { errorMessage = `无法应用界面缩放：${errorText(error)}`; }
      // The previous zoom must settle before the newer zoom is submitted.
      if (this.disposed || next.revision !== this.revision) continue;
      try { await this.port.native!.setTheme(next.preferences.theme === "system" ? null : next.preferences.theme); }
      catch (error) { errorMessage ||= `无法同步系统窗口主题：${errorText(error)}`; }
      if (!this.disposed && next.revision === this.revision && errorMessage) {
        this.state.error ||= errorMessage;
        this.emit();
      }
    }
  }
  whenIdle(): Promise<void> { return this.running ?? Promise.resolve(); }
  dispose(): void { this.disposed = true; this.pending = null; }
}
