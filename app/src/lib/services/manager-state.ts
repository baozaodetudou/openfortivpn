import type { InstanceView, LogEvent, ProfileView } from "../types";

export function compareInstances(left: InstanceView, right: InstanceView): number {
  return right.profileGeneration - left.profileGeneration ||
    (right.attemptSequence ?? 0) - (left.attemptSequence ?? 0) ||
    right.startedAt - left.startedAt || right.id.localeCompare(left.id);
}

export function mergeInstance(current: InstanceView[], incoming: InstanceView): InstanceView[] {
  const previous = current.find(view => view.profileId === incoming.profileId);
  if (previous) {
    if (incoming.profileGeneration < previous.profileGeneration) return current;
    if (incoming.profileGeneration === previous.profileGeneration) {
      const nextAttempt = incoming.attemptSequence ?? 0;
      const lastAttempt = previous.attemptSequence ?? 0;
      if (nextAttempt < lastAttempt ||
          (nextAttempt === lastAttempt && (incoming.id !== previous.id || incoming.revision <= previous.revision))) return current;
    }
  }
  return [...current.filter(view => view.profileId !== incoming.profileId), incoming].sort(compareInstances);
}

export function mergeProfile(current: ProfileView[], incoming: ProfileView): ProfileView[] {
  const previous = current.find(view => view.profile.id === incoming.profile.id);
  if (previous && (incoming.profile.revision ?? 0) < (previous.profile.revision ?? 0)) return current;
  return [...current.filter(view => view.profile.id !== incoming.profile.id), incoming]
    .sort((left, right) => left.profile.name.localeCompare(right.profile.name, "zh-CN"));
}

export function mergeLogEvents(current: LogEvent[], incoming: LogEvent[], limit = 400): LogEvent[] {
  const records = new Map<string, LogEvent>();
  for (const entry of [...current, ...incoming]) records.set(`${entry.instanceId}:${entry.id}`, entry);
  return [...records.values()].sort((left, right) => left.timestamp - right.timestamp || left.id - right.id).slice(-limit);
}

export function errorText(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (error && typeof error === "object") {
    const value = error as { message?: unknown; error?: { message?: unknown } };
    if (typeof value.message === "string") return value.message;
    if (typeof value.error?.message === "string") return value.error.message;
  }
  return "操作失败，请重试并检查恢复状态。";
}

export type Dispose = () => void;
export type Subscribe = <T>(name: string, handler: (event: { payload: T }) => void) => Promise<Dispose>;

type StateField = "profiles" | "privilege" | "remote" | "recovery";
export type SnapshotTicket = {
  sequence: number;
  revisions: ReadonlyMap<StateField, number>;
};

/** Events remain authoritative over requests started before those events. */
export class SnapshotAuthority {
  private sequence = 0;
  private disposed = false;
  private revisions = new Map<StateField, number>();
  begin(): SnapshotTicket {
    return { sequence: ++this.sequence, revisions: new Map(this.revisions) };
  }
  changed(field: StateField): void {
    this.revisions.set(field, (this.revisions.get(field) ?? 0) + 1);
  }
  current(ticket: SnapshotTicket): boolean {
    return this.alive() && ticket.sequence === this.sequence;
  }
  alive(): boolean { return !this.disposed; }
  accepts(ticket: SnapshotTicket, field: StateField): boolean {
    return this.current(ticket) &&
      (ticket.revisions.get(field) ?? 0) === (this.revisions.get(field) ?? 0);
  }
  dispose(): void { this.disposed = true; }
}

/** Late registrations are disposed immediately; disposed pages never receive events. */
export class EventSubscriptions {
  private disposed = false;
  private disposers: Dispose[] = [];
  constructor(private subscribe: Subscribe, private onError: (error: unknown) => void) {}
  add<T>(name: string, handler: (payload: T) => void): void {
    if (this.disposed) return;
    void this.subscribe<T>(name, event => { if (!this.disposed) handler(event.payload); })
      .then(dispose => { if (this.disposed) dispose(); else this.disposers.push(dispose); })
      .catch(error => { if (!this.disposed) this.onError(error); });
  }
  dispose(): void {
    this.disposed = true;
    for (const dispose of this.disposers.splice(0)) {
      try { dispose(); } catch { /* Continue removing all subscriptions during teardown. */ }
    }
  }
}
