<script lang="ts">
  import { invoke } from "$lib/services/desktop";
  import { errorText } from "$lib/services/manager-state";
  import type { RecoveryNotice } from "$lib/types";
  let { records, onRecovered }: { records: RecoveryNotice[]; onRecovered: () => Promise<void> } = $props();
  let confirmed = $state(false);
  let busy = $state(false);
  let error = $state("");
  async function acknowledge(instanceId: string) {
    if (!confirmed || busy) return;
    busy = true;
    error = "";
    try {
      await invoke("acknowledge_recovery", { instanceId, networkRestored: true });
      confirmed = false;
      await onRecovered();
    } catch (failure) {
      error = failure instanceof Error ? failure.message : String(failure);
    } finally { busy = false; }
  }
</script>

{#if records.length > 0}
  <section class="recovery" aria-label="连接恢复" aria-live="polite">
    <strong>连接需要恢复</strong>
    <p>上次连接的网络清理未确认。请先停止遗留 VPN 进程，检查并恢复路由与 DNS，再确认恢复。确认会解除连接保护。</p>
    <label><input type="checkbox" bind:checked={confirmed} disabled={busy} />我已停止遗留进程并恢复网络</label>
    {#each records as record (record.instanceId)}
      <div class="record"><span>{record.profileId || "未知配置"}：{record.message}</span><button disabled={!confirmed || busy} onclick={() => acknowledge(record.instanceId)}>确认恢复</button></div>
    {/each}
    {#if error}<p role="alert">{error}</p>{/if}
  </section>
{/if}

<style>
  .recovery { border: 1px solid var(--line); border-radius: 12px; padding: 16px; margin: 16px 0; }
  p { line-height: 1.6; font-size: 13px; }
  label { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  .record { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 12px; font-size: 13px; }
  button { padding: 8px 12px; border-radius: 6px; }
</style>
