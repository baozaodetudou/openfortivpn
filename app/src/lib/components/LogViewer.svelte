<script lang="ts">
  import type { LogEvent } from "$lib/types";
  let { logs, formatTime }: { logs: LogEvent[]; formatTime: (timestamp: number) => string } = $props();
</script>

<div class="terminal" role="log" aria-label="VPN 诊断日志" aria-live="polite">
  {#if logs.length === 0}
    <div class="terminal-empty">连接后将在这里显示 openfortivpn 输出</div>
  {:else}
    {#each logs as entry (`${entry.instanceId}:${entry.id}`)}
      <div class:error-line={entry.stream === "stderr"} class="log-line">
        <time>{formatTime(entry.timestamp)}</time><span>{entry.line}</span>
      </div>
    {/each}
  {/if}
</div>

<style>
  .terminal { height: 178px; overflow: auto; padding: 12px 16px 16px; border-top: 1px solid var(--line); color-scheme: dark; background: var(--terminal-bg); font: 10px/1.65 "SFMono-Regular", Consolas, monospace; }
  .terminal-empty { display: grid; height: 100%; place-items: center; color: #697a8f; }
  .log-line { display: grid; grid-template-columns: 66px minmax(0,1fr); gap: 10px; color: #a9b8cb; }
  .log-line time { color: #66768d; }
  .log-line span { overflow-wrap: anywhere; }
  .log-line.error-line span { color: #e4b2b9; }
</style>
