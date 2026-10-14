<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '$lib/services/desktop';
  import { errorText } from '$lib/services/manager-state';
  let { onRestored }: { onRestored: () => Promise<void> } = $props();
  let path = $state('');
  let busy = $state(false);
  let message = $state('');
  let failed = $state(false);
  let recoveryRequired = $state(false);
  async function refreshRepository() {
    try { recoveryRequired = await invoke<boolean>('repository_recovery_required'); }
    catch { /* The next explicit operation reports an unavailable IPC channel. */ }
  }
  onMount(() => { void refreshRepository(); });
  async function recoverRepository() {
    if (busy) return;
    busy = true; message = ''; failed = false;
    try {
      await invoke('recover_profile_repository');
      await onRestored();
      recoveryRequired = false;
      message = '已重新读取磁盘配置并完成凭据恢复，请重新连接。';
    } catch (error) { failed = true; message = errorText(error); }
    finally { busy = false; await refreshRepository(); }
  }
  async function run(action: 'backup_profiles' | 'restore_profiles') {
    if (busy) return;
    busy = true; message = ''; failed = false;
    try {
      await invoke(action, action === 'backup_profiles' ? { output: path } : { input: path });
      if (action === 'restore_profiles') await onRestored();
      message = action === 'backup_profiles' ? '私有备份已保存。' : '配置已还原，原配置备份保留在应用数据目录。';
    } catch (error) { failed = true; message = errorText(error); }
    finally { busy = false; await refreshRepository(); }
  }
</script>
<section class="backup-panel" aria-labelledby="backup-heading">
  <h3 id="backup-heading">配置备份与还原</h3>
  <p>备份包含已保存的 VPN 密码，文件仅当前用户可读。会话密码不导出。还原会替换当前配置，需要先停止所有连接并完成恢复。</p>
  {#if recoveryRequired}
    <p role="alert">配置写入未确认，配置操作与新连接已暂停。请停止所有连接后重新读取配置。</p>
  {/if}
  <button disabled={busy} onclick={recoverRepository}>重新读取并恢复配置仓库</button>
  <label>备份文件完整路径<input bind:value={path} disabled={busy} placeholder="完整路径，例如 /Users/me/Documents/vpn-backup.json" /></label>
  <div class="actions">
    <button disabled={busy || recoveryRequired || !path.trim()} onclick={() => run('backup_profiles')}>导出私有备份</button>
    <button disabled={busy || recoveryRequired || !path.trim()} onclick={() => run('restore_profiles')}>还原并替换配置</button>
  </div>
  {#if message}<p class:failed role={failed ? 'alert' : 'status'}>{message}</p>{/if}
</section>
<style>
  .backup-panel { padding: 16px; margin-top: 16px; border: 1px solid var(--line); border-radius: 12px; }
  h3 { margin: 0 0 8px; font-size: 13px; color: var(--text); }
  p { font-size: 10px; line-height: 1.6; color: var(--muted); }
  label { display: grid; gap: 7px; font-size: 10px; color: var(--text-soft); }
  input { padding: 10px; color: var(--text); background: var(--control-bg); border: 1px solid var(--line); border-radius: 8px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  button { padding: 8px 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--panel-soft); color: var(--text-soft); cursor: pointer; }
  button:disabled { opacity: .5; cursor: default; }
  .failed { color: var(--danger, #e78888); }
</style>
