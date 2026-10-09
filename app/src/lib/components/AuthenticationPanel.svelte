<script lang="ts">
  import { onMount } from "svelte";
  import type { AuthenticationChallenge } from "$lib/types";
  let { challenge, onSubmit, onCancel }: {
    challenge: AuthenticationChallenge;
    onSubmit: (challenge: AuthenticationChallenge, response: string) => Promise<void>;
    onCancel: () => Promise<void>;
  } = $props();
  let response = $state("");
  let busy = $state(false);
  let error = $state("");
  let now = $state(Date.now());
  let input: HTMLInputElement;
  let remaining = $derived(Math.max(0, Math.ceil((challenge.expiresAtMs - now) / 1000)));
  let valid = $derived(response.length > 0 && new TextEncoder().encode(response).length <= challenge.maxResponseBytes && !/[\r\n\0]/.test(response));
  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!valid || busy || remaining === 0) return;
    const value = response;
    response = "";
    busy = true;
    error = "";
    try { await onSubmit(challenge, value); }
    catch (failure) { error = failure instanceof Error ? failure.message : String(failure); }
    finally { busy = false; response = ""; }
  }
  async function cancel() {
    response = "";
    busy = true;
    try { await onCancel(); }
    finally { busy = false; }
  }
  onMount(() => {
    input?.focus();
    const timer = setInterval(() => {
      now = Date.now();
      if (now >= challenge.expiresAtMs) response = "";
    }, 500);
    return () => { clearInterval(timer); response = ""; };
  });
</script>

<section class="authentication" aria-label="VPN 验证码">
  <p>{challenge.prompt}</p>
  <form onsubmit={submit}>
    <label for="desktop-auth-response">一次性验证码</label>
    <input id="desktop-auth-response" bind:this={input} bind:value={response} type="password" autocomplete="one-time-code" spellcheck="false" disabled={busy || remaining === 0} maxlength={challenge.maxResponseBytes} aria-describedby="desktop-auth-deadline" />
    <small id="desktop-auth-deadline" role="status">{remaining ? `${remaining} 秒内有效` : "验证码已过期，请重新连接"}</small>
    <div><button type="submit" disabled={!valid || busy || remaining === 0}>{busy ? "正在提交…" : "提交验证码"}</button><button type="button" onclick={cancel} disabled={busy}>取消连接</button></div>
    {#if error}<p role="alert">{error}</p>{/if}
  </form>
</section>

<style>
  .authentication { border-top: 1px solid var(--line); padding-top: 16px; }
  p { font-size: 13px; overflow-wrap: anywhere; }
  form { display: grid; gap: 8px; }
  label, small { font-size: 12px; }
  input { min-width: 0; padding: 10px; border: 1px solid var(--line); border-radius: 6px; }
  form div { display: flex; gap: 8px; }
  button { padding: 8px 12px; border-radius: 6px; }
</style>
