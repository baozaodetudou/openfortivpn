/** Keep keyboard focus in the visible modal and restore its opener on close. */
export function modalFocus(node: HTMLElement, initial: { onClose: () => void; locked?: boolean }) {
  let options = initial;
  const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const items = () => Array.from(node.querySelectorAll<HTMLElement>('button, input, select, textarea, a[href], [tabindex]'))
    .filter((item) => !item.matches(':disabled, [tabindex="-1"]') && item.getClientRects().length > 0);
  const originalTabindex = node.getAttribute('tabindex');
  node.tabIndex = -1;
  const focus = () => (items()[0] ?? node).focus();
  const timer = window.setTimeout(focus, 0);
  const keyboard = (event: KeyboardEvent) => {
    if (event.key === 'Escape') { event.stopPropagation(); event.preventDefault(); if (!options.locked) options.onClose(); }
    if (event.key !== 'Tab') return;
    const controls = items();
    const first = controls[0];
    const last = controls.at(-1);
    if (!first) { event.preventDefault(); node.focus(); }
    else if (event.shiftKey && (document.activeElement === first || document.activeElement === node)) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  };
  const enforce = (event: FocusEvent) => {
    const top = Array.from(document.querySelectorAll<HTMLElement>('[aria-modal="true"]')).at(-1);
    if (top === node && event.target instanceof Node && !node.contains(event.target)) focus();
  };
  node.addEventListener('keydown', keyboard);
  document.addEventListener('focusin', enforce);
  return {
    update(next: typeof initial) { options = next; },
    destroy() {
      window.clearTimeout(timer);
      node.removeEventListener('keydown', keyboard);
      document.removeEventListener('focusin', enforce);
      if (originalTabindex === null) node.removeAttribute('tabindex'); else node.setAttribute('tabindex', originalTabindex);
      if (opener?.isConnected) opener.focus();
    }
  };
}
