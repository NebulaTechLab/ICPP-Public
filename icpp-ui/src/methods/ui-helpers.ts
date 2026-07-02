// ===================================================
// UI helpers
// Privacy ICP (ICPP)
//
// Version -> 1.1.02
// Date    -> 25 November 2025
// Status  -> Public release ver:1 subver:1 release:02
//
// Code developed by @Troesma
// ===================================================

export function $(selector: string): HTMLElement {
  const el = document.querySelector(selector);
  if (!el) throw new Error(`Element not found: ${selector}`);
  return el as HTMLElement;
}

export function clear(el: HTMLElement) {
  el.innerHTML = "";
}

export function setStatus(el: HTMLElement, msg: string, isError = false) {
  el.classList.toggle("status-error", isError);
  el.textContent = msg;
}
