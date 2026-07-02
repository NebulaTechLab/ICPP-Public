// ===================================================
// Wiring logic for UX frontend code
// Privacy ICP (ICPP)
//
// Version -> 2.0.04
// Date    -> 07 December 2025
// Status  -> Public release ver:2 subver:0 release:04
//
// Code developed by @Troesma
// ===================================================

import "./style.css";
import { 
  initICPPActors, 
  beginUserOperation, 
  endUserOperation, 
  logoutICPP,
  getActorsForQuery,
  getSessionRemainingMs,
  validateSession,
} from "./methods/canisters";
import {
  setupICPP,
  sendShielded,
  listAnnouncements,
  claimDeposit,
  calculateFees,
  withTimeout, 
  sanitizeError,
  clearSentIdsKey,
  getSessionIcpBalanceE8s,
  withdrawIcp,
} from "./methods/flows";
import { loadNk } from "./methods/nk";
import { $, clear, setStatus } from "./methods/ui-helpers";
import { Principal } from "@dfinity/principal";

type Tab = "access" | "send" | "receive" | "withdraw";

let currentTab: Tab = "access";
let isSetupComplete = false;

const DESKTOP_MIN_WIDTH = 1024;

function isMobileOrSmallScreen(): boolean {
  const ua = navigator.userAgent || "";
  const isMobileUA = /Mobi|Android|iPhone|iPad|iPod/i.test(ua);
  return isMobileUA || window.innerWidth < DESKTOP_MIN_WIDTH;
}

function installDesktopOnlyGuard(): void {
  const overlay = document.createElement("div");
  overlay.id = "desktop-only-overlay";
  overlay.innerHTML = `
    <div class="desktop-only-box">
      <div class="desktop-only-title">Desktop required</div>
      <div class="desktop-only-text">
        This application is intended for desktop browsers only.
        Please open it on a desktop or laptop device.
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const update = () => {
    const blocked = isMobileOrSmallScreen();
    document.body.classList.toggle("desktop-blocked", blocked);
  };

  window.addEventListener("resize", update);
  update();
}

// ====================
// Shared ICP utilities
// ====================

function formatIcpE8sFixed(e8s: bigint, decimals: number): string {
  const E8S = 100_000_000n;
  const whole = e8s / E8S;
  const frac8 = (e8s % E8S).toString().padStart(8, "0");
  const frac = frac8.slice(0, Math.min(8, Math.max(0, decimals)));
  return `${whole.toString()}.${frac.padEnd(decimals, "0")}`;
}

function parseIcpToE8s(icpString: string): bigint {
  let val = icpString.replace(/,/g, "").trim();
  if (!val) return 0n;
  if (val === ".") return 0n;

  const parts = val.split(".");
  if (parts.length > 2) throw new Error("Invalid format");

  let whole = parts[0] || "0";
  let fraction = parts[1] || "";

  if (fraction.length > 8) {
    fraction = fraction.slice(0, 8);
  }
  while (fraction.length < 8) {
    fraction += "0";
  }

  return BigInt(whole + fraction);
}

function normalizeIcpAmount(raw: string): { ok: true; value: string } | { ok: false; error: string } {
  let s = raw.trim().replace(/[\s_]/g, "");
  if (!s) return { ok: false, error: "Amount required" };

  const hasDot = s.includes(".");
  const hasComma = s.includes(",");

  if (hasDot && hasComma) {
    const us = /^\d{1,3}(,\d{3})+(\.\d+)?$/;
    const eu = /^\d{1,3}(\.\d{3})+(,\d+)?$/;
    if (us.test(s)) {
      s = s.replace(/,/g, "");
    } else if (eu.test(s)) {
      s = s.replace(/\./g, "");
      s = s.replace(/,/g, ".");
    } else {
      return { ok: false, error: "Invalid amount format" };
    }
  } else if (hasComma) {
    const thousandsOnly = /^\d{1,3}(,\d{3})+$/;
    if (thousandsOnly.test(s)) {
      s = s.replace(/,/g, "");
    } else {
      return { ok: false, error: "Use dot for decimals (e.g. 1.5)" };
    }
  }

  if (!/^\d+(\.\d+)?$/.test(s)) {
    return { ok: false, error: "Invalid format" };
  }

  const frac = s.split(".")[1];
  if (frac && frac.length > 4) {
    return { ok: false, error: "Maximum 4 decimals" };
  }

  const parts = s.split(".");
  const w = parts[0] || "0";
  const f = (parts[1] || "").padEnd(4, "0");
  s = `${w}.${f.slice(0, 4)}`;

  return { ok: true, value: s };
}

let balanceRefreshInterval: number | null = null;

function startBalanceAutoRefresh() {
  if (balanceRefreshInterval !== null) return;
  balanceRefreshInterval = window.setInterval(async () => {
    if (!isSetupComplete || sendInProgress || processingId !== null || withdrawInProgress || currentTab !== "send") return;
    
    try {
      await refreshBalanceCache();
      const balInput = document.getElementById("send-icp-balance") as HTMLInputElement | null;
      if (balInput) balInput.value = sendCachedBalanceText;
    } catch {
      // Retry on 
      // next interval
    }
  }, 30000);
}

function stopBalanceAutoRefresh() {
  if (balanceRefreshInterval !== null) {
    window.clearInterval(balanceRefreshInterval);
    balanceRefreshInterval = null;
  }
}

async function refreshBalanceCache(): Promise<void> {
  const e8s = await getSessionIcpBalanceE8s();
  sendCachedBalanceE8s = e8s;
  sendCachedBalanceText = formatIcpE8sFixed(e8s, 4);
  
  if (currentTab === "withdraw") {
    const balInput = document.getElementById("withdraw-balance") as HTMLInputElement | null;
    if (balInput) balInput.value = sendCachedBalanceText;
  } else if (currentTab === "send") {
    const balInput = document.getElementById("send-icp-balance") as HTMLInputElement | null;
    if (balInput) balInput.value = sendCachedBalanceText;
  }

  // Trigger validation
  // ------------------
  const event = new Event('balance-updated');
  window.dispatchEvent(event);
}

// Receive card persistent state 
// (survives tab switches)
// -----------------------------
const claimedIds = new Set<string>();
let cachedAnnouncements: Awaited<ReturnType<typeof listAnnouncements>> = [];
const failedIds = new Set<string>();
const hardFailedIds = new Set<string>();
let processingId: string | null = null;

// Send card 
// persistent state
// ----------------
let sendInProgress = false;
const SEND_LABEL_DEFAULT = "Review the transfer details and send";
let sendButtonLabel = SEND_LABEL_DEFAULT;

const SEND_MAX_E8S = 2000n * 100_000_000n;
const SEND_LABEL_OVER_LIMIT = "Up to 2,000 ICP can be sent";

const SEND_MIN_E8S = 2n * 100_000_000n;
const SEND_LABEL_BELOW_LIMIT = "Minimum transfer 2 ICP";

// State machine (send) 
// -> 'idle' | 'success' | 'error'
// -------------------------------
let sendState: "idle" | "success" | "error" = "idle"; 

let sendCachedStatus = "";
let sendCachedRecipient = "";
let sendCachedAmount = "";
let sendCachedFeeHtml = "";

// Cached ICRC-1 
// account balance (e8s)
// ---------------------
let sendCachedBalanceE8s: bigint | null = null;
let sendCachedBalanceText = "";

// Resets the Send card to its baseline draft state
// (narrower than resetSessionState() -> only clears
// send-related cached values and presentation state
// -------------------------------------------------
function resetSendCardToDefaultDraft(): void {
  if (sendInProgress) return;

  sendState = "idle";
  sendButtonLabel = SEND_LABEL_DEFAULT;
  sendCachedStatus = "";
  sendCachedRecipient = "";
  sendCachedAmount = "";
  sendCachedFeeHtml = "";
}

// Receive card
// ------------
let recvScanLabel = "Scan for transfers";
let recvScanInProgress = false;

// Withdraw card
// -------------
let withdrawInProgress = false;
const WITHDRAW_LABEL_DEFAULT = "Confirm and withdraw ICP";
let withdrawButtonLabel = WITHDRAW_LABEL_DEFAULT;
let withdrawState: "idle" | "success" | "error" = "idle";
let withdrawCachedDestination = "";
let withdrawCachedAmount = "";

// Block logout while any long-running op is active 
// - sendInProgress -> send() is executing
// - recvScanInProgress -> scan is running
// - processingId -> a claim is running
// - withdrawInProgress -> exfiltrating ICP
// ------------------------------------------------
function canSafelyLogout(): boolean {
  if (!isSetupComplete) return false;
  if (sendInProgress) return false;
  if (recvScanInProgress) return false;
  if (processingId !== null) return false;
  if (withdrawInProgress) return false;
  return true;
}

function updateLogoutEnabled(): void {
  const logoutBtn = document.getElementById("btn-logout") as HTMLButtonElement | null;
  if (logoutBtn) logoutBtn.disabled = !canSafelyLogout();
}

function resetSessionState(): void {
  // Stop balance
  // auto-refresh
  // ------------
  stopBalanceAutoRefresh();

  // Clears in-memory 
  // key material
  // ----------------
  try { clearSentIdsKey(); } catch {}

  // Force a 
  // safe baseline
  // -------------
  currentTab = "access";
  isSetupComplete = false;

  // Send state
  // ----------
  sendState = "idle";
  sendInProgress = false;
  sendButtonLabel = SEND_LABEL_DEFAULT;
  sendCachedStatus = "";
  sendCachedRecipient = "";
  sendCachedAmount = "";

  // Clear balance cache to prevent
  // stale data after re-login
  // ------------------------------
  sendCachedBalanceE8s = null;
  sendCachedBalanceText = "";

  // Receive state
  // -------------
  recvScanInProgress = false;
  recvScanLabel = "Scan for transfers";
  processingId = null;

  // Withdraw state
  // --------------
  withdrawInProgress = false;
  withdrawButtonLabel = WITHDRAW_LABEL_DEFAULT;
  withdrawState = "idle";
  withdrawCachedDestination = "";
  withdrawCachedAmount = "";

  // Clear transient 
  // lists/state
  // ---------------
  cachedAnnouncements = [];
  claimedIds.clear();
  failedIds.clear();
  hardFailedIds.clear();
}

// Centralized session gate
// (forces re-setup if session 
// invalid)
// ---------------------------
function ensureValidSession(): boolean {
  if (!isSetupComplete) return false;
  
  const status = validateSession();
  
  if (!status.valid) {
    resetSessionState();
    render();
    return false;
  }
  
  return true;
}

function switchTab(tab: Tab) {
  // Do not persist if 
  // amount over limit
  // -----------------
  if (currentTab === "send" && tab !== "send") {
    const isOutsideLimitView = sendState === "idle" && (sendButtonLabel === SEND_LABEL_OVER_LIMIT || sendButtonLabel === SEND_LABEL_BELOW_LIMIT);
    if (isOutsideLimitView) {
      resetSendCardToDefaultDraft();
    }
  }
  // Clear receive PIN when 
  // leaving the Receive tab
  // -----------------------
  if (currentTab === "receive" && tab !== "receive") {
    const pin = document.querySelector<HTMLInputElement>("#pin-recv");
    if (pin) pin.value = "";

    // Prevent sticky scan 
    // states across tabs
    // -------------------
    recvScanInProgress = false;
    recvScanLabel = "Scan for transfers";
  }

  if (!isSetupComplete && (tab === "send" || tab === "receive" || tab === "withdraw")) {
    return;
  }

  // Session gate for 
  // authenticated tabs
  // ------------------
  if (isSetupComplete && (tab === "send" || tab === "receive" || tab === "withdraw")) {
    if (!ensureValidSession()) return;
  }

  currentTab = tab;

  document
    .querySelectorAll<HTMLButtonElement>(".app-nav-main button[data-tab]")
    .forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === tab);
      if (
        !isSetupComplete &&
        (btn.dataset.tab === "send" || btn.dataset.tab === "receive" || btn.dataset.tab === "withdraw")
      ) {
        btn.disabled = true;
      } else if (isSetupComplete && btn.dataset.tab === "access") {
        btn.disabled = true;
      } else {
        btn.disabled = false;

        // Freeze send/withdraw 
        // if balance is 0
        // --------------------
        if (sendCachedBalanceE8s === 0n && (btn.dataset.tab === "send" || btn.dataset.tab === "withdraw")) {
          btn.disabled = true;
        }
      }
    });
  render();
}

function renderSetupCard() {
  const left = $("#left-card");
  clear(left);

  left.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">User Access</div>
          <div class="card-subtitle">
            Shield P2P transactions on the Internet Computer</br> 
            using the ICPP privacy tunnel
          </div>
        </div>
        <span class="card-badge">Per device</span>
      </div>
      <div class="field-group">
        <div class="field">
          <div class="field-label" style="color:#00b4d8;"><strong>On first access</strong></div>
          <div class="field-subtitle" style="margin-bottom:20px; margin-top:8px;">
            Choose a PIN of at least 6 digits to register</br> 
            <span style="font-weight:500; color:#f4a261;">It cannot be recovered if forgotten</span></br> 
            Please store it securely
          </div>
          <div class="field-label" style="color:#00b4d8;"><strong>Returning users</strong></div>
          <div class="field-subtitle" style="margin-bottom:10px; margin-top:8px;">
            Enter your PIN in the space provided below
          </div>
          <div class="pin-wrapper">
            <input id="pin-setup" type="password" placeholder="6 or more digits" />
            <button type="button" class="password-toggle" id="pin-toggle-setup" aria-label="Show PIN">
              <svg class="pw-icon" aria-hidden="true"><use href="#ico-eye-closed"></use></svg>
            </button>
          </div>
        </div>
        <button id="btn-setup" class="button-primary" disabled>Access ICPP</button>
        <div id="status-setup" class="status"></div>
      </div>
    </div>
  `;

  const btn = $("#btn-setup") as HTMLButtonElement;
  const pinInput = $("#pin-setup") as HTMLInputElement;
  const status = $("#status-setup");

  const SETUP_LABEL_DEFAULT = "Launch ICPP on this device";
  const SETUP_LABEL_CONNECTING = "Now connecting...";
  const SETUP_LABEL_RETRY_NET = "Try again later – Connection down";
  const SETUP_LABEL_RETRY_PIN = "PIN invalid – Please try again";

  function setSetupButton(label: string, disabled: boolean) {
    btn.textContent = label;
    btn.disabled = disabled;
  }

  // PIN validation
  // Button enabled only 
  // when PIN format valid
  // ---------------------
  pinInput.addEventListener("input", () => {
    const pin = pinInput.value.trim();
    const isValid = /^\d{6,}$/.test(pin);
    
    btn.disabled = !isValid;
    
    // Reset label if it 
    // was showing an error
    // --------------------
    if (isValid && btn.textContent !== SETUP_LABEL_DEFAULT) {
      btn.textContent = SETUP_LABEL_DEFAULT;
    }
  });

  const pinToggle = $("#pin-toggle-setup") as HTMLButtonElement;

  pinToggle.onclick = () => {
    const use = pinToggle.querySelector("use") as SVGUseElement;
    const toVisible = pinInput.type === "password";
    pinInput.type = toVisible ? "text" : "password";
    const ref = toVisible ? "#ico-eye-open" : "#ico-eye-closed";
    use.setAttribute("href", ref);

    // Safari fallback
    // ---------------
    use.setAttribute("xlink:href", ref);
    pinToggle.setAttribute("aria-label", toVisible ? "Hide PIN" : "Show PIN");
  };

  btn.onclick = async () => {
    const pinEl = document.getElementById("pin-setup") as HTMLInputElement | null;
    const pin = (pinEl?.value ?? "").trim();

    // Do not attempt II/agent 
    // calls if offline
    // -----------------------
    if (typeof navigator !== "undefined" && navigator.onLine === false) {
      setSetupButton(SETUP_LABEL_RETRY_NET, false);
      return;
    }

    try {
      setSetupButton(SETUP_LABEL_CONNECTING, true);
      status.textContent = "";

      await withTimeout(
        initICPPActors(),
        30_000,
        "did not complete within"
      );

      const { principal } = await setupICPP(pin);

      // Success
      // -------
      setSetupButton(SETUP_LABEL_DEFAULT, false);
      setStatus(
        status,
        `ICPP enabled.\nPrincipal:\n${principal?.toText() ?? "<unknown>"}`
      );

      isSetupComplete = true;
      startBalanceAutoRefresh();
      switchTab("send");
    } catch (e: any) {
      const msg = sanitizeError(e);

      if (msg === "Invalid PIN") {
        setSetupButton(SETUP_LABEL_RETRY_PIN, false);
        status.textContent = "";
        return;
      }

      if (
        msg.startsWith("Connection error") ||
        msg.startsWith("Network error") ||
        msg.startsWith("Operation timed out") ||
        msg.startsWith("Service temporarily unavailable")
      ) {
        setSetupButton(SETUP_LABEL_RETRY_NET, false);
        status.textContent = "";
        return;
      }

      setSetupButton(msg, false);
      status.textContent = "";
    } finally {
      btn.disabled = false;
    }
  };
}

function renderSendCard() {
  const left = $("#left-card");
  clear(left);

  left.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Send</div>
          <div class="card-subtitle">Transfer ICP using ICPP</div>
        </div>
        <span class="card-badge">Between ICPP accounts – Shielded</span>
      </div>
      <div class="field-group">
        <div class="field">
          <div class="field-label" style="color:#00b4d8; margin-bottom:1px;"><strong>ICPP Originator Account</strong></div>
          <div class="card-subtitle"">
            Linked to your Internet Identity and unique to you</br>
            Keep it in a safe place
          </div>
          <div id="send-origin-principal" class="mono" style="color:#f4a261; font-size:18px; font-weight:600; margin-top:10px;"></div>
        </div>
        <div class="field">
          <div class="field-label" style="margin-top:10px; margin-bottom:1px; color:#00b4d8;"><strong>Balance</strong></div>
          <div class="card-subtitle">ICP tokens available</div>
          <div class="balance-row">
            <input id="send-icp-balance" class="field-input" type="text" readonly />
            <button id="btn-refresh-balance" class="button-balance" type="button" style="margin-left:10px; min-width:120px;">Refresh</button>
          </div>
        </div>
        <hr style="border:0; border-top:1px solid #8da9c4; margin:20px 0;">
        <div class="field">
          <div class="field-label" style="margin-bottom:1px; color:#00b4d8;"><strong>Transfer to ICPP Account</strong></div>
          <div class="card-subtitle">Please verify recipient is an ICPP account (otherwise transfers are unrecoverable)</div>
          <input id="send-recipient" type="text" placeholder="Enter a 53-character PID" disabled style="opacity:0.65;" />
        </div>
        <div class="field">
          <div class="field-label" style="margin-top:10px; margin-bottom:1px; color:#00b4d8;"><strong>Amount</strong></div>
          <div class="card-subtitle">Min <strong>2</strong> ICP | Max <strong>2,000</strong> ICP</div>
          <div class="amount-wrapper">
            <input id="send-amount" type="text" placeholder="0.0000 Tokens" disabled style="opacity:0.65;" />
          </div>
        </div>
        <div
          id="fee-breakdown"
          style="
            margin-top:8px;
            padding:10px;
            border-radius:8px;
            background:rgba(15,23,42,0.6);
            border:1px solid rgba(148,163,184,0.3);
            font-size:14px;
            line-height:1.6;
            color:var(--fg-muted);
            min-height:20px;
          "
        ></div>
        
        <!-- Action Button -->
        <div style="display:flex; gap:10px; margin-top:5px;">
          <button id="btn-send" class="button-primary" style="flex:1;" disabled>${sendButtonLabel || SEND_LABEL_DEFAULT}</button>
        </div>
        <div id="status-send" class="status"></div>
      </div>
    </div>
  `;

  const status = $("#status-send");
  const btn = $("#btn-send") as HTMLButtonElement;
  const recipientInput = $("#send-recipient") as HTMLInputElement;
  const amountInput = $("#send-amount") as HTMLInputElement;
  const feeDisplay = $("#fee-breakdown");

  const originPrincipalEl = left.querySelector<HTMLDivElement>("#send-origin-principal")!;
  const balanceInput = left.querySelector<HTMLInputElement>("#send-icp-balance")!;
  const refreshBalanceBtn = left.querySelector<HTMLButtonElement>("#btn-refresh-balance")!;

  // Show last known balance 
  // immediately to avoid flicker
  // ----------------------------
  if (sendCachedBalanceText) {
    balanceInput.value = sendCachedBalanceText;
  }

  // Restore cached 
  // recipient/amount values
  // -----------------------
  if (sendCachedRecipient) {
    recipientInput.value = sendCachedRecipient;
  }
  if (sendCachedAmount) {
    amountInput.value = sendCachedAmount;
  }

  async function refreshBalanceUI(): Promise<void> {
    if (sendInProgress || processingId !== null || withdrawInProgress) {
      // Restore cached display
      // ----------------------
      if (sendCachedBalanceText) {
        balanceInput.value = sendCachedBalanceText;
      }
      return;
    }
    try {
      refreshBalanceBtn.disabled = true;
      balanceInput.value = "Loading balance";

      // While balance is loading 
      // freeze send in idle
      // ------------------------
      if (!sendInProgress && sendState === "idle") {
        btn.disabled = true;
      }

      const e8s = await getSessionIcpBalanceE8s();
      sendCachedBalanceE8s = e8s;
      sendCachedBalanceText = formatIcpE8sFixed(e8s, 4);
      balanceInput.value = sendCachedBalanceText;

      // Cascading validation 
      // handles button state
      // --------------------
      validateAndUpdateState();
    } catch (e: any) {
      // Preserve cached balance on error
      // (don't wipe out existing state)
      // --------------------------------
      if (sendCachedBalanceText && sendCachedBalanceE8s !== null) {
        // Keep showing 
        // cached balance
        // --------------
        balanceInput.value = sendCachedBalanceText;
      } else {
        balanceInput.value = "Balance unavailable";
      }
      
      // Cascading validation 
      // handles field states
      // --------------------
      validateAndUpdateState();
    } finally {
      const busy = sendInProgress || sendState !== "idle";
      refreshBalanceBtn.disabled = busy;
    }
  }

  refreshBalanceBtn.addEventListener("click", () => {
    void refreshBalanceUI();
  });

  // Populate principal immediately 
  // if session exists and refresh 
  // balance once on render
  // ------------------------------
  try {
    const actors = getActorsForQuery();
    if (actors && actors.principal) {
      // Verify delegation is still valid 
      // before trusting cached actors
      // --------------------------------
      const remaining = getSessionRemainingMs?.() ?? null;
      if (remaining !== null && remaining > 0) {
        originPrincipalEl.textContent = actors.principal.toText();
        void refreshBalanceUI();
      } else {
        originPrincipalEl.textContent = "Session invalid – Please refresh";
        balanceInput.value = "—";
        setFieldEnabled(recipientInput, false);
        setFieldEnabled(amountInput, false);
        btn.disabled = true;
      }
    } else {
      originPrincipalEl.textContent = "—";
      // Use cached balance 
      // if available
      // ------------------
      balanceInput.value = sendCachedBalanceText || "0.0000";
    }
  } catch {
    originPrincipalEl.textContent = "—";
    // Use cached balance 
    // if available
    // ------------------
    balanceInput.value = sendCachedBalanceText || "0.0000";
  }
  const successSendLabel = "Deposit sealed – Press to reset form";
  const retrySendLabel = "Review transfer and try again";

  const processingSendLabel = "Processing – Allow 10 to 15 min";

  function setSendButton(label: string, disabled: boolean) {
    btn.textContent = label;
    btn.disabled = disabled;
    sendButtonLabel = label;
  }

  function resetSendButtonToDefault() {
    setSendButton(SEND_LABEL_DEFAULT, false);
    btn.style.background = "";
    btn.style.color = "";
  }

  // Amount limit enforcement 
  // 2 ICP -> Low band
  // 2000 ICP -> Upper band
  // ------------------------
  let sendAmountOverLimit = false;
  let sendAmountBelowLimit = false;

  // Cached required balance for current draft
  // (amount + fees + 5% buffer on fees)
  // -----------------------------------------
  let sendRequiredE8s: bigint | null = null;

  function enforceSendAmountLimit(): boolean {
    if (sendInProgress) return false;

    // Only enforce limit 
    // when idle (not mid-op)
    // ----------------------
    if (sendState !== "idle") {
      sendAmountOverLimit = false;
      sendAmountBelowLimit = false;
      return false;
    }

    const norm = normalizeIcpAmount(amountInput.value);
    if (norm.ok === false) {
      if (sendAmountOverLimit || sendAmountBelowLimit) {
        sendAmountOverLimit = false;
        sendAmountBelowLimit = false;
        resetSendButtonToDefault();
        btn.style.background = "";
        btn.style.color = "";
      }
      return false;
    }

    let amt: bigint;

    try {
      amt = parseIcpToE8s(norm.value);
    } catch {
      if (sendAmountOverLimit || sendAmountBelowLimit) {
        sendAmountOverLimit = false;
        sendAmountBelowLimit = false;
        resetSendButtonToDefault();
        btn.style.background = "";
        btn.style.color = "";
      }
      return false;
    }

    if (amt > SEND_MAX_E8S) {
      sendAmountOverLimit = true;
      setSendButton(SEND_LABEL_OVER_LIMIT, true);
      btn.style.background = "#d62828";
      btn.style.color = "#ffffff";
      status.textContent = "";
      sendCachedStatus = "";
      return true;
    }

    if (amt < SEND_MIN_E8S) {
      sendAmountBelowLimit = true;
      setSendButton(SEND_LABEL_BELOW_LIMIT, true);
      btn.style.background = "#d62828";
      btn.style.color = "#ffffff";
      status.textContent = "";
      sendCachedStatus = "";
      return true;
    }

    // User fixed it
    //--------------
    if (sendAmountOverLimit || sendAmountBelowLimit) {
      sendAmountOverLimit = false;
      sendAmountBelowLimit = false;
      resetSendButtonToDefault();
      btn.style.background = "";
      btn.style.color = "";
      status.textContent = "";
      sendCachedStatus = "";
    }

    return false;
  }

  // Toggle input 
  // freeze on execution
  // -------------------
  const toggleInputs = (disabled: boolean) => {
    recipientInput.disabled = disabled;
    amountInput.disabled = disabled;
    
    const opacity = disabled ? "0.65" : "1";
    recipientInput.style.opacity = opacity;
    amountInput.style.opacity = opacity;
    feeDisplay.style.opacity = opacity;
  };

  // Field state helpers
  // -------------------
  function setFieldEnabled(el: HTMLInputElement, enabled: boolean): void {
    el.disabled = !enabled;
    el.style.opacity = enabled ? "1" : "0.65";
  }

  // Cascading validation
  // --------------------
  function validateAndUpdateState(): void {
    if (sendInProgress) return;
    if (sendState !== "idle") return;

    // Reset button 
    // to default
    // ------------
    resetSendButtonToDefault();

    // Check balance
    // -------------
    if (sendCachedBalanceE8s === null || sendCachedBalanceE8s === 0n) {
      setFieldEnabled(recipientInput, false);
      setFieldEnabled(amountInput, false);
      amountInput.value = "";
      sendCachedAmount = "";
      btn.disabled = true;
      return;
    }

    // Balance > 0 
    // -> unlock recipient
    // -------------------
    setFieldEnabled(recipientInput, true);

    // Validate recipient
    // ------------------
    const recipientText = recipientInput.value.trim();
    
    if (!recipientText) {
      setFieldEnabled(amountInput, false);
      amountInput.value = "";
      sendCachedAmount = "";
      btn.disabled = true;
      return;
    }

    // Check if 
    // valid Principal
    // ---------------
    try {
      Principal.fromText(recipientText);
    } catch {
      setFieldEnabled(amountInput, false);
      btn.disabled = true;
      return;
    }

    // Recipient valid
    // -> unlock amount
    // ----------------
    setFieldEnabled(amountInput, true);

    // Validate amount
    // ---------------
    const amountText = amountInput.value.trim();
    
    if (!amountText) {
      btn.disabled = true;
      return;
    }

    const norm = normalizeIcpAmount(amountText);
    if (!norm.ok) {
      btn.disabled = true;
      return;
    }

    let amountE8s: bigint;
    try {
      amountE8s = parseIcpToE8s(norm.value);
    } catch {
      btn.disabled = true;
      return;
    }

    if (amountE8s <= 0n) {
      btn.disabled = true;
      return;
    }

    // Check limits before proceeding
    // ------------------------------
    if (amountE8s < SEND_MIN_E8S || amountE8s > SEND_MAX_E8S) {
      enforceSendAmountLimit();
      return;
    }

    // Check sufficient balance (amount + fees)
    // Fee breakdown handles this and sets sendRequiredE8s
    // ---------------------------------------------------
    if (sendRequiredE8s !== null && sendCachedBalanceE8s < sendRequiredE8s) {
      btn.disabled = true;
      return;
    }

    // All valid
    // It's a go
    // ---------
    btn.disabled = false;
  }

  // Reset form 
  // (full clear)
  // ------------
  const resetForm = () => {
    // Clear State
    // -----------
    sendState = "idle";
    sendCachedStatus = "";
    sendCachedRecipient = "";
    sendCachedAmount = "";
    sendButtonLabel = SEND_LABEL_DEFAULT;
    sendAmountOverLimit = false;
    sendAmountBelowLimit = false;
    sendCachedFeeHtml = "";

    // Clear UI inputs
    // ---------------
    recipientInput.value = "";
    amountInput.value = "";
    status.innerHTML = "";
    
    // Reset button style
    // ------------------
    btn.textContent = SEND_LABEL_DEFAULT;
    btn.style.background = "";
    btn.style.color = "";

    // Cascading validation 
    // sets field/button states
    // ------------------------
    validateAndUpdateState();
    updateFees();
  };

  // Enable Review 
  // (keep data, unlock inputs)
  // --------------------------
  const enableReview = () => {
    sendState = "idle";
    sendButtonLabel = SEND_LABEL_DEFAULT;
    
    btn.textContent = SEND_LABEL_DEFAULT;
    btn.style.background = "";
    btn.style.color = "";

    status.innerHTML = "";

    // Cascading validation 
    // sets field/button states
    // ------------------------
    validateAndUpdateState();
  };
  
  // Logic to restore visual 
  // state based on sendState
  // ------------------------
  if (sendState === "success") {
    btn.textContent = successSendLabel;
    btn.style.background = "#9ac13e";
    btn.style.color = "#000000";
    btn.disabled = false;
    toggleInputs(true);

  } else if (sendState === "error") {
    btn.textContent = sendButtonLabel || retrySendLabel;
    btn.style.background = "#d62828";
    btn.style.color = "#ffffff";
    // Allow immediate editing 
    // to recover from error state
    // ---------------------------
    btn.disabled = false;
    toggleInputs(false);

  } else if (sendInProgress) {
    // If we somehow re-render 
    // while async is running
    // -----------------------
    btn.textContent = sendButtonLabel || processingSendLabel;
    btn.disabled = true;
    toggleInputs(true);

  } else {
    // Idle state
    // ----------
    btn.textContent = sendButtonLabel || SEND_LABEL_DEFAULT;
  }

  if (sendState === "success" && sendCachedStatus) {
    status.classList.remove("status-error");
    status.innerHTML = sendCachedStatus;
  } else {
    status.textContent = "";
  }

  // Enforce send cap
  // ----------------
  enforceSendAmountLimit();

  // Input event 
  // listeners
  // -----------
  recipientInput.addEventListener("input", () => {
    sendCachedRecipient = recipientInput.value;
    if (sendState !== "idle") {
      enableReview();
      enforceSendAmountLimit();
      return;
    }

    // If amount is over limit
    // keep the Send button frozen
    // ---------------------------
    if (sendAmountOverLimit || sendAmountBelowLimit) return;

    if (sendButtonLabel !== SEND_LABEL_DEFAULT) {
      resetSendButtonToDefault();
      btn.style.background = "";
      btn.style.color = "";
    }
    
    // Cascading validation
    // (unlock amount when recipient valid)
    // ------------------------------------
    validateAndUpdateState();
    
    // Reset fees display when 
    // amount gets cleared
    // -----------------------
    updateFees();
  });

  // Amount validation
  // -> input handling
  // -----------------
  amountInput.addEventListener("input", () => {
    sendCachedAmount = amountInput.value;
    
    if (sendState !== "idle") {
      enableReview();
      return;
    }

    // Only update 
    // fees preview
    // ------------
    updateFees();
  });

  // Amount validation
  // -> blur handler
  // -----------------
  amountInput.addEventListener("blur", () => {
    if (sendInProgress) return;
    
    const raw = amountInput.value.trim();
    if (!raw) {
      updateFees();
      return;
    }

    const norm = normalizeIcpAmount(raw);
    if (norm.ok) {
      amountInput.value = norm.value;
      sendCachedAmount = norm.value;
    }
    
    // Validate and 
    // update state
    // ------------
    updateFees();
    enforceSendAmountLimit();
    validateAndUpdateState();
  });

  // Resets the button label 
  // back to its default state
  // -------------------------
  const resetSendLabelOnFocus = () => {
    if (sendInProgress) return;
    if (sendState === "success") return;

    if (sendState === "error") {
      enableReview();
      return;
    }

    if (sendButtonLabel !== SEND_LABEL_DEFAULT) {
      resetSendButtonToDefault();
      status.textContent = "";
      sendCachedStatus = "";
    }
  };

  recipientInput.addEventListener("focus", resetSendLabelOnFocus);
  amountInput.addEventListener("focus", resetSendLabelOnFocus);

  // Fees logic
  // ----------
  const updateFees = async () => {
    if (sendInProgress) {
      // Restore cached display
      // ----------------------
      if (sendCachedFeeHtml) {
        feeDisplay.innerHTML = sendCachedFeeHtml;
      }
      return;
    }
    if (sendState !== "idle") return;
    
    const amountText = amountInput.value.trim();

    if (!amountText) {
      sendRequiredE8s = null;
      feeDisplay.innerHTML = '<span style="opacity:0.8;font-size:15px">Enter an amount to obtain a real-time estimate and breakdown of fees</span>';
      return;
    }

    try {
      const amt = parseIcpToE8s(amountText);

      if (amt <= 0n) {
        if(amountText !== "0" && amountText !== "0.") {
          sendRequiredE8s = null;
          feeDisplay.innerHTML = '<span style="color:var(--accent-danger);font-size:15px">Amount must be positive</span>';
        }
        return;
      }

      if (amt < SEND_MIN_E8S) {
        sendRequiredE8s = null;
        feeDisplay.innerHTML = '<span style="opacity:0.8;font-size:15px">Fees are only available for amounts at or above the minimum per transaction</span>';
        validateAndUpdateState();
        return;
      }

      if (amt > SEND_MAX_E8S) {
        sendRequiredE8s = null;
        feeDisplay.innerHTML = '<span style="opacity:0.8;font-size:15px">Fees are only available for amounts at or under the upper limit per transaction</span>';
        validateAndUpdateState();
        return;
      }

      const fees = await calculateFees(amt);

      const formatICP = (e8s: bigint) => {
        const v = Number(e8s) / 100_000_000;
        return v.toLocaleString(undefined, { maximumFractionDigits: 4 });
      };

      let html = `
        <div style="display:flex;flex-direction:column;gap:3px;">
          <div class="field-label" style="margin-bottom:5px;">
            <span style="font-size:14px;color:#00b4d8;"><strong>Fees breakdown</strong></span>
          </div>
          <div style="display:flex;justify-content:space-between;">
            <span>ICPP service fee &#10140; <span class="mono" style="color:#ffffff;font-size:14px;font-weight:600;">0.5%</span></span>
            <span class="mono" style="font-size:14px; text-align: right;">${formatICP(fees.depositFee)} ICP</span>
          </div>
          <div style="display:flex;justify-content:space-between;">
            <span>Cost of cycles provisioning &#10140; <span class="mono" style="color:#ffffff;font-weight:600;">Canister spawning and operations</span></span>
            <span class="mono" style="font-size:14px;text-align: right;">${formatICP(fees.spawnFee)} ICP</span>
          </div>
          <div style="display:flex;justify-content:space-between;">
            <span>Ledger fees &#10140; <span class="mono" style="color:#ffffff;font-weight:600;">${fees.numLedgerTransfers} transfers</span></span>
            <span class="mono" style="font-size:14px;text-align: right;">${formatICP(fees.totalLedgerFees)} ICP</span>
          </div>
      `;

      const totalFees = fees.totalApproval - amt;
      sendRequiredE8s = fees.totalApproval;

      // Success info or 
      // insufficient funds
      // ------------------
      let bottomBannerHtml = `
          <div style="margin-top:6px;padding:8px;background:rgba(69,123,157,0.3);border-radius:6px;font-size:14px;color:var(--fg-muted);">
            Recipient gets credited exactly <span class="mono" style="color:#ffffff;font-weight:600"> ${formatICP(amt)}</span> ICP tokens &nbsp;&#10072;&nbsp; 
            Transaction fees represent <span class="mono" style="color:#ffffff;font-weight:600;"> ${
              amt > 0n ? (Number(totalFees * 100000n / amt) / 1000).toFixed(3) : "0.000"
            }%</span>
          </div>
      `;

      const bal = sendCachedBalanceE8s;
      const hasBal = bal !== null;
      const sufficient = hasBal && (bal >= sendRequiredE8s);

      // Cascading validation handles button state
      // based on sendRequiredE8s we just set
      // -----------------------------------------
      validateAndUpdateState();

      if (!hasBal) {
        bottomBannerHtml = `
          <div style="margin-top:6px;padding:8px;background:rgba(249,115,115,0.10);border:1px solid rgba(249,115,115,0.25);border-radius:6px;font-size:14px;">
            <span style="color:var(--accent-danger);font-weight:600;">Balance unavailable</span>
            <span style="opacity:0.9;">Press UPDATE to validate funds before sending</span>
          </div>
        `;
      } else if (!sufficient) {
        bottomBannerHtml = `
          <div style="margin-top:6px;padding:8px;background:rgba(249,115,115,0.10);border:1px solid rgba(249,115,115,0.25);border-radius:6px;font-size:14px;">
            <span style="color:var(--accent-danger);font-weight:600;">&#9888;&nbsp;Insufficient balance &nbsp;&#10140;&nbsp;</span>
            <span style="opacity:0.9;">Required&nbsp;</span>
            <span class="mono" style="color:#ffffff;font-weight:600;">${formatICP(sendRequiredE8s)} ICP</span>
            <span style="opacity:0.9;">&nbsp;&#10072;&nbsp; Available&nbsp;</span>
            <span class="mono" style="color:#ffffff;font-weight:600;">${formatICP(bal)} ICP</span>
          </div>
        `;
      }
      
      if (totalFees * 4n > amt) {
        html += `
          <div style="margin-top:6px;padding:8px;background:rgba(249,115,115,0.12);border:1px solid rgba(249,115,115,0.3);border-radius:6px;font-size:14px">
            <div style="color:var(--accent-danger);font-weight:600;">&#9888; High Fee Warning</div>
            <div style="color:var(--accent-danger);margin-top:2px;">
              Fees exceed 25% of transfer amount
            </div>
          </div>
        `;
      }

      html += `
          <div style="margin-top:6px;padding-top:6px;border-top:1px solid rgba(148,163,184,0.25);font-size:14px;display:flex;justify-content:space-between;">
            <span class="mono" style="color:#ffffff;font-weight:600;"><strong>ICP tokens to be deducted from your account</strong></span>
            <span class="mono" style="color:#ffffff;font-weight:600;"><strong>${formatICP(fees.totalApproval)} ICP</strong></span>
          </div>
          ${bottomBannerHtml}
        </div>
      `;
      
      sendCachedFeeHtml = html;
      feeDisplay.innerHTML = html;

    } catch (e: any) {
      // Any fee-calculation failure 
      // must freeze the send action
      // ---------------------------
      sendRequiredE8s = null;
      
      // Cascading validation 
      // handles button state
      // --------------------
      validateAndUpdateState();
      
      const msg = String(e?.message || e);
      
      if (msg.includes("Session not initialized")) {
        feeDisplay.innerHTML = '<span style="opacity:0.8;font-size:15px">Complete setup to see fee breakdown</span>';
        return;
      }
      
      // If conversion fails (e.g. letters)
      // or symbols used) show format error
      // ----------------------------------
      if (amountText.length > 0 && !amountText.match(/^[0-9.,]+$/)) {
        feeDisplay.innerHTML = '<span style="color:var(--accent-danger);font-size:14px;">Invalid amount format</span>';
        return;
      }

      // Network or 
      // canister errors
      // ---------------
      feeDisplay.innerHTML = '<span style="color:var(--accent-danger);font-size:14px;">Unable to calculate fees at the moment</span>';
    }
  };

  updateFees();

  // Restore cached fees display 
  // if in success/error state
  // ---------------------------
  if (sendState !== "idle" && sendCachedFeeHtml) {
    feeDisplay.innerHTML = sendCachedFeeHtml;
  }
  
  // Initial field state validation
  // (updateFees will also call 
  // this after async completion)
  // ------------------------------
  validateAndUpdateState();

  // Listen for balance updates 
  // from auto-refresh
  // --------------------------
  window.addEventListener('balance-updated', () => {
    if (currentTab === "send") {
      validateAndUpdateState();
    }
  });

  // Main button 
  // handler
  // -----------
  btn.onclick = async () => {
    
    // Handle SUCCESS state click 
    // (user wants to make another 
    // transfer)
    // ---------------------------
    if (sendState === "success") {
      resetForm();
      return;
    }

    // Handle ERROR state click 
    // (user wants to review/retry)
    // ----------------------------
    if (sendState === "error") {
      enableReview();
      return;
    }

    // Handle IDLE state click 
    // (user submits form)
    // -----------------------
    try {
      btn.disabled = true;
      sendInProgress = true;
      toggleInputs(true);
      updateLogoutEnabled();

      const recipientText = recipientInput.value.trim();
      const amountText = amountInput.value.trim();

      if (!recipientText) {
        setSendButton("Recipient ICP PID required", false);
        status.textContent = "";
        sendInProgress = false;
        toggleInputs(false);
        return;
      }

      let bob: Principal;
      try {
        bob = Principal.fromText(recipientText);
      } catch {
        setSendButton("Invalid ICP PID format", false);
        status.textContent = "";
        sendInProgress = false;
        toggleInputs(false);
        return;
      }

      let amount: bigint;
      const norm = normalizeIcpAmount(amountText);
      if (norm.ok === false) {
        setSendButton(norm.error, false);
        status.textContent = "";
        sendInProgress = false;
        toggleInputs(false);
        return;
      }

      amountInput.value = norm.value;
      sendCachedAmount = norm.value;

      try {
        amount = parseIcpToE8s(norm.value);
      } catch {
        setSendButton("Invalid amount format", false);
        status.textContent = "";
        sendInProgress = false;
        toggleInputs(false);
        return;
      }

      // Hard guard -> cannot 
      // send > 2000 ICP
      // --------------------
      if (amount > SEND_MAX_E8S) {
        sendAmountOverLimit = true;
        setSendButton(SEND_LABEL_OVER_LIMIT, true);
        sendInProgress = false;
        toggleInputs(false);
        return;
      }

      if (amount < SEND_MIN_E8S) {
        sendAmountBelowLimit = true;
        setSendButton(SEND_LABEL_BELOW_LIMIT, true);
        sendInProgress = false;
        toggleInputs(false);
        return;
      }

      if (amount <= 0n) {
        setSendButton("Amount must be positive", false);
        status.textContent = "";
        sendInProgress = false;
        toggleInputs(false);
        return;
      }
      
      setSendButton(processingSendLabel, true);
      status.textContent = "";
      sendCachedStatus = "";

      // Prevent Internet Identity idle 
      // expiry from clearing actors mid-flight
      // --------------------------------------
      await beginUserOperation();
      let depositIdHex: string;
      try {
        const res = await sendShielded({
          amountE8s: amount,
          bobPrincipal: bob,
          subaccount: [],
        });
        depositIdHex = res.depositIdHex;
      } finally {
        endUserOperation();
      }

      // =============
      // SUCCESS STATE
      // =============
      
      sendState = "success";
      btn.textContent = successSendLabel;
      sendButtonLabel = successSendLabel;
      btn.style.background = "#9ac13e";
      btn.style.color = "#000000";
      btn.disabled = false;
      
      // User must click 
      // button to reset
      // ---------------
      const transferIdShort = depositIdHex.slice(0, 32);
      const successHtml =
        `Deposit successfully processed\n` +
        `Transfer ID <span class="mono" style="font-size:15px; font-weight:500px; color:#00b4d8;">${transferIdShort}</span>\n` +
        `Recipient will get an encrypted hint of ICP tokens being available for collection\n` +
        `This hint is both ephemeral and unlinkable to your PID`;

      status.classList.remove("status-error");
      status.innerHTML = successHtml;

      sendCachedStatus = successHtml;

      // Update persisted values
      // -----------------------
      sendCachedRecipient = recipientInput.value;
      sendCachedAmount = amountInput.value;
      void refreshBalanceCache();

    } catch (e: any) {
      sendState = "error";
      const errMsg = sanitizeError(e);

      setSendButton(errMsg, false);
      btn.style.background = "#d62828";
      btn.style.color = "#ffffff";

      status.textContent = "";
      sendCachedStatus = "";

      // Do not freeze 
      // inputs on error
      // ---------------
      toggleInputs(false);
      
    } finally {
      sendInProgress = false;
      updateLogoutEnabled();
      if (currentTab === "send" && !btn.isConnected) {
        renderSendCard();
        return;
      }
      // Only re-enable 
      // if not over limit
      // -----------------
      if (!sendAmountOverLimit || !sendAmountBelowLimit) {
        btn.disabled = false;
      }
    }
  };
}

function renderReceiveCard() {
  const left = $("#left-card");
  clear(left);

  left.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Receive</div>
          <div class="card-subtitle">
            Scan for incoming shielded ICP transfers</br>
            Processing is limited to one transaction at a time
          </div>
        </div>
        <span class="card-badge">Local decryption – Shielded</span>
      </div>
      <div class="field-group">
        <div class="field">
          <div class="field-label" style="color:#00b4d8; margin-bottom:1px;"><strong>Please enter your PIN</strong></div>
          <div class="field-subtitle" style="margin-bottom:10px;">
            Required for confirmation of ownership
          </div>
          <div class="pin-wrapper">
            <input id="pin-recv" type="password" placeholder="6 or more digits" />
            <button type="button" class="password-toggle" id="pin-toggle-recv" aria-label="Show PIN">
              <svg class="pw-icon" aria-hidden="true"><use href="#ico-eye-closed"></use></svg>
            </button>
          </div>
        </div>
        <button id="btn-scan" class="button-primary">Scan for transfers</button>
        <div id="recv-list" class="list"></div>
        <div id="status-recv" class="status"></div>
      </div>
    </div>
  `;

  const pinInput = $("#pin-recv") as HTMLInputElement;
  const btnScan = $("#btn-scan") as HTMLButtonElement;
  const list = $("#recv-list");
  const status = $("#status-recv");

  // Scan button labels
  // ------------------
  const SCAN_LABEL_DEFAULT = "Scan for transfers";
  const SCAN_LABEL_CHECKING = "Scanning – Please wait";
  const SCAN_LABEL_NONE = "Nothing found – Check back later";
  const SCAN_LABEL_UNAVAILABLE = "Unable now to process your request";

  // Container second-line messages
  // ------------------------------
  const META_CLAIMING = "Claiming funds – Usually takes 10 to 15 min for confirmation";
  const META_DONE = "Success – Check the balance of your ICPP account";
  const META_FAIL = "Network or other issues prevent processing – Please wait a few minutes";
  const META_HARD_FAIL = "State corruption or other issues are leading to retrieval failure";

  function metaDefault(storageLen: number) {
    return `Stored in ${storageLen} ephemeral nodes – Please note the claim window is 72 hs`;
  }

  function setScanButton(label: string, disabled: boolean) {
    recvScanLabel = label;
    btnScan.textContent = label;
    btnScan.disabled = disabled;
  }

  status.textContent = "";

  // PIN must not persist 
  // across tab switches
  // --------------------
  pinInput.addEventListener("input", () => {
    updateAllButtons();
    
    // Scan button disabled until 
    // PIN valid (like ACCESS card)
    // ----------------------------
    if (!recvScanInProgress && processingId === null) {
      const pinOk = isPinValid();
      btnScan.disabled = !pinOk;
    }
  });

  // Check if PIN 
  // format is valid
  // ---------------
  function isPinValid(): boolean {
    const pinEl = document.getElementById("pin-recv") as HTMLInputElement | null;
    const pin = (pinEl?.value ?? "").trim();
    return /^\d{6,}$/.test(pin);
  }

  const pinToggle = $("#pin-toggle-recv") as HTMLButtonElement;

  pinToggle.onclick = () => {
    const use = pinToggle.querySelector("use") as SVGUseElement;
    const toVisible = pinInput.type === "password";
    pinInput.type = toVisible ? "text" : "password";
    const ref = toVisible ? "#ico-eye-open" : "#ico-eye-closed";
    use.setAttribute("href", ref);

    // Safari fallback
    // ---------------
    use.setAttribute("xlink:href", ref);
    pinToggle.setAttribute("aria-label", toVisible ? "Hide PIN" : "Show PIN");
  };

  // Set button appearance 
  // based on state
  // ---------------------
  const applyButtonState = (btn: HTMLButtonElement, depositId: string) => {
    if (claimedIds.has(depositId)) {
      btn.textContent = "Done";
      btn.disabled = true;
      btn.style.background = "#9ac13e";
      btn.style.color = "#000000";
      btn.style.cursor = "default";

    } else if (processingId === depositId) {
      btn.textContent = "Processing";
      btn.disabled = true;
      btn.style.background = "#94a3b8";
      btn.style.color = "#000000";
      btn.style.cursor = "default";

    } else if (hardFailedIds.has(depositId)) {
      btn.textContent = "Failed";
      btn.disabled = true;
      btn.style.background = "#d62828";
      btn.style.color = "#ffffff";
      btn.style.cursor = "default";

    } else if (failedIds.has(depositId)) {
      btn.textContent = "Try Again";
      const pinOk = isPinValid();
      btn.disabled = processingId !== null || !pinOk;
      btn.style.background = "#d69f7e";
      btn.style.color = "#000000";
      btn.style.cursor = (processingId !== null || !pinOk) ? "default" : "pointer";

    } else {
      btn.textContent = "Claim";
      const pinOk = isPinValid();
      btn.disabled = processingId !== null || !pinOk;
      btn.style.background = "#ffb703";
      btn.style.color = "#000000";
      btn.style.cursor = (processingId !== null || !pinOk) ? "default" : "pointer";
    }
  };

  // Restore main scan 
  // button on re-render
  // -------------------
  if (recvScanInProgress) {
    setScanButton(SCAN_LABEL_CHECKING, true);
  } else {
    // Scan button disabled until 
    // PIN valid (like ACCESS card)
    // ----------------------------
    const pinOk = isPinValid();
    setScanButton(SCAN_LABEL_DEFAULT, !pinOk);
  }

  // Update all notice buttons 
  // based on current state
  // -------------------------
  const updateAllButtons = () => {
    const items = list.querySelectorAll<HTMLElement>(".list-item");
    items.forEach((item) => {
      const id = item.dataset.depositId || "";
      const storageLen = Number(item.dataset.storageLen || "0");
      const btn = item.querySelector(".button-claim") as HTMLButtonElement | null;
      const meta = item.querySelector(".recv-meta") as HTMLSpanElement | null;

      if (!btn || !meta) return;

      // Button states 
      // -> Done | Processing | Try Again | Claim | Failed
      // -------------------------------------------------
      applyButtonState(btn, id);

      // Second-line state
      // -----------------
      if (claimedIds.has(id)) {
        meta.textContent = META_DONE;
      } else if (processingId === id) {
        meta.textContent = META_CLAIMING;
      } else if (failedIds.has(id)) {
        meta.textContent = META_FAIL;
      } else if (hardFailedIds.has(id)) {
        meta.textContent = META_HARD_FAIL;
      } else {
        meta.textContent = metaDefault(storageLen);
      }
    });

    updateLogoutEnabled();
  };

  // Render announcement list 
  // from cache or fresh data
  // ------------------------
  const renderList = (anns: typeof cachedAnnouncements) => {
    clear(list);

    if (!anns.length) {
      clear(list);
      return;
    }

    anns.forEach((a) => {
      const item = document.createElement("div");
      item.className = "list-item";
      item.dataset.depositId = a.depositIdHex;
      item.dataset.storageLen = String(a.storagePrincipals.length);
      item.innerHTML = `
        <div class="list-item-main">
          <div class="mono">Transfer ID ${a.depositIdHex.slice(0, 32)}</div>
          <div class="list-item-meta">
            <span class="mono recv-meta" style="margin-top:3px;"></span>
          </div>
        </div>
        <button class="button-claim">Claim</button>
      `;

      const btnClaim = item.querySelector(".button-claim") as HTMLButtonElement;

      // Apply initial state
      // -------------------
      btnClaim.onclick = async () => {
        if (processingId !== null) return;
        if (claimedIds.has(a.depositIdHex)) return;

        const pinEl = document.getElementById("pin-recv") as HTMLInputElement | null;
        const pin = (pinEl?.value ?? "").trim();

        // Clear from failed 
        // if retrying
        // -----------------
        failedIds.delete(a.depositIdHex);
        processingId = a.depositIdHex;
        btnScan.disabled = true;
        updateAllButtons();

        try {
          // Processing
          // ----------
          status.textContent = "";

          // Claim can take minutes so prevent idle 
          // expiry from clearing actors mid-flight
          // --------------------------------------
          await beginUserOperation();
          try {
            await claimDeposit(a.depositIdHex, pin, a.storagePrincipals);
          } finally {
            endUserOperation();
          }

          // Success
          // -------
          claimedIds.add(a.depositIdHex);
          void refreshBalanceCache();
          updateAllButtons();

        } catch (e: any) {
          const msg = sanitizeError(e);

          // Hard-fail conditions 
          // -> FAILED button
          // --------------------
          if (
            msg === "Invalid transfer data" ||
            msg === "Transfer data unavailable" ||
            msg === "This transfer may not be for you"
          ) {
            hardFailedIds.add(a.depositIdHex);
            failedIds.delete(a.depositIdHex);
            status.textContent = "";

          } else if (msg === "Session expired – Please re-login") {
            // Session expiry -> show message and mark retryable
            // (user needs to re-authenticate before retry)
            // -------------------------------------------------
            failedIds.add(a.depositIdHex);
            status.textContent = msg;

          } else {
            // Everything else retryable
            // -> TRY AGAIN button
            // -------------------------
            failedIds.add(a.depositIdHex);
            status.textContent = "";
          }

          updateAllButtons();

        } finally {
          processingId = null;
          
          // Clear PIN after 
          // claim attempt
          // ---------------
          const pinEl = document.getElementById("pin-recv") as HTMLInputElement | null;
          if (pinEl) pinEl.value = "";

          // Re-render as DOM 
          // refs may be stale
          // -----------------
          if (currentTab === "receive" && (!list.isConnected || !btnScan.isConnected)) {
            renderReceiveCard();
            return;
          }

          updateAllButtons();

          // Re-enable scan unless 
          // scan running or PIN invalid
          // ---------------------------
          if (!recvScanInProgress) {
            btnScan.disabled = !isPinValid();
          }
        }
      };

      list.appendChild(item);
    });
    
    updateAllButtons();
  };

  // Restore cached 
  // list on re-render
  // -----------------
  if (cachedAnnouncements.length > 0) {
    renderList(cachedAnnouncements);
  }

  // Disable scan button 
  // if claim in progress
  // --------------------
  if (processingId !== null) {
    btnScan.disabled = true;
  }

  btnScan.onclick = async () => {
    if (processingId !== null) return;
    if (recvScanInProgress) return;

    // PIN validation (format 
    // already checked by isPinValid)
    // ------------------------------
    const pin = pinInput.value.trim();

    if (!isPinValid()) {
      setScanButton("PIN has at least 6 digits", false);
      return;
    }

    // Verify PIN against stored NK
    // before proceeding with scan
    // ----------------------------
    const actors = getActorsForQuery();
    if (!actors) {
      setScanButton("Session not initialized", false);
      return;
    }

    try {
      await loadNk(actors.principal, pin);
    } catch {
      setScanButton("Invalid PIN – Please try again", false);
      return;
    }

    // Scan noticeboard
    // ----------------
    recvScanInProgress = true;
    setScanButton(SCAN_LABEL_CHECKING, true);
    status.textContent = "";
    updateLogoutEnabled();

    try {
      const anns = await listAnnouncements();
      cachedAnnouncements = anns;

      recvScanInProgress = false;
      updateLogoutEnabled();

      // Decide final scan 
      // button label FIRST
      // ------------------
      if (anns.length === 0) {
        recvScanLabel = SCAN_LABEL_NONE;
      } else {
        recvScanLabel = SCAN_LABEL_DEFAULT;
      }

      // If user tab-switched while awaiting
      // re-render using the updated state
      // -----------------------------------
      if (currentTab === "receive" && !btnScan.isConnected) {
        renderReceiveCard();
        return;
      }

      if (anns.length === 0) {
        clear(list);
        setScanButton(SCAN_LABEL_NONE, processingId !== null);
        return;
      }

      // Found transfers -> revert
      // scan button to default
      // -------------------------
      setScanButton(SCAN_LABEL_DEFAULT, processingId !== null);
      renderList(anns);

    } catch (e: any) {
      recvScanInProgress = false;
      updateLogoutEnabled();

      const msg = sanitizeError(e);

      // Map specific normalized errors 
      // directly to the scan button label
      // ---------------------------------
      if (
        msg === "No service – Try again later" ||
        msg === "Bad connection – Try again later" ||
        msg === "Unable now to handle your request"
      ) {
        recvScanLabel = msg;
      } else {
        recvScanLabel = SCAN_LABEL_UNAVAILABLE;
      }

      setScanButton(recvScanLabel, processingId !== null);
      status.textContent = "";
    }
  };
}

function renderWithdrawCard() {
  const left = $("#left-card");
  clear(left);

  left.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Withdraw</div>
          <div class="card-subtitle">Move ICP out of this ICPP account</div>
        </div>
        <span class="card-badge">Standard transfer – Not shielded</span>
      </div>
      <div class="field-group">
        <div class="field">
          <div class="field-label" style="color:#00b4d8; margin-bottom:1px;"><strong>Balance</strong></div>
          <div class="field-subtitle">ICP tokens available</div>
          <div class="balance-row">
            <input id="withdraw-balance" class="field-input" type="text" value="${sendCachedBalanceText || '0.0000'}" readonly style="flex:1;" />
          </div>
        </div>
        <hr style="border:0; border-top:1px solid #8da9c4; margin:12px 0;">
        <div class="field">
          <div class="field-label" style="color:#00b4d8; margin-bottom:1px;"><strong>Amount</strong></div>
          <div class="amount-wrapper">
            <input id="withdraw-amount" type="text" placeholder="0.0000 Tokens" />
          </div>
        </div>
        <div class="field">
          <div class="field-label" style="margin-top:8px; color:#00b4d8; margin-bottom:1px;"><strong>Withdraw to</strong></div>
          <div class="field-subtitle">Provide the Principal ID to receive the funds (any ICRC-1 PID is acceptable)</div>
          <input id="withdraw-destination" type="text" placeholder="Enter a 53-character PID" disabled style="opacity:0.65;" />
        </div>
        <div class="field">
          <div class="field-label" style="margin-top:8px; color:#00b4d8; margin-bottom:1px;"><strong>Please enter your PIN</strong></div>
          <div class="field-subtitle">Required for confirmation of ownership</div>
          <div class="pin-wrapper">
            <input id="pin-withdraw" type="password" placeholder="6 or more digits" disabled style="opacity:0.65;" />
            <button type="button" class="password-toggle" id="pin-toggle-withdraw" aria-label="Show PIN">
              <svg class="pw-icon" aria-hidden="true"><use href="#ico-eye-closed"></use></svg>
            </button>
          </div>
        </div>
        <div
          id="withdraw-info-ribbon"
          style="
            margin-top:8px;
            padding:10px;
            border-radius:8px;
            background:rgba(15,23,42,0.6);
            border:1px solid rgba(148,163,184,0.3);
            font-size:14px;
            line-height:1.6;
            color:var(--fg-muted);
            min-height:40px;
          "
        >
          Please note the <span style="font-weight:500;">standard ledger fee</span> of <span class="mono" style="color:#ffffff;">0.0001 ICP</span> applies to this transaction
        </div>
        <div style="display:flex; gap:10px; margin-top:5px;">
          <button id="btn-withdraw" class="button-primary" style="flex:1;">${withdrawButtonLabel}</button>
        </div>
      </div>
    </div>
  `;

  const balanceInput = $("#withdraw-balance") as HTMLInputElement;
  const amountInput = $("#withdraw-amount") as HTMLInputElement;
  const destinationInput = $("#withdraw-destination") as HTMLInputElement;
  const pinInput = $("#pin-withdraw") as HTMLInputElement;
  const btn = $("#btn-withdraw") as HTMLButtonElement;
  const infoRibbon = $("#withdraw-info-ribbon") as HTMLDivElement;

  // Set initial 
  // disabled state 
  // --------------
  btn.disabled = true;

  const defaultLabel = WITHDRAW_LABEL_DEFAULT;
  const successLabel = "Success – Press to reset form";
  const processingLabel = "Processing withdrawal...";

  const defaultRibbonHtml = `Please note the <span style="font-weight:500;">standard ledger fee</span> of&nbsp; 
                             <span class="mono" style="color:#ffffff;">0.0001 ICP</span>&nbsp;applies to this transaction`;

  // Insufficient 
  // balance
  // ------------
  const insufficientRibbonHtml = `<span style="color:var(--accent-danger);font-weight:600;">&#9888;&nbsp;Insufficient balance&nbsp;&nbsp;&#10140;&nbsp;</span> <span style="opacity:0.9;"> 
                                 Only&nbsp;</span> <span class="mono" style="color:#ffffff;font-weight:600;">${sendCachedBalanceText || '0.0000'} ICP</span>&nbsp;
                                 available on your ICPC account`;

  // PIN toggle
  // ----------
  const pinToggle = $("#pin-toggle-withdraw") as HTMLButtonElement;
  pinToggle.onclick = () => {
    const use = pinToggle.querySelector("use") as SVGUseElement;
    const toVisible = pinInput.type === "password";
    pinInput.type = toVisible ? "text" : "password";
    const ref = toVisible ? "#ico-eye-open" : "#ico-eye-closed";
    use.setAttribute("href", ref);
    use.setAttribute("xlink:href", ref);
    pinToggle.setAttribute("aria-label", toVisible ? "Hide PIN" : "Show PIN");
  };

  // Field state helpers
  // -------------------
  function setFieldEnabled(el: HTMLInputElement, enabled: boolean): void {
    el.disabled = !enabled;
    el.style.opacity = enabled ? "1" : "0.65";
  }

  function setButtonEnabled(enabled: boolean): void {
    btn.disabled = !enabled;
  }

  function setButtonLabel(label: string): void {
    btn.textContent = label;
    withdrawButtonLabel = label;
  }

  function resetButtonStyle(): void {
    btn.style.background = "";
    btn.style.color = "";
  }

  function setButtonSuccess(): void {
    btn.style.background = "#9ac13e";
    btn.style.color = "#000000";
  }

  function setButtonError(): void {
    btn.style.background = "#d62828";
    btn.style.color = "#ffffff";
  }

  function setRibbonDefault(): void {
    infoRibbon.innerHTML = defaultRibbonHtml;
    infoRibbon.style.background = "rgba(15,23,42,0.6)";
    infoRibbon.style.border = "1px solid rgba(148,163,184,0.3)";
  }

  function setRibbonError(): void {
    infoRibbon.innerHTML = insufficientRibbonHtml;
    infoRibbon.style.background = "rgba(249,115,115,0.10)";
    infoRibbon.style.border = "1px solid rgba(249,115,115,0.25)";
  }

  // Freeze all inputs 
  // -----------------
  function freezeAllInputs(): void {
    setFieldEnabled(amountInput, false);
    setFieldEnabled(destinationInput, false);
    setFieldEnabled(pinInput, false);
  }

  // Reset form 
  // to initial state
  // ----------------
  function resetForm(): void {
    withdrawState = "idle";
    withdrawButtonLabel = defaultLabel;
    withdrawCachedDestination = "";
    withdrawCachedAmount = "";
    
    amountInput.value = "";
    destinationInput.value = "";
    pinInput.value = "";
    
    setFieldEnabled(amountInput, true);
    setFieldEnabled(destinationInput, false);
    setFieldEnabled(pinInput, false);
    
    setButtonLabel(defaultLabel);
    setButtonEnabled(false);
    resetButtonStyle();
    setRibbonDefault();
  }

  // Validation 
  // helpers
  // ----------
  function isValidPrincipal(text: string): boolean {
    try {
      Principal.fromText(text);
      return true;
    } catch {
      return false;
    }
  }

  // Cascading validation
  // --------------------
  function validateAndUpdateState(): void {
    if (withdrawInProgress) return;
    if (withdrawState !== "idle") return;

    const amountText = amountInput.value.trim();
    const destinationText = destinationInput.value.trim();
    const pin = pinInput.value.trim();

    // Reset to default ribbon
    // -----------------------
    setRibbonDefault();
    resetButtonStyle();
    setButtonLabel(defaultLabel);
    
    // Helper to clear child fields
    // when parent becomes EMPTY
    // ----------------------------
    const clearChildFields = () => {
      destinationInput.value = "";
      withdrawCachedDestination = "";
      pinInput.value = "";
    };
    
    const clearPinOnly = () => {
      pinInput.value = "";
    };
    
    // No balance available
    // --------------------
    if (sendCachedBalanceE8s === null || sendCachedBalanceE8s === 0n) {
      setFieldEnabled(destinationInput, false);
      setFieldEnabled(pinInput, false);
      clearChildFields();
      setButtonEnabled(false);
      return;
    }

    // No amount entered
    // -----------------
    if (!amountText) {
      setFieldEnabled(destinationInput, false);
      setFieldEnabled(pinInput, false);
      clearChildFields();
      setButtonEnabled(false);
      return;
    }

    // Normalize and 
    // parse amount
    // -------------
    const norm = normalizeIcpAmount(amountText);
    if (!norm.ok) {
      setFieldEnabled(destinationInput, false);
      setFieldEnabled(pinInput, false);
      setButtonEnabled(false);
      return;
    }

    let amountE8s: bigint;

    try {
      amountE8s = parseIcpToE8s(norm.value);
    } catch {
      setFieldEnabled(destinationInput, false);
      setFieldEnabled(pinInput, false);
      setButtonEnabled(false);
      return;
    }

    // Amount must 
    // be positive
    // -----------
    if (amountE8s <= 0n) {
      setFieldEnabled(destinationInput, false);
      setFieldEnabled(pinInput, false);
      setButtonEnabled(false);
      return;
    }

    // Amount exceeds balance 
    // -> freeze downstream
    // ----------------------
    if (amountE8s > sendCachedBalanceE8s) {
      setRibbonError();
      setFieldEnabled(destinationInput, false);
      setFieldEnabled(pinInput, false);
      setButtonEnabled(false);
      return;
    }

    setFieldEnabled(destinationInput, true);
    
    if (!destinationText) {
      setFieldEnabled(pinInput, false);
      clearPinOnly();
      setButtonEnabled(false);
      return;
    }

    if (!isValidPrincipal(destinationText)) {
      setFieldEnabled(pinInput, false);
      setButtonEnabled(false);
      return;
    }

    setFieldEnabled(pinInput, true);

    // Validate PIN
    // ------------
    if (!/^\d{6,}$/.test(pin)) {
      setButtonEnabled(false);
      return;
    }

    // PIN format valid 
    // -> enable button
    // ----------------
    setButtonEnabled(true);
  }

  // Sync balance 
  // from shared cache
  // -----------------
  balanceInput.value = sendCachedBalanceText || "0.0000";
  
  if (!withdrawInProgress) {
    void refreshBalanceCache().catch(() => {});
  }

  // Restore cached state
  // --------------------
  amountInput.value = withdrawCachedAmount;
  destinationInput.value = withdrawCachedDestination;

  // Apply persisted UI state
  // ------------------------
  if (withdrawState === "success") {
    setButtonLabel(successLabel);
    setButtonSuccess();
    setButtonEnabled(true);
    freezeAllInputs();
  } else if (withdrawState === "error") {
    setButtonLabel(withdrawButtonLabel);
    setButtonError();
    setButtonEnabled(true);
    // Don't freeze inputs on error 
    // -> allow user to correct
    // ----------------------------
    validateAndUpdateState();
  } else if (withdrawInProgress) {
    setButtonLabel(processingLabel);
    setButtonEnabled(false);
    freezeAllInputs();
  } else {
    // Idle state -> run validation 
    // to set correct field states
    // ----------------------------
    validateAndUpdateState();
  }

  // Input event handlers
  // --------------------
  amountInput.addEventListener("input", () => {
    if (withdrawInProgress) return;

    if (withdrawState === "success") {
      resetForm();
      return;
    }

    if (withdrawState === "error") {
      withdrawState = "idle";
      resetButtonStyle();
    }

    withdrawCachedAmount = amountInput.value;
    validateAndUpdateState();
  });

  amountInput.addEventListener("blur", () => {
    if (withdrawInProgress) return;
    const norm = normalizeIcpAmount(amountInput.value.trim());
    if (norm.ok) {
      amountInput.value = norm.value;
      withdrawCachedAmount = norm.value;
    }
    validateAndUpdateState();
  });

  destinationInput.addEventListener("input", () => {
    if (withdrawInProgress) return;

    if (withdrawState === "success") {
      resetForm();
      return;
    }

    if (withdrawState === "error") {
      withdrawState = "idle";
      resetButtonStyle();
    }

    withdrawCachedDestination = destinationInput.value;
    validateAndUpdateState();
  });

  pinInput.addEventListener("input", () => {
    if (withdrawInProgress) return;

    if (withdrawState === "success") {
      resetForm();
      return;
    }

    if (withdrawState === "error") {
      withdrawState = "idle";
      resetButtonStyle();
    }

    validateAndUpdateState();
  });

  // Submit handler
  // --------------
  btn.onclick = async () => {
    // SUCCESS state
    // -------------
    if (withdrawState === "success") {
      resetForm();
      return;
    }

    // ERROR state
    // -----------
    if (withdrawState === "error") {
      withdrawState = "idle";
      resetButtonStyle();
      validateAndUpdateState();
      return;
    }

    // Final validation 
    // before submit
    // ----------------
    const amountText = amountInput.value.trim();
    const destinationText = destinationInput.value.trim();
    const pin = pinInput.value.trim();

    const norm = normalizeIcpAmount(amountText);
    if (!norm.ok) return;
    
    amountInput.value = norm.value;
    withdrawCachedAmount = norm.value;

    let amountE8s: bigint;
    try { amountE8s = parseIcpToE8s(norm.value); }
    catch { return; }

    if (amountE8s <= 0n) return;
    if (sendCachedBalanceE8s !== null && amountE8s > sendCachedBalanceE8s) return;

    let destination: Principal;
    try { destination = Principal.fromText(destinationText); }
    catch { return; }

    if (!/^\d{6,}$/.test(pin)) return;

    // Execute
    // -------
    try {
      withdrawInProgress = true;
      freezeAllInputs();
      setButtonLabel(processingLabel);
      setButtonEnabled(false);
      updateLogoutEnabled();

      await beginUserOperation();
      try { await withdrawIcp(destination, amountE8s, pin); }
      finally { endUserOperation(); }

      withdrawState = "success";
      setButtonLabel(successLabel);
      setButtonSuccess();
      setButtonEnabled(true);

      void refreshBalanceCache();

    } catch (e: any) {
      withdrawState = "error";
      const errMsg = sanitizeError(e);
      setButtonLabel(errMsg);
      setButtonError();
      setButtonEnabled(true);

      if (errMsg === "Session expired – Please re-login") {
        resetSessionState();
        render();
        return;
      }

      // Unfreeze inputs 
      // so user can correct
      // -------------------
      setFieldEnabled(amountInput, true);
      validateAndUpdateState();

    } finally {
      withdrawInProgress = false;
      updateLogoutEnabled();
      if (currentTab === "withdraw" && !btn.isConnected) {
        renderWithdrawCard();
      }
    }
  };
}

function renderSidePanel() {
  const right = $("#right-card");
  clear(right);

  right.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Basics</div>
          <div class="card-subtitle">Protocol versioning and other information about ICPP</div>
        </div>
      </div>
      <div class="stack">
        <div class="chip">
          <span><strong>Privacy model and release </strong>&#10140;</span>
          <span class="mono" style="color:#00b4d8;">RDMPF + SgpFE (v2.1.00 Jan 2026)</span>
        </div>
        <div class="chip">
          <span><strong>Identity handling </strong>&#10140;</span>
          <span class="mono" style="color:#00b4d8;">Internet Identity</span>
        </div>
        <div class="chip">
          <span><strong>User credentials storage </strong>&#10140;</span>
          <span class="mono" style="color:#00b4d8;">Browser-local NK</span>
        </div>
        <div class="chip">
          <span><strong>Decryption by recepient </strong>&#10140;</span>
          <span class="mono" style="color:#00b4d8;">RDMPF (in-browser and isolated)</span>
        </div>
      </div>
      <div style="margin-top:14px;font-size:14px;color:var(--fg-muted);line-height:1.4;">
        <span style="color:#f4a261;"><strong>ICPP offers privacy-enabled P2P ICP token transfers on the Internet Computer.</strong></span> 
      </div>
      <div style="margin-top:14px;font-size:14px;color:var(--fg-muted);line-height:1.4;">
        The platform uses ephemeral intermediaries, transaction pooling, and cryptographic mechanisms to decouple deposit and retrieval stages, ensuring 
        secure sealed storage in transit and attested teardown upon completion. ICPP preserves sender identity privacy with respect to the recipient, content 
        confidentiality, and forward secrecy of transport keys through staged destruction. It achieves this alongside verifiable liveness and finality. 
      </div>
      <div style="margin-top:14px;font-size:14px;color:var(--fg-muted);line-height:1.4;">  
        <span style="color:#f4a261;"><strong>Important additional information</strong></span><br/>
        <ul class="no-indent">
          <li>Your PIN and NK never leave (nor leak from) this device.</li>
          <li>Always verify the recipient address before sending funds.</li>
          <li>Allow 10 to 15 min for transaction processing, although duration ultimately depends on network congestion.</li>
          <li>Canister spawning costs are fixed, progressively lowering its impact (in percentage terms) as the amounts being sent increase.</li>
          <li>ICPP has been thoroughly tested but it's still in active development.</li>
        </ul>
      </div>
      <div style="margin-top:14px;font-size:14px;color:var(--fg-muted);line-height:1.4;">
        <span style="color:#f4a261;"><strong>By making P2P transfers through ICPP you agree to be using the platform at your own risk including, but 
        not limited to, the potential loss of funds.</strong></span>
      </div>
    </div>
  `;
}

function render() {
  const root = $("#root");
  if (!root.querySelector(".app-shell")) {
    root.innerHTML = `
      <div class="app-shell">
        <div class="app-header">
          <div class="app-title">
            <div class="app-title-logo"></div>
            <div>
              <div class="app-title-text-main">ICPP Protocol</div>
              <div class="app-title-text-sub">A platform for privacy-enabled P2P ICP transfers</div>
            </div>
          </div>
          <div class="app-nav-row">
            <div class="app-nav app-nav-main">
              <button data-tab="access" class="active">Access</button>
              <button data-tab="send">Send</button>
              <button data-tab="receive">Receive</button>
              <button data-tab="withdraw">Withdraw</button>
            </div>
            <div class="app-nav app-nav-actions">
              <button id="btn-help" type="button">Help</button>
              <button id="btn-logout" type="button">Logout</button>
            </div>
          </div>
        </div>
        <div class="app-body">
          <div id="left-card"></div>
          <div id="right-card"></div>
        </div>
      </div>
    `;

    document
      .querySelectorAll<HTMLButtonElement>(".app-nav-main button[data-tab]")
      .forEach((btn) => {
        btn.onclick = () => switchTab(btn.dataset.tab as Tab);
        if (!isSetupComplete && (btn.dataset.tab === "send" || btn.dataset.tab === "receive" || btn.dataset.tab === "withdraw")) {
          btn.disabled = true;
        }
      });

    const helpBtn = document.getElementById("btn-help") as HTMLButtonElement | null;
    if (helpBtn) {
      helpBtn.onclick = () => {
        window.open("/icpp-intro-userguide-v2100.pdf", "_blank", "noopener,noreferrer");
      };
    }

    const logoutBtn = document.getElementById("btn-logout") as HTMLButtonElement | null;
    if (logoutBtn) {
      logoutBtn.onclick = async () => {
        if (!canSafelyLogout()) return;
        const ok = window.confirm("Log out of Internet Identity on this device?");
        if (!ok) return;

        logoutBtn.disabled = true;
        const prev = logoutBtn.textContent;
        logoutBtn.textContent = "Logging out";

        try {
          await logoutICPP();
        } finally {
          logoutBtn.textContent = prev || "Logout";
          updateLogoutEnabled();
        }
      };
    }
  }

  renderSidePanel();

  document
    .querySelectorAll<HTMLButtonElement>(".app-nav-main button[data-tab]")
    .forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === currentTab);

      if (
        !isSetupComplete &&
        (btn.dataset.tab === "send" || btn.dataset.tab === "receive" || btn.dataset.tab === "withdraw")
      ) {
        btn.disabled = true;
      } else if (isSetupComplete && btn.dataset.tab === "access") {
        btn.disabled = true;
      } else {
        btn.disabled = false;
      }
    });

  if (currentTab === "access") renderSetupCard();
  else if (currentTab === "send") renderSendCard();
  else if (currentTab === "receive") renderReceiveCard();
  else if (currentTab === "withdraw") renderWithdrawCard();

  updateLogoutEnabled();

}

// Expiration handling
// -------------------
if (typeof window !== "undefined") {
  window.addEventListener("icpp:session_expired", () => {
    // Logout and idle-expiry 
    // identically treated
    // ----------------------
    resetSessionState();
    render();
  });
}

if (typeof window !== "undefined") {
  installDesktopOnlyGuard();

  // Prevent accidental loss of context 
  // while an operation is in-flight
  // ----------------------------------
  window.addEventListener("beforeunload", (e) => {
    const inFlight = sendInProgress || recvScanInProgress || processingId !== null || withdrawInProgress;
    if (!inFlight) return;

    e.preventDefault();
    (e as any).returnValue = "";
  });
}

render();