// The main view: account list on the left, the selected account's code on the
// right, and one shared clock because every TOTP code changes together.
import { api } from "./api.js";
import { announce, copyText, groupCode, h, icon, openDialog } from "./ui.js";
import { themeSwitch } from "./theme.js";
import { openImport } from "./importer.js";

const PERIOD = 30;
const WARN_SECONDS = 5;
const IDLE_LOCK_MS = 5 * 60 * 1000;
const COPIED_MS = 2000;
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

export function showMain(app, { onLocked }) {
  const state = { accounts: [], selectedId: null, deadline: 0, copiedId: null, refreshing: false };
  let copiedTimer = 0;
  let warnTimer = 0;
  let railAnim = null;
  let lastInput = Date.now();

  const list = h("ul", { class: "side-list", role: "list", "aria-label": "Accounts" });
  const side = h("nav", { class: "side", "aria-label": "Accounts" }, list);
  const focus = h("section", { class: "focus-panel", "aria-label": "Selected account" });
  const railFill = h("i");
  const rail = h("div", { class: "rail", "aria-hidden": "true" }, railFill);
  const meta = h("p", { class: "meta", "aria-live": "off" });

  async function lock() {
    try {
      await api.post("/api/lock");
    } finally {
      cleanup();
      onLocked();
    }
  }

  const bar = h("header", { class: "bar" },
    h("span", { class: "brand" }, "otpmh"),
    h("span", { class: "vault" }, "Vault unlocked"),
    h("span", { class: "spacer" }),
    themeSwitch(),
    h("button", { class: "btn", type: "button", onclick: () => openImport({ onSaved: refresh }) }, "Import"),
    h("button", { class: "btn", type: "button", onclick: () => openExport() }, "Export"),
    h("button", { class: "btn", type: "button", onclick: () => openActivity() }, "Activity"),
    h("button", { class: "btn solid", type: "button", onclick: lock }, "Lock"));

  app.replaceChildren(h("div", { class: "app" }, bar, h("div", { class: "body" }, side, focus)));

  const selected = () => state.accounts.find((a) => a.id === state.selectedId) || null;

  // ---------- list ----------
  function renderList() {
    if (state.accounts.length === 0) {
      list.replaceChildren(h("li", { class: "empty" },
        h("p", null, "No accounts yet."),
        h("button", { class: "btn solid", type: "button", onclick: () => openImport({ onSaved: refresh }) }, "Import accounts")));
      return;
    }
    list.replaceChildren(state.accounts.map((a) => {
      const hotp = a.kind === "hotp";
      const done = state.copiedId === a.id;
      const action = hotp
        ? h("button", { class: "cp", type: "button", "aria-label": "Next code for " + a.label, onclick: () => nextCode(a) }, icon("next"), "Next")
        : h("button", { class: "cp" + (done ? " done" : ""), type: "button", "aria-label": "Copy code for " + a.label, onclick: () => copyCode(a) }, icon(done ? "check" : "copy"), done ? "Copied" : "Copy");
      return h("li", { class: "item" + (a.id === state.selectedId ? " sel" : "") },
        h("button", { class: "pick", type: "button", "aria-current": a.id === state.selectedId ? "true" : null, onclick: () => select(a.id) },
          h("b", null, a.issuer || a.name),
          h("small", null, groupCode(a.code), hotp ? h("small", { class: "note" }, " counter " + a.counter) : null)),
        action);
    }));
  }

  // ---------- focus panel ----------
  function renderFocus() {
    const a = selected();
    if (!a) {
      focus.replaceChildren(h("p", { class: "focus-empty" }, state.accounts.length ? "Choose an account to see its code." : "Import your accounts to see their codes here."));
      rail.hidden = true;
      return;
    }
    const hotp = a.kind === "hotp";
    rail.hidden = hotp;
    focus.replaceChildren(
      h("p", { class: "issuer" }, a.issuer || a.name),
      a.issuer ? h("p", { class: "name" }, a.name) : null,
      h("p", { class: "code", "aria-label": "Code " + a.code.split("").join(" ") }, groupCode(a.code)),
      meta,
      h("div", { class: "focus-actions" },
        h("button", { class: "btn light", type: "button", onclick: () => copyCode(a) }, "Copy code"),
        hotp ? h("button", { class: "btn", type: "button", onclick: () => nextCode(a) }, "Next code") : null,
        h("button", { class: "btn", type: "button", onclick: () => openQR(a) }, "Show QR"),
        h("button", { class: "btn", type: "button", onclick: () => openExport() }, "Export")),
      rail);
    updateMeta();
    startRail();
  }

  function updateMeta() {
    const a = selected();
    if (!a) return;
    if (a.kind === "hotp") {
      meta.textContent = "Counter " + a.counter + ". Press Next code to get the following one.";
      return;
    }
    const left = Math.max(0, Math.ceil((state.deadline - performance.now()) / 1000));
    meta.textContent = "New code in " + left + (left === 1 ? " second" : " seconds");
  }

  function startRail() {
    if (railAnim) railAnim.cancel();
    clearTimeout(warnTimer);
    rail.classList.remove("expiring");
    const left = Math.max(0, (state.deadline - performance.now()) / 1000);
    const from = left / PERIOD;
    if (reducedMotion.matches) {
      railFill.style.transform = "scaleX(" + from + ")";
    } else {
      railAnim = railFill.animate([{ transform: "scaleX(" + from + ")" }, { transform: "scaleX(0)" }], { duration: left * 1000, easing: "linear", fill: "forwards" });
    }
    const untilWarn = (left - WARN_SECONDS) * 1000;
    if (untilWarn <= 0) rail.classList.add("expiring");
    else warnTimer = setTimeout(() => rail.classList.add("expiring"), untilWarn);
  }

  // ---------- actions ----------
  function select(id) {
    state.selectedId = id;
    renderList();
    renderFocus();
  }

  async function copyCode(a) {
    if (!(await copyText(a.code))) return;
    state.copiedId = a.id;
    announce("Code copied");
    renderList();
    clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => { state.copiedId = null; renderList(); }, COPIED_MS);
  }

  async function nextCode(a) {
    try {
      await api.post("/api/accounts/" + a.id + "/next");
      await refresh();
      announce("Next code ready");
    } catch (e) {
      handleError(e);
    }
  }

  function handleError(e) {
    if (e.status === 401) {
      cleanup();
      onLocked(e.data && e.data.locked ? null : e.message);
      return;
    }
    announce(e.message);
    meta.textContent = e.message;
  }

  async function refresh() {
    if (state.refreshing) return;
    state.refreshing = true;
    try {
      const data = await api.get("/api/codes");
      state.accounts = data.accounts;
      state.deadline = performance.now() + data.secondsLeft * 1000;
      if (!selected()) state.selectedId = state.accounts.length ? state.accounts[0].id : null;
      renderList();
      renderFocus();
    } catch (e) {
      handleError(e);
    } finally {
      state.refreshing = false;
    }
  }

  // ---------- dialogs ----------
  function openQR(a) {
    const img = h("img", { src: "/api/accounts/" + a.id + "/qr.png", alt: "QR code to add " + a.label + " to another authenticator app", width: "300", height: "300" });
    const reveal = h("div");
    const showSecret = h("button", { class: "btn", type: "button" }, "Show secret and setup link");
    showSecret.addEventListener("click", async () => {
      try {
        const d = await api.get("/api/accounts/" + a.id + "/details");
        const copyLink = h("button", { class: "btn", type: "button" }, "Copy setup link");
        copyLink.addEventListener("click", async () => { if (await copyText(d.url)) copyLink.textContent = "Copied"; });
        reveal.replaceChildren(
          h("div", { class: "field" }, h("label", null, "Secret"), h("p", { class: "mono-val" }, d.secret)),
          h("div", { class: "actions" }, copyLink));
        showSecret.hidden = true;
      } catch (e) {
        reveal.replaceChildren(h("p", { class: "error", role: "alert" }, e.message));
      }
    });
    openDialog("Add " + (a.issuer || a.name) + " elsewhere", h("div", null,
      h("p", { class: "hint" }, "Scan this with another authenticator app. Anyone who can see it can create your codes, so close this when you are done."),
      h("div", { class: "qr-box" }, img),
      h("div", { class: "actions" }, showSecret),
      reveal));
  }

  const EXPORTS = [
    ["bitwarden", "Bitwarden (JSON)"],
    ["passwords-csv", "Passwords app and other CSV importers"],
    ["otpauth", "Plain otpauth:// list"],
  ];

  function openExport() {
    const name = "fmt-" + Math.random().toString(36).slice(2, 7);
    const chosen = { value: "bitwarden" };
    const understand = h("input", { type: "checkbox", id: "understand" });
    const go = h("button", { class: "btn solid big", type: "button", disabled: true }, "Download");
    const error = h("p", { class: "error", role: "alert", hidden: true });
    understand.addEventListener("change", () => { go.disabled = !understand.checked; });
    go.addEventListener("click", async () => {
      error.hidden = true;
      try {
        const blob = await api.blob("/api/export", { format: chosen.value, confirm: true });
        const link = h("a", { href: URL.createObjectURL(blob), download: fileName(chosen.value) });
        document.body.append(link);
        link.click();
        link.remove();
        announce("Export downloaded");
      } catch (e) {
        error.textContent = e.message;
        error.hidden = false;
      }
    });
    const options = EXPORTS.map(([value, label]) =>
      h("label", null, h("input", { type: "radio", name, value, checked: value === chosen.value, onchange: () => { chosen.value = value; } }), h("span", null, label)));
    openDialog("Export accounts", h("div", null,
      h("p", { class: "hint" }, "Download your accounts to import them into a password manager."),
      h("fieldset", null, h("legend", null, "Format"), h("div", { class: "seg" }, options)),
      h("p", { class: "notice" }, "This file is not encrypted. Anyone who gets it can create your codes. Delete it after importing."),
      h("div", { class: "check" }, understand, h("label", { for: "understand" }, "I understand the file is not encrypted.")),
      error,
      h("div", { class: "actions" }, go)));
  }

  function fileName(format) {
    return { bitwarden: "otpmh-bitwarden.json", "passwords-csv": "otpmh-passwords.csv", otpauth: "otpmh-otpauth.txt" }[format];
  }

  const ACTION_LABELS = {
    create: "Vault created", unlock: "Unlocked", unlock_failed: "Unlock failed", import: "Accounts imported",
    export: "Accounts exported", show_qr: "QR code shown", reveal: "Secret shown", recovery: "Vault recovered",
    recovery_failed: "Recovery failed", recovery_blocked: "Recovery blocked", show: "Accounts shown", live: "Live codes opened",
  };

  async function openActivity() {
    const body = h("div", null, h("p", { class: "hint" }, "Loading…"));
    openDialog("Activity", body);
    try {
      const data = await api.get("/api/log");
      const rows = data.entries.slice().reverse().map((e) =>
        h("tr", null, h("td", { class: "when" }, new Date(e.time).toLocaleString()), h("td", null, ACTION_LABELS[e.action] || e.action), h("td", null, e.detail)));
      body.replaceChildren(
        h("p", { class: "hint" }, "A local record of what happened in this vault. It never contains secrets or codes."),
        h("table", { class: "log" }, h("thead", null, h("tr", null, h("th", null, "When"), h("th", null, "What"), h("th", null, "Details"))), h("tbody", null, rows)));
    } catch (e) {
      body.replaceChildren(h("p", { class: "error", role: "alert" }, e.message));
    }
  }

  // ---------- timers and idle lock ----------
  const tick = setInterval(() => {
    updateMeta();
    if (state.deadline && performance.now() >= state.deadline) refresh();
    if (Date.now() - lastInput > IDLE_LOCK_MS) lock();
  }, 1000);
  const markActive = () => { lastInput = Date.now(); };
  const onVisible = () => { if (!document.hidden) refresh(); };
  for (const type of ["pointerdown", "keydown", "wheel", "touchstart"]) window.addEventListener(type, markActive, { passive: true });
  document.addEventListener("visibilitychange", onVisible);

  function cleanup() {
    clearInterval(tick);
    clearTimeout(copiedTimer);
    clearTimeout(warnTimer);
    if (railAnim) railAnim.cancel();
    for (const type of ["pointerdown", "keydown", "wheel", "touchstart"]) window.removeEventListener(type, markActive);
    document.removeEventListener("visibilitychange", onVisible);
  }

  refresh();
}
