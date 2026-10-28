// Screens shown before the vault is open: create, recovery code, unlock, recover.
import { api } from "./api.js";
import { announce, copyText, errorBox, field, h, textInput } from "./ui.js";

const MODES = [
  ["password", "Password"],
  ["ssh", "SSH key"],
  ["either", "Either"],
  ["both", "Both"],
];
const MODE_HINT = {
  password: "Unlock with a password you choose.",
  ssh: "Unlock with an SSH key on this computer.",
  either: "Unlock with the password or the SSH key, whichever is handy.",
  both: "Unlock only with the password and the SSH key together.",
};

const needsPassword = (mode) => mode === "password" || mode === "either" || mode === "both";
const needsKey = (mode) => mode === "ssh" || mode === "either" || mode === "both";

function stage(...children) {
  return h("div", { class: "stage" }, h("main", { class: "panel" }, h("span", { class: "brand" }, "otpmh"), ...children));
}

function modePicker(initial, onChange) {
  const name = "mode-" + Math.random().toString(36).slice(2, 7);
  const hint = h("p", { class: "hint" }, MODE_HINT[initial]);
  const items = MODES.map(([value, label]) =>
    h("label", null,
      h("input", { type: "radio", name, value, checked: value === initial, onchange: () => { hint.textContent = MODE_HINT[value]; onChange(value); } }),
      h("span", null, label)));
  return h("fieldset", null, h("legend", null, "Unlock with"), h("div", { class: "seg" }, items), hint);
}

// newCredentials builds the "choose how it unlocks" part shared by create and
// recover. It returns the element plus a getter for the entered values.
function newCredentials(initialMode) {
  let mode = initialMode;
  const holder = h("div");
  const password = textInput({ type: "password", autocomplete: "new-password" });
  const confirm = textInput({ type: "password", autocomplete: "new-password" });
  const publicKey = h("textarea", { class: "input", rows: "3", placeholder: "ssh-ed25519 AAAA… you@laptop" });

  function render() {
    holder.replaceChildren(
      needsPassword(mode) ? [field("Password", password), field("Confirm password", confirm)] : null,
      needsKey(mode) ? field("SSH public key", publicKey, "Paste the whole line from your .pub file, for example ~/.ssh/id_ed25519.pub. To unlock later you will point to the matching private key file.") : null,
    );
  }
  render();

  const root = h("div", null, modePicker(mode, (m) => { mode = m; render(); }), holder);
  return {
    root,
    values() {
      if (needsPassword(mode) && password.value !== confirm.value) throw new Error("The two passwords do not match.");
      return { mode, password: needsPassword(mode) ? password.value : "", sshPublicKey: needsKey(mode) ? publicKey.value.trim() : "" };
    },
  };
}

function recoveryPassphraseFields(label) {
  const pass = textInput({ type: "password", autocomplete: "new-password" });
  const confirm = textInput({ type: "password", autocomplete: "new-password" });
  return {
    root: h("div", null,
      field(label, pass, "At least 12 characters. You need this together with the recovery code."),
      field("Confirm " + label.toLowerCase(), confirm)),
    value() {
      if (pass.value !== confirm.value) throw new Error("The two recovery passphrases do not match.");
      return pass.value;
    },
  };
}

export function showCreate(app, status, { onCreated }) {
  const creds = newCredentials("password");
  const recovery = recoveryPassphraseFields("Recovery passphrase");
  const skip = h("input", { type: "checkbox", id: "skip-recovery" });
  const recoveryBlock = h("div", null, recovery.root);
  skip.addEventListener("change", () => { recoveryBlock.hidden = skip.checked; });
  const setup = textInput({ autocomplete: "off" });
  const error = errorBox();
  const submit = h("button", { class: "btn solid big", type: "submit" }, "Create vault");

  const form = h("form", { novalidate: true },
    creds.root,
    recoveryBlock,
    h("div", { class: "check" }, skip, h("label", { for: "skip-recovery" }, "Skip recovery. If I lose my password or key, the vault cannot be recovered.")),
    status.setupCodeRequired ? field("Setup code", setup, "Printed in the server's output when it started.") : null,
    error,
    h("div", { class: "actions" }, submit));

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.clear();
    try {
      const body = { ...creds.values(), noRecovery: skip.checked, setupCode: setup.value.trim() };
      if (!skip.checked) body.recoveryPassphrase = recovery.value();
      submit.disabled = true;
      const result = await api.post("/api/vault", body);
      onCreated(result.recoveryCode);
    } catch (e) {
      error.show(e.message);
    } finally {
      submit.disabled = false;
    }
  });

  app.replaceChildren(stage(
    h("h1", null, "Create your vault"),
    h("p", { class: "lede" }, "Your accounts stay on this device, encrypted. Choose how the vault unlocks."),
    form));
}

export function showRecoveryCode(app, code, { heading, onDone }) {
  const saved = h("input", { type: "checkbox", id: "saved" });
  const go = h("button", { class: "btn solid big", type: "button", disabled: true, onclick: onDone }, "Continue");
  saved.addEventListener("change", () => { go.disabled = !saved.checked; });
  const copy = h("button", { class: "btn", type: "button" }, "Copy code");
  copy.addEventListener("click", async () => {
    if (await copyText(code)) { copy.textContent = "Copied"; announce("Recovery code copied"); }
  });

  app.replaceChildren(stage(
    h("h1", null, heading),
    h("p", { class: "lede" }, "This code is shown once. Keep it somewhere safe, apart from your password. To recover the vault you need this code and your recovery passphrase."),
    h("div", { class: "recovery-code", "aria-label": "Recovery code" }, code),
    h("div", { class: "actions" }, copy),
    h("div", { class: "check" }, saved, h("label", { for: "saved" }, "I saved the recovery code and my recovery passphrase.")),
    h("div", { class: "actions" }, go)));
}

export function showUnlock(app, status, { onUnlocked, onRecover, notice }) {
  const mode = status.mode;
  let useKey = mode === "ssh" || mode === "both";
  const holder = h("div");
  const password = textInput({ type: "password", autocomplete: "current-password" });
  const keyPath = textInput({ placeholder: "~/.ssh/id_ed25519" });
  const keyPass = textInput({ type: "password", autocomplete: "off" });
  const error = errorBox();
  const submit = h("button", { class: "btn solid big", type: "submit" }, "Unlock");

  function render() {
    const parts = [];
    if (mode === "either") {
      const name = "via-" + Math.random().toString(36).slice(2, 7);
      parts.push(h("fieldset", null, h("legend", null, "Unlock with"), h("div", { class: "seg" },
        h("label", null, h("input", { type: "radio", name, checked: !useKey, onchange: () => { useKey = false; render(); } }), h("span", null, "Password")),
        h("label", null, h("input", { type: "radio", name, checked: useKey, onchange: () => { useKey = true; render(); } }), h("span", null, "SSH key")))));
    }
    if (mode === "password" || mode === "both" || (mode === "either" && !useKey)) parts.push(field("Password", password));
    if (mode === "ssh" || mode === "both" || (mode === "either" && useKey)) {
      parts.push(field("SSH private key file", keyPath, "The path to your private key on the machine running otpmh."));
      parts.push(field("Key passphrase", keyPass, "Only if your key has one."));
    }
    holder.replaceChildren(parts);
  }
  render();

  const form = h("form", { novalidate: true }, holder, error,
    h("div", { class: "actions" }, submit, h("button", { class: "btn link", type: "button", onclick: onRecover }, "Forgot your password or key?")));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.clear();
    submit.disabled = true;
    try {
      await api.post("/api/unlock", {
        password: password.value,
        sshIdentityPath: useKey ? keyPath.value : "",
        sshPassphrase: useKey ? keyPass.value : "",
      });
      password.value = "";
      keyPass.value = "";
      onUnlocked();
    } catch (e) {
      error.show(e.message);
    } finally {
      submit.disabled = false;
    }
  });

  app.replaceChildren(stage(
    h("h1", null, "Unlock your vault"),
    h("p", { class: "lede" }, "Enter what you chose when you created it."),
    notice ? h("p", { class: "notice" }, notice) : null,
    form));
  (password.isConnected ? password : keyPath).focus();
}

export function showRecover(app, { onBack, onRecovered }) {
  const code = textInput({ placeholder: "ABCD-EFGH-…" });
  const pass = textInput({ type: "password", autocomplete: "off" });
  const creds = newCredentials("password");
  const recovery = recoveryPassphraseFields("New recovery passphrase");
  const error = errorBox();
  const submit = h("button", { class: "btn solid big", type: "submit" }, "Recover vault");

  const form = h("form", { novalidate: true },
    field("Recovery code", code),
    field("Recovery passphrase", pass),
    h("h2", { class: "sub" }, "Set new credentials"),
    creds.root,
    recovery.root,
    error,
    h("div", { class: "actions" }, submit, h("button", { class: "btn link", type: "button", onclick: onBack }, "Back to unlock")));

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.clear();
    try {
      const body = { ...creds.values(), code: code.value.trim(), passphrase: pass.value, newRecoveryPassphrase: recovery.value() };
      submit.disabled = true;
      const result = await api.post("/api/recover", body);
      onRecovered(result.recoveryCode);
    } catch (e) {
      error.show(e.message);
    } finally {
      submit.disabled = false;
    }
  });

  app.replaceChildren(stage(
    h("h1", null, "Recover your vault"),
    h("p", { class: "lede" }, "You need the recovery code and the recovery passphrase. Recovery sets new credentials and re-encrypts your accounts."),
    form));
}

