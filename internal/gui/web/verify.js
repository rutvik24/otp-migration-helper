// "Confirm it's you": before a QR code, a secret or an export is shown, the
// vault's own credentials are asked for again.
import { api, ApiError } from "./api.js";
import { announce, errorBox, field, h, openDialog, setChildren, textInput } from "./ui.js";
import { keyInput } from "./keys.js";

const needsPassword = (mode) => mode === "password" || mode === "both" || mode === "either";
const needsKey = (mode) => mode === "ssh" || mode === "both" || mode === "either";

// credentialFields builds the inputs the vault's unlock mode asks for. In
// "either" mode the user picks which one to use.
export function credentialFields(mode) {
  let useKey = mode === "ssh" || mode === "both";
  const password = textInput({ type: "password", autocomplete: "current-password" });
  const key = keyInput();
  const holder = h("div");

  function render() {
    const parts = [];
    if (mode === "either") {
      const name = "via-" + Math.random().toString(36).slice(2, 7);
      parts.push(h("fieldset", null, h("legend", null, "Use"), h("div", { class: "seg" },
        h("label", null, h("input", { type: "radio", name, checked: !useKey, onchange: () => { useKey = false; render(); } }), h("span", null, "Password")),
        h("label", null, h("input", { type: "radio", name, checked: useKey, onchange: () => { useKey = true; render(); } }), h("span", null, "SSH key")))));
    }
    if (needsPassword(mode) && !(mode === "either" && useKey)) parts.push(field("Password", password));
    if (needsKey(mode) && !(mode === "either" && !useKey)) parts.push(key.root);
    setChildren(holder, parts);
  }
  render();

  return {
    root: holder,
    focus: () => (password.isConnected ? password : holder).focus(),
    values: () => ({ password: password.value, ...(useKey ? key.value() : {}) }),
    clear() {
      password.value = "";
      key.clear();
    },
  };
}

// confirmIdentity asks for the credentials and resolves true once the server
// accepts them, or false if the user closes the dialog.
export function confirmIdentity(mode) {
  return new Promise((resolve) => {
    const creds = credentialFields(mode);
    const error = errorBox();
    const submit = h("button", { class: "btn solid big", type: "submit" }, "Confirm");
    let confirmed = false;
    const form = h("form", { novalidate: true },
      h("p", { class: "hint" }, "Enter your credentials again before secrets are shown. This protects your vault if someone else is using this screen."),
      creds.root, error,
      h("div", { class: "actions" }, submit));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      error.clear();
      submit.disabled = true;
      try {
        await api.post("/api/reauth", creds.values());
        confirmed = true;
        creds.clear();
        announce("Confirmed");
        dlg.close();
      } catch (e) {
        error.show(e.message);
      } finally {
        submit.disabled = false;
      }
    });
    const dlg = openDialog("Confirm it's you", form, { onClose: () => { creds.clear(); resolve(confirmed); } });
  });
}

// withVerification runs an action that reveals secrets. If the server says the
// user must confirm first, it shows the dialog and then retries once.
export async function withVerification(mode, action) {
  try {
    return await action();
  } catch (e) {
    if (!(e instanceof ApiError) || e.status !== 403 || !(e.data && e.data.reauth)) throw e;
  }
  if (!(await confirmIdentity(mode))) throw new ApiError(0, "Cancelled. Nothing was shown.");
  return action();
}
