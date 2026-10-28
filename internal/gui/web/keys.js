// The SSH key part of the unlock and confirm forms. The key is read here, in
// the browser, from an uploaded file or pasted text and sent with the request;
// the server never reads key files from its own disk and never stores the key.
import { field, h, textInput } from "./ui.js";

const MAX_KEY_BYTES = 64 * 1024;

export function keyInput() {
  const paste = h("textarea", { class: "input", rows: "4", spellcheck: "false", autocomplete: "off", placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----", "aria-label": "SSH private key" });
  const passphrase = textInput({ type: "password", autocomplete: "off" });
  const fileName = h("span", { class: "hint" });
  const picker = h("input", { type: "file", class: "sr-only", id: "key-file-" + Math.random().toString(36).slice(2, 8) });
  const choose = h("label", { class: "btn", for: picker.id }, "Upload key file");

  picker.addEventListener("change", async () => {
    const file = picker.files[0];
    picker.value = "";
    if (!file) return;
    if (file.size > MAX_KEY_BYTES) {
      fileName.textContent = file.name + " is too large to be an SSH key.";
      return;
    }
    paste.value = await file.text();
    fileName.textContent = "Loaded " + file.name;
  });

  const root = h("div", { class: "keybox" },
    h("div", { class: "field" }, h("span", { class: "label-like" }, "SSH private key"),
      h("div", { class: "actions tight" }, choose, picker, fileName),
      paste,
      h("p", { class: "hint" }, "Upload the key file or paste its text. It is used once to unlock and is never saved.")),
    field("Key passphrase", passphrase, "Only if your key has one."));

  return {
    root,
    value: () => ({ sshPrivateKey: paste.value, sshPassphrase: passphrase.value }),
    // Wipe what was typed so it does not linger in the page.
    clear() {
      paste.value = "";
      passphrase.value = "";
      fileName.textContent = "";
    },
  };
}
