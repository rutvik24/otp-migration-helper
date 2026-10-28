// Import: QR images, camera scans and pasted text all feed one list of decoded
// texts, in any order. The server merges them (including multi-QR exports)
// and the page shows what was found before anything is saved.
import { api } from "./api.js";
import { announce, h, openDialog } from "./ui.js";
import { cameraProblem, startScan } from "./scan.js";

export function openImport({ onSaved }) {
  const texts = [];
  let stopCamera = null;
  let preview = { accounts: [], warnings: [] };
  let notes = [];
  let busy = false;

  const status = h("p", { class: "hint", role: "status" });
  const found = h("div", { class: "found", "aria-live": "polite" });
  const video = h("video", { playsinline: true, "aria-label": "Camera preview" });
  video.muted = true;
  const cameraBox = h("div", { class: "camera", hidden: true }, video);
  const cameraButton = h("button", { class: "btn", type: "button" }, "Scan with camera");
  const files = h("input", { type: "file", accept: "image/*", multiple: true, class: "sr-only", id: "import-files" });
  const paste = h("textarea", { class: "input", rows: "3", "aria-label": "Decoded QR text", placeholder: "otpauth-migration://offline?data=… or otpauth://totp/…" });
  const save = h("button", { class: "btn solid big", type: "button", disabled: true }, "Save accounts");

  const drop = h("div", { class: "drop" },
    h("p", null, "Drop QR images here"),
    h("label", { class: "btn", for: "import-files" }, "Choose images"));

  // addTexts tries the new texts together with the ones already read, so a bad
  // one is rejected on its own without losing the rest.
  async function addTexts(incoming) {
    const fresh = [...new Set(incoming.map((t) => t.trim()).filter(Boolean))].filter((t) => !texts.includes(t));
    if (fresh.length === 0) return 0;
    let added = 0;
    for (const text of fresh) {
      try {
        const result = await api.post("/api/import/preview", { texts: [...texts, text] });
        texts.push(text);
        preview = result;
        added++;
      } catch (e) {
        notes.push(e.message);
      }
    }
    render();
    return added;
  }

  async function addImages(fileList) {
    if (busy) return;
    busy = true;
    status.textContent = "Reading images…";
    try {
      const form = new FormData();
      for (const file of fileList) form.append("image", file, file.name);
      const result = await api.upload("/api/decode-image", form);
      notes.push(...result.errors);
      const added = await addTexts(result.texts);
      announce(added ? "QR codes read" : "No new QR codes found");
    } catch (e) {
      notes.push(e.message);
      render();
    } finally {
      busy = false;
      status.textContent = "";
    }
  }

  function render() {
    const fresh = preview.accounts.filter((a) => !a.saved).length;
    const saved = preview.accounts.length - fresh;
    found.replaceChildren(
      notes.length ? h("p", { class: "error", role: "alert" }, notes.join(" ")) : null,
      preview.warnings.length ? h("p", { class: "notice" }, preview.warnings.join(". ") + ". Add the missing QR codes, or save what was read.") : null,
      preview.accounts.length
        ? h("div", null,
            h("h3", null, fresh + (fresh === 1 ? " new account" : " new accounts") + (saved ? ", " + saved + " already saved" : "")),
            h("ul", null, preview.accounts.map((a) => h("li", null, a.label, h("span", null, a.saved ? "Already saved" : a.kind === "hotp" ? "Counter-based" : "Time-based")))))
        : h("p", { class: "hint" }, "Nothing read yet."));
    save.disabled = fresh === 0;
    save.textContent = fresh ? "Save " + fresh + (fresh === 1 ? " account" : " accounts") : "Save accounts";
    notes = [];
  }

  async function toggleCamera() {
    if (stopCamera) {
      stopCamera();
      stopCamera = null;
      cameraBox.hidden = true;
      cameraButton.textContent = "Scan with camera";
      return;
    }
    cameraBox.hidden = false;
    cameraButton.textContent = "Stop camera";
    status.textContent = "Starting camera…";
    try {
      stopCamera = await startScan(video, (text) => {
        if (!texts.includes(text.trim())) addTexts([text]);
      });
      status.textContent = "Point the camera at a QR code. Scan each code of a multi-code export in turn.";
    } catch (e) {
      cameraBox.hidden = true;
      cameraButton.textContent = "Scan with camera";
      status.textContent = "";
      notes.push(cameraProblem(e));
      render();
    }
  }

  files.addEventListener("change", () => { if (files.files.length) addImages([...files.files]); files.value = ""; });
  drop.addEventListener("dragover", (event) => { event.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("over");
    if (event.dataTransfer.files.length) addImages([...event.dataTransfer.files]);
  });
  cameraButton.addEventListener("click", toggleCamera);
  const addPasted = h("button", { class: "btn", type: "button" }, "Add text");
  addPasted.addEventListener("click", async () => {
    const parts = paste.value.split(/\s+/).filter(Boolean);
    if (parts.length === 0) return;
    await addTexts(parts);
    paste.value = "";
  });

  save.addEventListener("click", async () => {
    save.disabled = true;
    try {
      const result = await api.post("/api/import/commit", { texts });
      announce(result.added + " accounts saved");
      dlg.close();
      onSaved();
    } catch (e) {
      notes.push(e.message);
      render();
    }
  });

  const dlg = openDialog("Import accounts", h("div", null,
    h("p", { class: "hint" }, "Read a Google Authenticator export with any mix of QR images, your camera, and pasted text. Nothing is saved until you choose Save."),
    drop, files,
    h("div", { class: "actions" }, cameraButton),
    cameraBox,
    h("div", { class: "field" }, h("label", { for: "paste-text" }, "Or paste decoded text"), paste, h("div", { class: "actions" }, addPasted)),
    status, found,
    h("div", { class: "actions" }, save)), { onClose: () => { if (stopCamera) stopCamera(); } });
  paste.id = "paste-text";
  render();
}
