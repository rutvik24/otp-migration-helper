import { api } from "./api.js";
import { showCreate, showRecover, showRecoveryCode, showUnlock } from "./auth.js";
import { showMain } from "./main.js";
import { h, setChildren } from "./ui.js";

const app = document.getElementById("app");

function showFatal(message) {
  setChildren(app, h("div", { class: "stage" }, h("main", { class: "panel" },
    h("span", { class: "brand" }, "otpmh"),
    h("h1", null, "Can't continue"),
    h("p", { class: "lede" }, message),
    h("div", { class: "actions" }, h("button", { class: "btn solid big", type: "button", onclick: () => location.reload() }, "Reload")))));
}

async function route(options = {}) {
  let status;
  try {
    status = await api.get("/api/status");
  } catch (e) {
    showFatal(e.message);
    return;
  }
  if (!status.exists) {
    showCreate(app, status, { onCreated: created });
  } else if (!status.unlocked) {
    showUnlock(app, status, { onUnlocked: () => route(), onRecover: recover, notice: options.notice });
  } else {
    showMain(app, { mode: status.mode, onLocked: (notice) => route({ notice }) });
  }
}

function created(code) {
  if (!code) {
    route({ notice: "Vault created without recovery. Unlock it to continue." });
    return;
  }
  showRecoveryCode(app, code, { heading: "Save your recovery code", onDone: () => route({ notice: "Vault created. Unlock it to continue." }) });
}

function recover() {
  showRecover(app, {
    onBack: () => route(),
    onRecovered: (code) => showRecoveryCode(app, code, {
      heading: "Vault recovered. Save your new recovery code",
      onDone: () => route({ notice: "Unlock with your new credentials." }),
    }),
  });
}

route();
