// Small DOM helpers. Text always goes in through text nodes, never as markup,
// so account names from a QR code can never inject markup.
const SVG_NS = "http://www.w3.org/2000/svg";

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return el;
}

const ICONS = {
  copy: ["M10.5 3.2V3A1.5 1.5 0 0 0 9 1.5H3A1.5 1.5 0 0 0 1.5 3v6A1.5 1.5 0 0 0 3 10.5h.2", "M7.3 5.5h5.4a.8.8 0 0 1 .8.8v5.4a.8.8 0 0 1-.8.8H7.3a.8.8 0 0 1-.8-.8V6.3a.8.8 0 0 1 .8-.8z"],
  check: ["M3 8.5l3.2 3.2L13 4.8"],
  next: ["M3 8h9M8.5 4l4 4-4 4"],
};

// setChildren replaces an element's content; arrays are flattened and empty
// values (null, false) are skipped, unlike the bare DOM method.
export function setChildren(el, ...children) {
  el.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
}

export function icon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONS[name]) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

export function announce(message) {
  const region = document.getElementById("announce");
  region.textContent = "";
  // A tick later so repeating the same message is still announced.
  setTimeout(() => { region.textContent = message; }, 30);
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    announce("Copying needs a secure connection. Open this page over HTTPS or on localhost.");
    return false;
  }
}

export function field(label, input, hint) {
  const id = input.id || "f-" + Math.random().toString(36).slice(2, 9);
  input.id = id;
  return h("div", { class: "field" }, h("label", { for: id }, label), input, hint ? h("p", { class: "hint" }, hint) : null);
}

export function textInput(props) {
  return h("input", { class: "input", autocomplete: "off", spellcheck: "false", ...props });
}

export function errorBox() {
  const box = h("div", { class: "error", role: "alert", hidden: true });
  box.show = (message) => { box.textContent = message; box.hidden = false; };
  box.clear = () => { box.hidden = true; box.textContent = ""; };
  return box;
}

export function openDialog(title, content, { onClose } = {}) {
  const dlg = h("dialog", { "aria-label": title });
  const close = () => dlg.close();
  const head = h("div", { class: "dlg-head" }, h("h2", null, title), h("button", { class: "btn link", type: "button", onclick: close }, "Close"));
  dlg.append(h("div", { class: "dlg" }, head, content));
  dlg.addEventListener("close", () => {
    dlg.remove();
    if (onClose) onClose();
  });
  dlg.addEventListener("click", (event) => { if (event.target === dlg) close(); });
  document.body.append(dlg);
  dlg.showModal();
  return { el: dlg, close };
}

// groupCode shows 482913 as "482 913" and 12345678 as "1234 5678".
export function groupCode(code) {
  const half = Math.ceil(code.length / 2);
  return code.slice(0, half) + " " + code.slice(half);
}
