import { h } from "./ui.js";

const KEY = "otpmh-theme";
const CHOICES = [["system", "System"], ["light", "Light"], ["dark", "Dark"]];

function apply(pref) {
  document.documentElement.setAttribute("data-theme", pref);
  try {
    localStorage.setItem(KEY, pref);
  } catch (e) {
    // Storage can be blocked; the choice then lasts until the page closes.
  }
}

// themeSwitch is the System / Light / Dark control. System follows the OS.
export function themeSwitch() {
  const current = document.documentElement.getAttribute("data-theme") || "system";
  const name = "theme-" + Math.random().toString(36).slice(2, 7);
  const items = CHOICES.map(([value, label]) =>
    h("label", null,
      h("input", { type: "radio", name, value, checked: value === current, onchange: () => apply(value) }),
      h("span", null, label)));
  return h("div", { class: "seg theme-seg", role: "radiogroup", "aria-label": "Theme" }, items);
}
