// Runs before first paint so the page never flashes the wrong theme.
(function () {
  var pref = "system";
  try {
    var saved = localStorage.getItem("otpmh-theme");
    if (saved === "light" || saved === "dark" || saved === "system") pref = saved;
  } catch (e) {
    // Storage can be blocked; the system theme is the default anyway.
  }
  document.documentElement.setAttribute("data-theme", pref);
})();
