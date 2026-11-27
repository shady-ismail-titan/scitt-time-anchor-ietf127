(function () {
  "use strict";
  try {
    var stored = localStorage.getItem("scitt-color-scheme");
    if (stored === "light" || stored === "dark") {
      document.documentElement.dataset.theme = stored;
      var meta = document.querySelector('meta[name="color-scheme"]');
      if (meta) {
        meta.setAttribute("content", stored);
      }
    }
  } catch (_) {
    /* Storage access blocked; fall back to system prefers-color-scheme */
  }
})();
