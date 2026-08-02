/*
 * Sync embedded BadZure attack-path graphs with the docs light/dark toggle.
 *
 * The reports honor prefers-color-scheme on their own, but the mkdocs-material
 * palette toggle is independent of the OS. This appends ?theme=light|dark to each
 * .bz-graph iframe to match the current site palette, and updates it when the
 * reader flips the toggle. Material sets data-md-color-scheme="slate" for dark.
 */
(function () {
  "use strict";

  function currentTheme() {
    const scheme = document.body.getAttribute("data-md-color-scheme");
    return scheme === "slate" ? "dark" : "light";
  }

  function applyTheme(theme) {
    document.querySelectorAll("iframe.bz-graph").forEach(function (frame) {
      const raw = frame.getAttribute("src");
      if (!raw) return;
      const url = new URL(raw, window.location.href);
      if (url.searchParams.get("theme") === theme) return;
      url.searchParams.set("theme", theme);
      // Assign relative form so we don't hard-code the origin into the DOM.
      frame.src = url.pathname + url.search;
    });
  }

  function init() {
    applyTheme(currentTheme());
    // React to palette toggles (Material rewrites the body attribute in place).
    const observer = new MutationObserver(function () {
      applyTheme(currentTheme());
    });
    observer.observe(document.body, {
      attributes: true,
      attributeFilter: ["data-md-color-scheme"],
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
