import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";

import App from "./App";
import { Overlay } from "./routes/Overlay";
import "./index.css";

/**
 * Respect the OS theme on first paint. The tokens file keys off data-theme, so
 * this is the only place the choice is made until Settings lands in Phase 8.
 */
const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
document.documentElement.dataset.theme = prefersLight ? "light" : "dark";

/**
 * Two windows share one bundle: the main app and the hotkey overlay. Which one
 * renders is decided by the window label, not by a route, because the overlay
 * is a separate OS window rather than a page the user navigates to.
 */
const label = (() => {
  try {
    return getCurrentWindow().label;
  } catch {
    return "main";
  }
})();

const isOverlay = label === "overlay";
if (isOverlay) {
  // The overlay window is transparent; the panel inside draws its own surface.
  document.documentElement.classList.add("kr-overlay-window");
}

const root = document.getElementById("root");
if (root) {
  ReactDOM.createRoot(root).render(
    <React.StrictMode>{isOverlay ? <Overlay /> : <App />}</React.StrictMode>,
  );
}
