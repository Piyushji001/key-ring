import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed port and no browser auto-open.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: false,
    watch: {
      // The Rust side has its own watcher.
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    // WebView2 on Windows 10/11 is modern; no legacy transpilation needed.
    target: "chrome110",
    minify: "esbuild",
    // No source maps in the shipped bundle. They make the UI easier to read
    // for anyone poking at an installed copy, and buy us nothing.
    sourcemap: false,
  },
});
