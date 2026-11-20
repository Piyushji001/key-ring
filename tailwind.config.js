/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // Every colour is a CSS variable so that the locked/unlocked warming and
      // the light theme are pure CSS - no React re-render, no class swapping.
      // See src/styles/tokens.css and UI Spec section 2.
      colors: {
        void: "var(--kr-void)",
        panel: "var(--kr-panel)",
        "panel-hi": "var(--kr-panel-hi)",
        edge: "var(--kr-edge)",
        "edge-strong": "var(--kr-edge-strong)",
        text: "var(--kr-text)",
        "text-dim": "var(--kr-text-dim)",
        "text-faint": "var(--kr-text-faint)",
        accent: "var(--kr-accent)",
        "accent-hi": "var(--kr-accent-hi)",
        "accent-dim": "var(--kr-accent-dim)",
        danger: "var(--kr-danger)",
        ok: "var(--kr-ok)",
        warn: "var(--kr-warn)",
      },
      fontFamily: {
        ui: ["Inter", "Segoe UI Variable", "Segoe UI", "system-ui", "sans-serif"],
        data: ["JetBrains Mono", "Cascadia Mono", "Consolas", "ui-monospace", "monospace"],
      },
      fontSize: {
        xs: ["11px", "16px"],
        sm: ["13px", "20px"],
        base: ["14px", "22px"],
        lg: ["16px", "24px"],
        xl: ["20px", "28px"],
        "2xl": ["28px", "36px"],
      },
      borderRadius: {
        control: "6px",
        panel: "10px",
        overlay: "14px",
        tag: "4px",
      },
    },
  },
  plugins: [],
};
