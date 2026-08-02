/**
 * Global CSS for the Tono shell and pages: layout classes, the spinner
 * keyframes, and shared form/control styles. Anything theme- or state-aware
 * (colors, tints) stays inline in the components.
 */
export const TONO_CSS = `
.tono-root {
  position: relative;
  width: 100vw;
  height: 100vh;
  overflow: hidden;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}
.tono-shell {
  position: relative;
  z-index: 1;
  display: flex;
  height: 100%;
}
.tono-main {
  flex: 1;
  min-width: 0;
  overflow-y: auto;
  position: relative;
  scrollbar-gutter: stable;
}
.tono-main::-webkit-scrollbar {
  width: 8px;
}
.tono-main::-webkit-scrollbar-thumb {
  border: 2px solid transparent;
  border-radius: 999px;
  background: rgba(128, 138, 164, 0.35);
  background-clip: padding-box;
}
.tono-titlebar {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 32px;
  z-index: 20;
  display: flex;
  align-items: flex-start;
  justify-content: flex-end;
}

/* Sidebar */
.tono-sidebar {
  width: 190px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  padding: 18px 12px;
  box-sizing: border-box;
  backdrop-filter: blur(12px) saturate(1.08);
  -webkit-backdrop-filter: blur(12px) saturate(1.08);
}
.tono-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 10px;
  margin-bottom: 22px;
  height: 30px;
}
.tono-brand-name {
  font-size: 17px;
  font-weight: 650;
  letter-spacing: -0.25px;
  flex: 1;
}
.tono-nav {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.tono-nav__item {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  min-height: 40px;
  padding: 9px 11px;
  border: none;
  border-radius: 11px;
  background: transparent;
  font-family: inherit;
  font-size: 13px;
  line-height: 1.2;
  text-align: left;
  cursor: pointer;
  transition: background 0.16s ease, color 0.16s ease, box-shadow 0.16s ease;
}
.tono-nav__item:not([aria-current="page"]):hover {
  background: rgba(128, 140, 170, 0.11) !important;
}
.tono-nav__item:focus-visible,
.tono-button:focus-visible,
.tono-link:focus-visible,
.tono-pill:focus-visible,
.tono-server-card:focus-visible {
  outline: 2px solid rgba(75, 110, 255, 0.9);
  outline-offset: 2px;
}
.tono-nav__icon {
  width: 20px;
  display: flex;
  justify-content: center;
  flex-shrink: 0;
}
.tono-nav__icon svg {
  width: 16px;
  height: 16px;
}
.tono-nav__spacer {
  flex: 1;
}
.tono-advanced__items {
  padding-left: 12px;
}

/* Spinner */
.tono-spin {
  display: inline-block;
  animation: tono-rotate 0.8s linear infinite;
}
@keyframes tono-rotate {
  to {
    transform: rotate(360deg);
  }
}

/* Pages */
.tono-page {
  min-height: 100%;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  padding: 48px 40px 36px;
}
.tono-page-title {
  font-size: 26px;
  font-weight: 650;
  line-height: 1.2;
  letter-spacing: -0.5px;
  margin: 0;
}

/* Shared controls */
.tono-input {
  width: 100%;
  box-sizing: border-box;
  padding: 12px 14px;
  border-radius: 12px;
  font-family: inherit;
  font-size: 14px;
  outline: none;
  transition: border-color 0.15s ease, background 0.15s ease;
}
.tono-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  border: none;
  border-radius: 12px;
  font-family: inherit;
  font-weight: 600;
  cursor: pointer;
  min-height: 36px;
  transition: filter 0.15s ease, transform 0.1s ease, background 0.15s ease, box-shadow 0.15s ease;
}
.tono-button:disabled {
  cursor: default;
  opacity: 0.55;
}
.tono-button:not(:disabled):active {
  transform: scale(0.98);
}
.tono-button:not(:disabled):hover {
  filter: brightness(1.06);
}
.tono-link {
  background: none;
  border: none;
  padding: 0;
  font-family: inherit;
  cursor: pointer;
  border-radius: 7px;
  transition: color 0.15s ease, background 0.15s ease;
}

/* Dashboard */
.tono-dashboard {
  height: 100vh;
  padding-top: 42px;
}
.tono-dashboard__content {
  flex: 1 1 auto;
  width: 100%;
  min-height: 0;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 18px;
  padding: 24px 0;
}
.tono-pill:not(:disabled):hover {
  transform: translateY(-2px);
}
.tono-pill:not(:disabled):active {
  transform: translateY(0) scale(0.99);
}
.tono-server-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 12px;
}
.tono-server-card {
  transition: transform 0.16s ease, background 0.16s ease, border-color 0.16s ease, box-shadow 0.16s ease;
}
.tono-server-card:not(:disabled):hover {
  transform: translateY(-1px);
  box-shadow: 0 12px 28px -22px rgba(30, 45, 90, 0.6);
}

/* Settings rows */
.tono-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 0;
}
.tono-row + .tono-row {
  border-top: 1px solid rgba(142, 142, 147, 0.18);
}

/* Native range slider, Tono flavored */
.tono-range {
  -webkit-appearance: none;
  appearance: none;
  width: 140px;
  height: 4px;
  border-radius: 2px;
  outline: none;
}
.tono-range::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: #ffffff;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
  cursor: pointer;
}
.tono-range::-moz-range-thumb {
  width: 14px;
  height: 14px;
  border: none;
  border-radius: 50%;
  background: #ffffff;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
  cursor: pointer;
}

@media (max-width: 760px) {
  .tono-sidebar {
    width: 168px;
    padding-inline: 10px;
  }
  .tono-page {
    padding: 44px 24px 28px;
  }
}

@media (max-height: 680px) {
  .tono-page {
    padding-top: 38px;
    padding-bottom: 24px;
  }
  .tono-dashboard__content {
    justify-content: flex-start;
    gap: 14px;
    padding-block: 16px;
  }
}

/* RDP, VM and accessibility mode: remove expensive compositing and non-essential motion. */
@media (prefers-reduced-motion: reduce) {
  .tono-root *,
  .tono-root *::before,
  .tono-root *::after {
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
    scroll-behavior: auto !important;
  }
  .tono-sidebar,
  .tono-glass-card,
  .tono-pill,
  .tono-button,
  .tono-server-card {
    backdrop-filter: none !important;
    -webkit-backdrop-filter: none !important;
  }
  .tono-pill:hover,
  .tono-server-card:hover {
    transform: none !important;
  }
}
`
