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
  width: 200px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  padding: 14px 10px 16px;
  box-sizing: border-box;
}
.tono-brand {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 6px;
  margin-bottom: 16px;
  height: 22px;
}
.tono-brand-name {
  font-size: 15px;
  font-weight: 600;
  flex: 1;
}
.tono-nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.tono-nav__item {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 7px 10px;
  border: none;
  border-radius: 8px;
  background: transparent;
  font-family: inherit;
  font-size: 13px;
  text-align: left;
  cursor: pointer;
}
.tono-nav__icon {
  width: 22px;
  display: flex;
  justify-content: center;
  flex-shrink: 0;
}
.tono-nav__icon svg {
  width: 15px;
  height: 15px;
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
  padding: 32px 12px;
}
.tono-page-title {
  font-size: 24px;
  font-weight: 600;
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
  transition: filter 0.15s ease, transform 0.1s ease, background 0.15s ease;
}
.tono-button:disabled {
  cursor: default;
  opacity: 0.55;
}
.tono-button:not(:disabled):active {
  transform: scale(0.98);
}
.tono-link {
  background: none;
  border: none;
  padding: 0;
  font-family: inherit;
  cursor: pointer;
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
`
