import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate } from 'react-router'

import { version as appVersion } from '@root/package.json'

import { navItems } from '@/pages/_navigation'
import { useThemeMode } from '@/services/states'

import { TONO_COLORS, tonoText } from './theme'
import { TonoLogo } from './TonoLogo'

/**
 * The Tono sidebar (SidebarView.swift): 200 wide, brand on top, Dashboard /
 * Nodes / Account in order, Settings pinned to the bottom.
 */

const SIDEBAR_MAIN_PATHS = ['/', '/servers', '/account']
const SETTINGS_PATH = '/settings'

export const TonoSidebar = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const location = useLocation()
  const navigate = useNavigate()

  const mainItems = navItems.filter(
    (item) => item.group === 'main' && SIDEBAR_MAIN_PATHS.includes(item.path),
  )
  const settingsItem = navItems.find((item) => item.path === SETTINGS_PATH)

  const isActive = (path: string) =>
    path === '/'
      ? location.pathname === '/'
      : location.pathname.startsWith(path)

  const navButton = (item: (typeof navItems)[number], key?: string) => {
    const active = isActive(item.path)
    return (
      <button
        key={key ?? item.path}
        type="button"
        className="tono-nav__item"
        aria-current={active ? 'page' : undefined}
        onClick={() => navigate(item.path)}
        style={{
          // Structural properties are duplicated inline on purpose: a real
          // machine was found running with no layout stylesheet applied,
          // where these buttons fell back to native chrome and the whole
          // navigation read as blank boxes. Inline wins even then.
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          width: '100%',
          minHeight: 40,
          padding: '9px 11px',
          border: 'none',
          borderRadius: 11,
          textAlign: 'left',
          cursor: 'pointer',
          fontFamily: 'inherit',
          fontSize: 13,
          background: active ? `${TONO_COLORS.accent}1F` : 'transparent',
          color: active ? (dark ? '#A9B7FF' : '#3453D5') : text.secondary,
          fontWeight: active ? 600 : 400,
          boxShadow: active
            ? `inset 0 0 0 1px ${TONO_COLORS.accent}2E`
            : 'none',
        }}
      >
        <span className="tono-nav__icon">{item.icon[0]}</span>
        <span>{t(item.label)}</span>
      </button>
    )
  }

  return (
    <nav
      className="tono-sidebar"
      style={{
        // See the note on the nav buttons: structural layout is inline so a
        // missing stylesheet cannot collapse the shell.
        width: 190,
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        padding: '18px 12px',
        boxSizing: 'border-box',
        background: dark ? 'rgba(8,11,19,0.58)' : 'rgba(248,250,255,0.56)',
        borderRight: `1px solid ${dark ? 'rgba(255,255,255,0.08)' : 'rgba(35,48,78,0.08)'}`,
      }}
    >
      <div className="tono-brand">
        <TonoLogo connected={false} compact size={22} />
        <span className="tono-brand-name" style={{ color: text.primary }}>
          Tono
        </span>
      </div>

      <div className="tono-nav">{mainItems.map((item) => navButton(item))}</div>

      <div className="tono-nav__spacer" />

      {settingsItem && navButton(settingsItem, SETTINGS_PATH)}

      {/* Support builds are identified from customer photos, so the running
          version has to be readable on screen without opening a menu. */}
      <div className="tono-sidebar__version" style={{ color: text.secondary }}>
        v{appVersion}
      </div>
    </nav>
  )
}
