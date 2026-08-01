import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate } from 'react-router'

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

  const navButton = (
    item: (typeof navItems)[number],
    key?: string,
  ) => {
    const active = isActive(item.path)
    return (
      <button
        key={key ?? item.path}
        type="button"
        className="tono-nav__item"
        onClick={() => navigate(item.path)}
        style={{
          background: active ? TONO_COLORS.accent : 'transparent',
          color: active ? '#FFFFFF' : text.primary,
          fontWeight: active ? 600 : 400,
        }}
      >
        <span className="tono-nav__icon">{item.icon[0]}</span>
        <span>{t(item.label)}</span>
      </button>
    )
  }

  return (
    <nav className="tono-sidebar">
      <div className="tono-brand">
        <TonoLogo connected={false} compact size={22} />
        <span className="tono-brand-name" style={{ color: text.primary }}>
          Tono
        </span>
      </div>

      <div className="tono-nav">{mainItems.map((item) => navButton(item))}</div>

      <div className="tono-nav__spacer" />

      {settingsItem && navButton(settingsItem, SETTINGS_PATH)}
    </nav>
  )
}
