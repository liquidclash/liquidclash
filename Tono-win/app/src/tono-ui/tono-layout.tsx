import { ThemeProvider } from '@mui/material'
import dayjs from 'dayjs'
import { useCallback, useEffect, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet, useLocation, useNavigate } from 'react-router'

import { BaseErrorBoundary } from '@/components/base'
import { NoticeManager } from '@/components/layout/notice-manager'
import {
  WindowControls,
  WindowResizeHandles,
} from '@/components/layout/window-controller'
import { useI18n } from '@/hooks/use-i18n'
import { useVerge } from '@/hooks/use-verge'
import { useWindowDecorations } from '@/hooks/use-window'
import {
  useCustomTheme,
  useLayoutEvents,
  useLoadingOverlay,
} from '@/pages/_layout/hooks'
import { TonoAuthGuard } from '@/pages/_layout/tono-auth-guard'
import { handleNoticeMessage } from '@/pages/_layout/utils'
import { useThemeMode } from '@/services/states'
import getSystem from '@/utils/get-system'

import { MeshBackground } from './MeshBackground'
import { TONO_CSS } from './styles'
import { TONO_FONT_STACK, tonoText } from './theme'
import { TonoSidebar } from './TonoSidebar'

import 'dayjs/locale/ru'
import 'dayjs/locale/zh-cn'

const OS = getSystem()

/**
 * The Tono application shell: frosted window background, 200px sidebar,
 * custom titlebar on undecorated windows, and the existing auth guard. The
 * MUI ThemeProvider stays because the Advanced (legacy Clash Verge) pages
 * render MUI components.
 */
const TonoLayout = () => {
  const mode = useThemeMode()
  const isDark = mode !== 'light'
  const text = tonoText(isDark)
  const { t } = useTranslation()
  const { theme } = useCustomTheme()
  const { verge } = useVerge()
  const { language } = verge ?? {}
  const { switchLanguage } = useI18n()
  const navigate = useNavigate()
  const location = useLocation()
  const themeReady = useMemo(() => Boolean(theme), [theme])

  const windowControlsRef = useRef<any>(null)
  const { decorated } = useWindowDecorations()

  const isLoginRoute = location.pathname === '/login'

  useLoadingOverlay(themeReady)

  const handleNotice = useCallback(
    (payload: [string, string]) => {
      const [status, msg] = payload
      try {
        handleNoticeMessage(status, msg, t, navigate)
      } catch (error) {
        console.error('[通知处理] 失败:', error)
      }
    },
    [t, navigate],
  )

  useLayoutEvents(handleNotice)

  useEffect(() => {
    if (language) {
      dayjs.locale(language === 'zh' ? 'zh-cn' : language)
      switchLanguage(language)
    }
  }, [language, switchLanguage])

  if (!themeReady) {
    return (
      <div
        style={{
          width: '100vw',
          height: '100vh',
          background: mode === 'light' ? '#fff' : '#181a1b',
        }}
      />
    )
  }

  return (
    <ThemeProvider theme={theme}>
      <NoticeManager position={verge?.notice_position} />
      <style>{TONO_CSS}</style>
      <div
        className={`tono-root ${OS}`}
        style={{ fontFamily: TONO_FONT_STACK, color: text.primary }}
      >
        <MeshBackground dark={isDark} />

        {decorated === false && (
          <>
            <WindowResizeHandles />
            <div className="tono-titlebar" data-tauri-drag-region="true">
              <WindowControls ref={windowControlsRef} />
            </div>
          </>
        )}

        <TonoAuthGuard>
          <div className="tono-shell">
            {!isLoginRoute && <TonoSidebar />}
            <main className="tono-main">
              <BaseErrorBoundary>
                <Outlet />
              </BaseErrorBoundary>
            </main>
          </div>
        </TonoAuthGuard>
      </div>
    </ThemeProvider>
  )
}

export default TonoLayout
