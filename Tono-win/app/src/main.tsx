import './assets/styles/index.scss'

import { ResizeObserver } from '@juggle/resize-observer'
import { ComposeContextProvider } from 'foxact/compose-context-provider'
import React from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from 'react-router'
import { SWRConfig } from 'swr'
import { MihomoWebSocket } from 'tauri-plugin-mihomo-api'

import { BaseErrorBoundary } from './components/base/base-error-boundary'
import { router } from './pages/_routers'
import { WindowProvider } from './providers/window'
import { FALLBACK_LANGUAGE, initializeLanguage } from './services/i18n'
import {
  preloadAppData,
  resolveThemeMode,
  getPreloadConfig,
} from './services/preload'
import { swrConfig } from './services/query-client'
import {
  LoadingCacheProvider,
  ThemeModeProvider,
  UpdateStateProvider,
} from './services/states'
import { disableWebViewShortcuts } from './utils/disable-webview-shortcuts'

if (!window.ResizeObserver) {
  window.ResizeObserver = ResizeObserver
}

const mainElementId = 'root'
const APP_BOOTSTRAP_BUDGET_MS = 2000
const APP_BOOTSTRAP_TIMEOUT_MESSAGE =
  'initial App IPC/language preload timed out'
const container = document.getElementById(mainElementId)

if (!container) {
  throw new Error(`No container '${mainElementId}' found to render application`)
}

disableWebViewShortcuts()

let appInitialized = false
let pendingAppData: ReturnType<typeof preloadAppData> | null = null
const initializeApp = (initialThemeMode: 'light' | 'dark') => {
  if (appInitialized) return
  appInitialized = true
  const contexts = [
    <ThemeModeProvider key="theme" initialState={initialThemeMode} />,
    <LoadingCacheProvider key="loading" />,
    <UpdateStateProvider key="update" />,
  ]

  const root = createRoot(container)
  root.render(
    <React.StrictMode>
      <ComposeContextProvider contexts={contexts}>
        <BaseErrorBoundary>
          <SWRConfig value={swrConfig}>
            <WindowProvider>
              <RouterProvider router={router} />
            </WindowProvider>
          </SWRConfig>
        </BaseErrorBoundary>
      </ComposeContextProvider>
    </React.StrictMode>,
  )
}

const bootstrap = async () => {
  const appDataPromise = preloadAppData()
  pendingAppData = appDataPromise
  const deadline = new Promise<never>((_, reject) => {
    window.setTimeout(
      () => reject(new Error(APP_BOOTSTRAP_TIMEOUT_MESSAGE)),
      APP_BOOTSTRAP_BUDGET_MS,
    )
  })

  const { initialThemeMode } = await Promise.race([appDataPromise, deadline])
  initializeApp(initialThemeMode)
}

bootstrap().catch((error) => {
  console.error(
    '[main.tsx] App bootstrap failed, falling back to default language:',
    error,
  )
  // Render immediately after the deadline. Language modules and the original IPC preload keep
  // resolving in the background; i18next will notify mounted consumers when resources arrive.
  initializeApp(resolveThemeMode(getPreloadConfig()))
  const fallbackLanguage = initializeLanguage(FALLBACK_LANGUAGE).catch(
    (fallbackError) => {
      console.error(
        '[main.tsx] Fallback language initialization failed:',
        fallbackError,
      )
    },
  )
  // When only the deadline fired, preserve the user's eventual language. Re-apply it after the
  // fallback load so completion order cannot leave a slow English/etc. preload overwritten by zh.
  if (
    error instanceof Error &&
    error.message === APP_BOOTSTRAP_TIMEOUT_MESSAGE &&
    pendingAppData
  ) {
    void pendingAppData
      .then(async ({ initialLanguage }) => {
        await fallbackLanguage
        await initializeLanguage(initialLanguage)
      })
      .catch((lateError) => {
        console.error('[main.tsx] Late App preload failed:', lateError)
      })
  }
})

// Error handling
window.addEventListener('error', (event) => {
  console.error('[main.tsx] Global error:', event.error)
})

window.addEventListener('unhandledrejection', (event) => {
  console.error('[main.tsx] Unhandled promise rejection:', event.reason)
})

// Page close/refresh events
window.addEventListener('beforeunload', () => {
  // Clean up all WebSocket instances to prevent memory leaks
  MihomoWebSocket.cleanupAll()
})

// Page loaded event
window.addEventListener('DOMContentLoaded', () => {
  // Clean up all WebSocket instances to prevent memory leaks
  MihomoWebSocket.cleanupAll()
})
