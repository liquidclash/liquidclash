// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { TonoUiState } from '@/services/tono'

vi.mock('@/services/states', () => ({ useThemeMode: () => 'dark' }))

import { ConnectPill } from './ConnectPill'

// No resources loaded: t() returns the key, which is what we assert on.
void i18n.use(initReactI18next).init({ resources: {}, lng: 'en' })

const renderPill = (uiState: TonoUiState, stageLabel?: string | null) => {
  const onConnect = vi.fn()
  const onDisconnect = vi.fn()
  render(
    <ConnectPill
      uiState={uiState}
      stageLabel={stageLabel}
      onConnect={onConnect}
      onDisconnect={onDisconnect}
    />,
  )
  return { onConnect, onDisconnect }
}

const pillButton = () => screen.getByRole('button')

afterEach(() => cleanup())

describe('ConnectPill five states', () => {
  it('notConnected: title, tap-to-connect subtitle, click connects', () => {
    const { onConnect, onDisconnect } = renderPill('notConnected')

    expect(screen.getByText('tono.pill.title.notConnected')).toBeDefined()
    expect(screen.getByText('tono.pill.subtitle.tapToConnect')).toBeDefined()
    expect((pillButton() as HTMLButtonElement).disabled).toBe(false)

    fireEvent.click(pillButton())
    expect(onConnect).toHaveBeenCalledTimes(1)
    expect(onDisconnect).not.toHaveBeenCalled()
  })

  it('connecting: title, backend stage label as subtitle, disabled', () => {
    const { onConnect, onDisconnect } = renderPill(
      'connecting',
      'Locking traffic…',
    )

    expect(screen.getByText('tono.pill.title.connecting')).toBeDefined()
    expect(screen.getByText('Locking traffic…')).toBeDefined()
    expect((pillButton() as HTMLButtonElement).disabled).toBe(true)

    fireEvent.click(pillButton())
    expect(onConnect).not.toHaveBeenCalled()
    expect(onDisconnect).not.toHaveBeenCalled()
  })

  it('connecting without a stage label falls back to the starting subtitle', () => {
    renderPill('connecting', null)

    expect(screen.getByText('tono.pill.subtitle.starting')).toBeDefined()
  })

  it('connected: title, tap-to-disconnect subtitle, click disconnects', () => {
    const { onConnect, onDisconnect } = renderPill('connected')

    expect(screen.getByText('tono.pill.title.connected')).toBeDefined()
    expect(
      screen.getByText('tono.pill.subtitle.tapToDisconnect'),
    ).toBeDefined()
    expect((pillButton() as HTMLButtonElement).disabled).toBe(false)

    fireEvent.click(pillButton())
    expect(onDisconnect).toHaveBeenCalledTimes(1)
    expect(onConnect).not.toHaveBeenCalled()
  })

  it('protectedOffline: title, tap-to-restore subtitle, click disconnects', () => {
    const { onConnect, onDisconnect } = renderPill('protectedOffline')

    expect(
      screen.getByText('tono.pill.title.protectedOffline'),
    ).toBeDefined()
    expect(screen.getByText('tono.pill.subtitle.tapToRestore')).toBeDefined()
    expect((pillButton() as HTMLButtonElement).disabled).toBe(false)

    fireEvent.click(pillButton())
    expect(onDisconnect).toHaveBeenCalledTimes(1)
    expect(onConnect).not.toHaveBeenCalled()
  })

  it('disconnecting: title, restoring-access subtitle, disabled', () => {
    const { onConnect, onDisconnect } = renderPill('disconnecting')

    expect(screen.getByText('tono.pill.title.disconnecting')).toBeDefined()
    expect(
      screen.getByText('tono.pill.subtitle.restoringAccess'),
    ).toBeDefined()
    expect((pillButton() as HTMLButtonElement).disabled).toBe(true)

    fireEvent.click(pillButton())
    expect(onConnect).not.toHaveBeenCalled()
    expect(onDisconnect).not.toHaveBeenCalled()
  })
})
