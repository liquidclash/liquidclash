import { Box, MenuItem, Select } from '@mui/material'
import React, { useRef } from 'react'
import { useTranslation } from 'react-i18next'

import { DialogRef, Switch, TooltipIcon } from '@/components/base'
import ProxyControlSwitches from '@/components/shared/proxy-control-switches'
import { useSystemState } from '@/hooks/use-system-state'
import { useVerge } from '@/hooks/use-verge'
import { getMacosKillSwitchStatus } from '@/services/cmds'
import { useQuery } from '@/services/query-client'
import getSystem from '@/utils/get-system'

import { GuardState } from './mods/guard-state'
import { SettingList, SettingItem } from './mods/setting-comp'
import { SysproxyViewer } from './mods/sysproxy-viewer'
import { TunViewer } from './mods/tun-viewer'

const OS = getSystem()

interface Props {
  onError?: (err: Error) => void
}

const SettingSystem = ({ onError }: Props) => {
  const { t } = useTranslation()

  const { verge, mutateVerge, patchVerge } = useVerge()
  const { runState } = useSystemState()
  const {
    data: killSwitchStatus,
    refetch: refetchKillSwitchStatus,
  } = useQuery({
    queryKey: ['getMacosKillSwitchStatus'],
    queryFn: getMacosKillSwitchStatus,
    enabled: OS === 'macos',
    refetchInterval: 2000,
    refetchOnWindowFocus: true,
  })

  const {
    enable_auto_launch,
    enable_silent_start,
    enable_tun_mode,
    macos_kill_switch_mode,
  } = verge ?? {}

  const sysproxyRef = useRef<DialogRef>(null)
  const tunRef = useRef<DialogRef>(null)

  const onSwitchFormat = (
    _e: React.ChangeEvent<HTMLInputElement>,
    value: boolean,
  ) => value
  const onChangeData = (patch: Partial<IVergeConfig>) => {
    mutateVerge({ ...verge, ...patch }, false)
  }

  const killSwitchMode = macos_kill_switch_mode ?? 'disabled'
  const killSwitchSupported = killSwitchStatus?.supported === true
  const killSwitchStatusView = (() => {
    if (!killSwitchStatus) {
      return {
        color: 'text.secondary',
        text: t('settings.sections.system.status.killSwitch.checking'),
      }
    }
    if (!killSwitchStatus.capabilityAvailable) {
      return {
        color: 'error.main',
        text: t('settings.sections.system.status.killSwitch.unavailable'),
      }
    }
    if (!killSwitchSupported) {
      return {
        color: 'warning.main',
        text: t('settings.sections.system.status.killSwitch.updateService'),
      }
    }
    if (!killSwitchStatus.statusAvailable) {
      return {
        color: 'error.main',
        text: t('settings.sections.system.status.killSwitch.unavailable'),
      }
    }
    if (
      killSwitchStatus.mode !== killSwitchMode ||
      killSwitchStatus.wanted !== killSwitchStatus.live ||
      (killSwitchStatus.wanted && killSwitchStatus.mode === 'disabled')
    ) {
      return {
        color: 'error.main',
        text: t('settings.sections.system.status.killSwitch.unhealthy'),
      }
    }
    if (!killSwitchStatus.wanted) {
      return {
        color: 'text.secondary',
        text: t('settings.sections.system.status.killSwitch.off'),
      }
    }
    return {
      color: 'success.main',
      text: t(
        runState.mode === 'NotRunning'
          ? 'settings.sections.system.status.killSwitch.blocking'
          : 'settings.sections.system.status.killSwitch.protected',
      ),
    }
  })()

  return (
    <SettingList title={t('settings.sections.system.title')}>
      <SysproxyViewer ref={sysproxyRef} />
      <TunViewer ref={tunRef} />

      <ProxyControlSwitches
        label={t('settings.sections.system.toggles.tunMode')}
        onError={onError}
      />

      <ProxyControlSwitches
        label={t('settings.sections.system.toggles.systemProxy')}
        onError={onError}
      />

      {OS === 'macos' && (
        <SettingItem
          label={t('settings.sections.system.fields.killSwitch')}
          secondary={
            <Box component="span" sx={{ color: killSwitchStatusView.color }}>
              {killSwitchStatusView.text}
            </Box>
          }
          extra={
            <TooltipIcon
              title={t('settings.sections.system.tooltips.killSwitch')}
              sx={{ opacity: '0.7' }}
            />
          }
        >
          <GuardState
            value={killSwitchMode}
            onCatch={(error) => {
              onError?.(error)
              // Kill Switch intent is persisted before a Core restart. If that restart fails,
              // GuardState rolls back its optimistic value; refresh once that rollback completes.
              setTimeout(() => mutateVerge(), 0)
            }}
            onFormat={(e: React.ChangeEvent<{ value: unknown }>) =>
              e.target.value as 'disabled' | 'standard' | 'permanent'
            }
            onChange={(mode) =>
              onChangeData({ macos_kill_switch_mode: mode })
            }
            onGuard={async (mode) => {
              if (mode !== 'disabled' && !enable_tun_mode) {
                throw new Error(
                  t('settings.sections.system.notifications.killSwitch.requiresTun'),
                )
              }
              if (mode !== 'disabled' && !killSwitchSupported) {
                throw new Error(
                  t(
                    'settings.sections.system.notifications.killSwitch.requiresServiceUpdate',
                  ),
                )
              }
              try {
                await patchVerge({ macos_kill_switch_mode: mode })
              } finally {
                await refetchKillSwitchStatus()
              }
            }}
          >
            <Select
              disabled={
                killSwitchMode === 'disabled' &&
                (!enable_tun_mode || !killSwitchSupported)
              }
              size="small"
              sx={{ width: 160 }}
            >
              <MenuItem value="disabled">
                {t('settings.sections.system.options.killSwitch.disabled')}
              </MenuItem>
              <MenuItem
                disabled={!enable_tun_mode || !killSwitchSupported}
                value="standard"
              >
                {t('settings.sections.system.options.killSwitch.standard')}
              </MenuItem>
              <MenuItem
                disabled={!enable_tun_mode || !killSwitchSupported}
                value="permanent"
              >
                {t('settings.sections.system.options.killSwitch.permanent')}
              </MenuItem>
            </Select>
          </GuardState>
        </SettingItem>
      )}

      <SettingItem label={t('settings.sections.system.fields.autoLaunch')}>
        <GuardState
          value={enable_auto_launch ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => {
            onChangeData({ enable_auto_launch: e })
          }}
          onGuard={async (e) => {
            try {
              // 先触发UI更新立即看到反馈
              onChangeData({ enable_auto_launch: e })
              await patchVerge({ enable_auto_launch: e })
              return Promise.resolve()
            } catch (error) {
              // 如果出错，恢复原始状态
              onChangeData({ enable_auto_launch: !e })
              return Promise.reject(error)
            }
          }}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>

      <SettingItem
        label={t('settings.sections.system.fields.silentStart')}
        extra={
          <TooltipIcon
            title={t('settings.sections.system.tooltips.silentStart')}
            sx={{ opacity: '0.7' }}
          />
        }
      >
        <GuardState
          value={enable_silent_start ?? false}
          valueProps="checked"
          onCatch={onError}
          onFormat={onSwitchFormat}
          onChange={(e) => onChangeData({ enable_silent_start: e })}
          onGuard={(e) => patchVerge({ enable_silent_start: e })}
        >
          <Switch edge="end" />
        </GuardState>
      </SettingItem>
    </SettingList>
  )
}

export default SettingSystem
