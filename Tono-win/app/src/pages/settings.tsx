import ContentCopyRoundedIcon from '@mui/icons-material/ContentCopyRounded'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useI18n } from '@/hooks/use-i18n'
import { useVerge } from '@/hooks/use-verge'
import { supportedLanguages } from '@/services/i18n'
import { showNotice } from '@/services/notice-service'
import { setCacheData, useQuery } from '@/services/query-client'
import { useThemeMode } from '@/services/states'
import {
  tonoAuditEnabled,
  tonoAuditLogPath,
  tonoSetAuditEnabled,
} from '@/services/tono'
import { GlassCard } from '@/tono-ui/GlassCard'
import {
  TONO_COLORS,
  TONO_MONO_STACK,
  setGlassTransparency,
  tonoText,
  useGlassTransparency,
} from '@/tono-ui/theme'
import { TonoAccountCard } from '@/tono-ui/TonoAccountCard'
import { TonoLogo } from '@/tono-ui/TonoLogo'
import { TonoToggle } from '@/tono-ui/TonoToggle'
import { version } from '@root/package.json'

const tonoAuditEnabledQueryKey = ['tonoAuditEnabled'] as const
const tonoAuditLogPathQueryKey = ['tonoAuditLogPath'] as const

const LANGUAGE_LABELS: Record<string, string> = {
  en: 'English',
  ru: 'Русский',
  zh: '简体中文',
  fa: 'فارسی',
  tt: 'Татар',
  id: 'Bahasa Indonesia',
  ar: 'العربية',
  ko: '한국어',
  tr: 'Türkçe',
  de: 'Deutsch',
  es: 'Español',
  jp: '日本語',
  zhtw: '繁體中文',
}

const CardHeader = ({
  icon,
  title,
  tint,
}: {
  icon: string
  title: string
  tint: string
}) => {
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
      <span
        aria-hidden
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 36,
          height: 36,
          borderRadius: 10,
          fontSize: 18,
          background: tint,
          flexShrink: 0,
        }}
      >
        {icon}
      </span>
      <span style={{ fontSize: 15, fontWeight: 600, color: text.primary }}>
        {title}
      </span>
    </div>
  )
}

const Row = ({
  label,
  subtitle,
  children,
}: {
  label: string
  subtitle?: string
  children?: React.ReactNode
}) => {
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  return (
    <div className="tono-row">
      <span style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
        <span style={{ fontSize: 13, fontWeight: 500, color: text.primary }}>
          {label}
        </span>
        {subtitle && (
          <span style={{ fontSize: 11, color: text.secondary }}>{subtitle}</span>
        )}
      </span>
      {children}
    </div>
  )
}

const GeneralCard = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const { verge, mutateVerge, patchVerge } = useVerge()
  const { switchLanguage } = useI18n()

  const { data: auditEnabled } = useQuery({
    queryKey: tonoAuditEnabledQueryKey,
    queryFn: tonoAuditEnabled,
  })
  const { data: auditLogInfo } = useQuery({
    queryKey: tonoAuditLogPathQueryKey,
    queryFn: tonoAuditLogPath,
  })
  const logPath = auditLogInfo?.path

  const handleAutostart = useLockFn(async (value: boolean) => {
    const previous = verge?.enable_auto_launch ?? false
    mutateVerge((prev) =>
      prev ? { ...prev, enable_auto_launch: value } : prev,
    )
    try {
      await patchVerge({ enable_auto_launch: value })
    } catch (error) {
      mutateVerge((prev) =>
        prev ? { ...prev, enable_auto_launch: previous } : prev,
      )
      showNotice.error(error instanceof Error ? error.message : String(error))
    }
  })

  const handleLanguage = useLockFn(async (language: string) => {
    try {
      await switchLanguage(language)
      await patchVerge({ language })
    } catch (error) {
      showNotice.error(error instanceof Error ? error.message : String(error))
    }
  })

  const handleAudit = useLockFn(async (value: boolean) => {
    const previous = auditEnabled ?? true
    setCacheData(tonoAuditEnabledQueryKey, value)
    try {
      await tonoSetAuditEnabled(value)
    } catch (error) {
      setCacheData(tonoAuditEnabledQueryKey, previous)
      showNotice.error(error instanceof Error ? error.message : String(error))
    }
  })

  const handleCopyPath = useLockFn(async () => {
    if (!logPath) return
    try {
      await navigator.clipboard.writeText(logPath)
      showNotice.success('settings.sections.tono.auditLog.copied')
    } catch (error) {
      console.warn('[Settings] copy to clipboard failed:', error)
      showNotice.error('settings.sections.tono.auditLog.copyFailed')
    }
  })

  return (
    <GlassCard>
      <CardHeader
        icon="⚙️"
        title={t('tono.settings.general.title')}
        tint={`${TONO_COLORS.accent}26`}
      />
      <Row label={t('tono.settings.general.launchAtStartup')}>
        <TonoToggle
          checked={verge?.enable_auto_launch ?? false}
          onChange={(value) => void handleAutostart(value)}
          label={t('tono.settings.general.launchAtStartup')}
        />
      </Row>
      <Row label={t('tono.settings.general.language')}>
        <select
          value={verge?.language ?? 'en'}
          onChange={(event) => void handleLanguage(event.target.value)}
          style={{
            fontFamily: 'inherit',
            fontSize: 12,
            padding: '6px 8px',
            borderRadius: 8,
            color: text.primary,
            background: dark ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.7)',
            border: `1px solid ${dark ? 'rgba(255,255,255,0.16)' : 'rgba(20,22,30,0.12)'}`,
          }}
        >
          {supportedLanguages.map((code) => (
            <option key={code} value={code}>
              {LANGUAGE_LABELS[code] ?? code}
            </option>
          ))}
        </select>
      </Row>
      <Row
        label={t('settings.sections.tono.auditLog.label')}
        subtitle={t('settings.sections.tono.auditLog.description')}
      >
        <TonoToggle
          checked={auditEnabled ?? true}
          onChange={(value) => void handleAudit(value)}
          label={t('settings.sections.tono.auditLog.label')}
        />
      </Row>
      <Row label={t('settings.sections.tono.auditLog.pathLabel')}>
        <span
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            maxWidth: 220,
          }}
        >
          <span
            style={{
              fontSize: 10,
              fontFamily: TONO_MONO_STACK,
              color: text.tertiary,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              direction: 'rtl',
            }}
            title={logPath ?? undefined}
          >
            {logPath ?? '—'}
          </span>
          <button
            type="button"
            className="tono-link"
            aria-label={t('settings.sections.tono.auditLog.copyPath')}
            title={t('settings.sections.tono.auditLog.copyPath')}
            disabled={!logPath}
            style={{ color: TONO_COLORS.accent, display: 'flex' }}
            onClick={handleCopyPath}
          >
            <ContentCopyRoundedIcon style={{ fontSize: 14 }} />
          </button>
        </span>
      </Row>
    </GlassCard>
  )
}

const ProxyEngineCard = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)

  return (
    <GlassCard>
      <CardHeader
        icon="🛡️"
        title={t('tono.settings.proxyEngine.title')}
        tint={`${TONO_COLORS.connected}26`}
      />
      <Row
        label={t('tono.settings.proxyEngine.tun')}
        subtitle={t('tono.settings.proxyEngine.tunSubtitle')}
      >
        <TonoToggle checked disabled label={t('tono.settings.proxyEngine.tun')} />
      </Row>
      <Row
        label={t('tono.settings.proxyEngine.allowLan')}
        subtitle={t('tono.settings.proxyEngine.allowLanSubtitle')}
      >
        <TonoToggle
          checked={false}
          disabled
          label={t('tono.settings.proxyEngine.allowLan')}
        />
      </Row>
      <Row label={t('tono.settings.proxyEngine.mixedPort')}>
        <span
          style={{
            fontSize: 12,
            fontFamily: TONO_MONO_STACK,
            color: text.secondary,
          }}
        >
          7890
        </span>
      </Row>
    </GlassCard>
  )
}

const AppearanceCard = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const { verge, patchVerge } = useVerge()
  const transparency = useGlassTransparency()
  const [slider, setSlider] = useState<number | null>(null)

  const themeMode = verge?.theme_mode ?? 'system'
  const sliderValue = slider ?? transparency

  const handleThemeMode = useLockFn(
    async (value: 'light' | 'dark' | 'system') => {
      try {
        await patchVerge({ theme_mode: value })
      } catch (error) {
        showNotice.error(error instanceof Error ? error.message : String(error))
      }
    },
  )

  const commitSlider = () => {
    if (slider !== null) {
      setGlassTransparency(slider)
      setSlider(null)
    }
  }

  return (
    <GlassCard>
      <CardHeader
        icon="🎨"
        title={t('tono.settings.appearance.title')}
        tint={`${TONO_COLORS.protectedOffline}26`}
      />
      <Row label={t('tono.settings.appearance.themeMode')}>
        <span
          style={{
            display: 'flex',
            borderRadius: 8,
            overflow: 'hidden',
            border: `1px solid ${dark ? 'rgba(255,255,255,0.16)' : 'rgba(20,22,30,0.12)'}`,
          }}
        >
          {(['light', 'dark', 'system'] as const).map((value) => (
            <button
              key={value}
              type="button"
              className="tono-link"
              onClick={() => void handleThemeMode(value)}
              style={{
                padding: '6px 10px',
                fontSize: 11,
                fontWeight: themeMode === value ? 600 : 400,
                color: themeMode === value ? '#fff' : text.secondary,
                background:
                  themeMode === value ? TONO_COLORS.accent : 'transparent',
              }}
            >
              {t(`tono.settings.appearance.theme.${value}`)}
            </button>
          ))}
        </span>
      </Row>
      <Row
        label={t('tono.settings.appearance.glass')}
        subtitle={t('tono.settings.appearance.glassSubtitle')}
      >
        <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <input
            type="range"
            className="tono-range"
            min={0}
            max={100}
            value={sliderValue}
            aria-label={t('tono.settings.appearance.glass')}
            onChange={(event) => setSlider(Number(event.target.value))}
            onPointerUp={commitSlider}
            onKeyUp={commitSlider}
            onBlur={commitSlider}
            style={{
              background: `linear-gradient(to right, ${TONO_COLORS.accent} 0%, ${TONO_COLORS.accent} ${sliderValue}%, rgba(142,142,147,0.35) ${sliderValue}%, rgba(142,142,147,0.35) 100%)`,
            }}
          />
          <span
            style={{
              fontSize: 11,
              fontFamily: TONO_MONO_STACK,
              color: text.secondary,
              width: 24,
              textAlign: 'right',
            }}
          >
            {sliderValue}
          </span>
        </span>
      </Row>
    </GlassCard>
  )
}

const AboutCard = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)

  return (
    <GlassCard
      style={{
        background: `linear-gradient(135deg, ${TONO_COLORS.accent}1A 0%, ${TONO_COLORS.protectedOffline}1A 100%), ${
          dark ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.4)'
        }`,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
        gap: 10,
        justifyContent: 'center',
      }}
    >
      <TonoLogo connected compact={false} size={56} />
      <span style={{ fontSize: 15, fontWeight: 600, color: text.primary }}>
        Tono v{version}
      </span>
      <span style={{ fontSize: 12, fontWeight: 500, color: text.secondary }}>
        {t('tono.settings.about.tagline')}
      </span>
      <span style={{ fontSize: 11, color: text.tertiary, maxWidth: 260 }}>
        {t('tono.settings.about.description')}
      </span>
    </GlassCard>
  )
}

const SettingPage = () => {
  const { t } = useTranslation()

  return (
    <div className="tono-page">
      <h1 className="tono-page-title" style={{ marginBottom: 18 }}>
        {t('tono.settings.title')}
      </h1>

      <div style={{ marginBottom: 24 }}>
        <TonoAccountCard />
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 24,
          alignItems: 'start',
        }}
      >
        <GeneralCard />
        <ProxyEngineCard />
        <AppearanceCard />
        <AboutCard />
      </div>
    </div>
  )
}

export default SettingPage
