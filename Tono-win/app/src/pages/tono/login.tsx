import { useLockFn } from 'ahooks'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'

import { useTonoStatus } from '@/hooks/use-tono'
import { useThemeMode } from '@/services/states'
import {
  tonoRetryRestore,
  tonoSignInStart,
  tonoSignInVerify,
} from '@/services/tono'
import { GlassCard } from '@/tono-ui/GlassCard'
import { TONO_COLORS, tonoText } from '@/tono-ui/theme'

const RESEND_COUNTDOWN = 60

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const errorMessage = (error: unknown) =>
  error instanceof Error ? error.message : String(error)

const ShieldIcon = ({
  size = 42,
  color = TONO_COLORS.accent,
}: {
  size?: number
  color?: string
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden>
    <path
      d="M12 2L4 5.5v5.6c0 4.9 3.4 9.5 8 10.4 4.6-.9 8-5.5 8-10.4V5.5L12 2z"
      stroke={color}
      strokeWidth="1.6"
      strokeLinejoin="round"
    />
    <path
      d="M12 8.5a3 3 0 0 1 3 3c0 1.2-.7 2.2-1.6 2.7L14 17h-4l.6-2.8A3 3 0 0 1 12 8.5z"
      fill={color}
    />
  </svg>
)

const LoginPage = () => {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const { status, mutateTonoStatus } = useTonoStatus()

  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [codeSent, setCodeSent] = useState(false)
  const [sending, setSending] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [retrying, setRetrying] = useState(false)
  const [verifySuspended, setVerifySuspended] = useState(false)
  const [suspendedDismissed, setSuspendedDismissed] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [countdown, setCountdown] = useState(0)

  useEffect(() => {
    if (countdown <= 0) return
    const timer = window.setTimeout(() => setCountdown((v) => v - 1), 1000)
    return () => window.clearTimeout(timer)
  }, [countdown])

  // A suspended account signed in on another path still lands here; the banner
  // can be dismissed to try a different email.
  const suspended =
    !suspendedDismissed &&
    (verifySuspended || status?.accountState === 'suspended')

  const restoreFailed = status?.accountState === 'error'

  const resetToStart = () => {
    setCodeSent(false)
    setCode('')
    setError(null)
  }

  const handleSendCode = useLockFn(async () => {
    const trimmed = email.trim()
    if (!EMAIL_PATTERN.test(trimmed)) {
      setError(t('tono.login.invalidEmail'))
      return
    }
    setSending(true)
    setError(null)
    try {
      await tonoSignInStart(trimmed)
      setCodeSent(true)
      // The challenge's `expiresIn` is the code's validity window (minutes),
      // not a resend cooldown — the resend cooldown stays a fixed 60s.
      setCountdown(RESEND_COUNTDOWN)
    } catch (error) {
      setError(errorMessage(error))
    } finally {
      setSending(false)
    }
  })

  const handleVerify = useLockFn(async () => {
    const trimmedCode = code.trim()
    if (!/^\d{6}$/.test(trimmedCode)) {
      setError(t('tono.login.invalidCode'))
      return
    }
    setVerifying(true)
    setError(null)
    try {
      const account = await tonoSignInVerify(email.trim(), trimmedCode)
      if (account.suspended) {
        setVerifySuspended(true)
        return
      }
      await mutateTonoStatus()
      navigate('/', { replace: true })
    } catch (error) {
      setError(errorMessage(error))
    } finally {
      setVerifying(false)
    }
  })

  const handleRetryRestore = useLockFn(async () => {
    setRetrying(true)
    setError(null)
    try {
      await tonoRetryRestore()
      await mutateTonoStatus()
    } catch (error) {
      setError(errorMessage(error))
    } finally {
      setRetrying(false)
    }
  })

  const inputStyle: React.CSSProperties = {
    background: dark ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.7)',
    border: `1px solid ${dark ? 'rgba(255,255,255,0.18)' : 'rgba(20,22,30,0.12)'}`,
    color: text.primary,
  }

  const primaryButtonStyle: React.CSSProperties = {
    width: '100%',
    padding: '12px 16px',
    fontSize: 14,
    color: '#fff',
    background: TONO_COLORS.accent,
  }

  if (suspended) {
    return (
      <div
        className="tono-page"
        style={{ alignItems: 'center', justifyContent: 'center' }}
      >
        <GlassCard
          style={{
            width: 470,
            maxWidth: '100%',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 18,
            padding: 32,
          }}
        >
          <ShieldIcon color={TONO_COLORS.error} />
          <h1 className="tono-page-title" style={{ color: text.primary }}>
            {t('tono.login.suspended.title')}
          </h1>
          <p style={{ margin: 0, fontSize: 13, color: text.secondary }}>
            {t('tono.login.suspended.description')}
          </p>
          <button
            type="button"
            className="tono-link"
            style={{ fontSize: 13, color: TONO_COLORS.accent }}
            onClick={() => {
              setSuspendedDismissed(true)
              setVerifySuspended(false)
              resetToStart()
            }}
          >
            {t('tono.login.changeEmail')}
          </button>
        </GlassCard>
      </div>
    )
  }

  return (
    <div
      className="tono-page"
      style={{ alignItems: 'center', justifyContent: 'center' }}
    >
      <GlassCard
        style={{
          width: 470,
          maxWidth: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'stretch',
          gap: 18,
          padding: 32,
        }}
      >
        {restoreFailed && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 10,
              borderRadius: 10,
              padding: '10px 12px',
              fontSize: 12,
              color: TONO_COLORS.error,
              background: `${TONO_COLORS.error}1F`,
            }}
          >
            <span>
              <strong>{t('tono.login.restoreFailed.title')}</strong>{' '}
              {t('tono.login.restoreFailed.description')}
            </span>
            <button
              type="button"
              className="tono-button"
              style={{
                padding: '6px 10px',
                fontSize: 12,
                color: '#fff',
                background: TONO_COLORS.error,
                flexShrink: 0,
              }}
              onClick={handleRetryRestore}
              disabled={retrying}
            >
              {retrying ? '…' : t('tono.login.restoreFailed.retry')}
            </button>
          </div>
        )}

        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 10,
            textAlign: 'center',
          }}
        >
          <ShieldIcon />
          <h1
            style={{
              margin: 0,
              fontSize: 28,
              fontWeight: 700,
              color: text.primary,
            }}
          >
            {t('tono.login.welcome')}
          </h1>
          <p style={{ margin: 0, fontSize: 13, color: text.secondary }}>
            {t('tono.login.intro')}
          </p>
        </div>

        <input
          className="tono-input"
          style={inputStyle}
          type="email"
          placeholder={t('tono.login.emailPlaceholder')}
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          disabled={sending || verifying || codeSent}
        />

        {!codeSent ? (
          <button
            type="button"
            className="tono-button"
            style={primaryButtonStyle}
            onClick={handleSendCode}
            disabled={sending}
          >
            {sending ? t('tono.login.sending') : t('tono.login.sendCode')}
          </button>
        ) : (
          <>
            <input
              className="tono-input"
              style={{
                ...inputStyle,
                textAlign: 'center',
                letterSpacing: 6,
                fontSize: 18,
              }}
              placeholder={t('tono.login.codePlaceholder')}
              value={code}
              maxLength={6}
              inputMode="numeric"
              onChange={(event) => setCode(event.target.value)}
              disabled={sending || verifying}
            />
            <button
              type="button"
              className="tono-button"
              style={primaryButtonStyle}
              onClick={handleVerify}
              disabled={sending || verifying}
            >
              {verifying ? t('tono.login.verifying') : t('tono.login.verify')}
            </button>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: 12,
              }}
            >
              <span style={{ color: text.tertiary }}>
                {t('tono.login.validity')}
              </span>
              <button
                type="button"
                className="tono-link"
                style={{
                  fontSize: 12,
                  color: countdown > 0 ? text.tertiary : TONO_COLORS.accent,
                  cursor: countdown > 0 ? 'default' : 'pointer',
                  flexShrink: 0,
                  marginLeft: 8,
                }}
                onClick={countdown > 0 ? undefined : handleSendCode}
                disabled={sending || countdown > 0}
              >
                {countdown > 0
                  ? t('tono.login.resendIn', { seconds: countdown })
                  : t('tono.login.sendNewCode')}
              </button>
            </div>
            <button
              type="button"
              className="tono-link"
              style={{
                fontSize: 12,
                color: text.secondary,
                alignSelf: 'center',
              }}
              onClick={resetToStart}
              disabled={sending || verifying}
            >
              {t('tono.login.changeEmail')}
            </button>
          </>
        )}

        {error && (
          <p
            role="alert"
            style={{
              margin: 0,
              fontSize: 12,
              textAlign: 'center',
              color: TONO_COLORS.error,
            }}
          >
            {error}
          </p>
        )}
        {codeSent && !error && (
          <p
            style={{
              margin: 0,
              fontSize: 12,
              textAlign: 'center',
              color: TONO_COLORS.latencyGood,
            }}
          >
            {t('tono.login.codeSent')}
          </p>
        )}
      </GlassCard>
    </div>
  )
}

export default LoginPage
