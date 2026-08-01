import { TONO_COLORS, TONO_EASE } from './theme'

/**
 * A small native toggle in the macOS style (36×20 pill, accent when on).
 */

interface TonoToggleProps {
  checked: boolean
  disabled?: boolean
  onChange?: (checked: boolean) => void
  label?: string
}

export const TonoToggle = ({
  checked,
  disabled = false,
  onChange,
  label,
}: TonoToggleProps) => (
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    aria-label={label}
    disabled={disabled}
    onClick={() => onChange?.(!checked)}
    style={{
      position: 'relative',
      width: 36,
      height: 20,
      flexShrink: 0,
      border: 'none',
      borderRadius: 10,
      padding: 0,
      cursor: disabled ? 'default' : 'pointer',
      opacity: disabled ? 0.45 : 1,
      background: checked ? TONO_COLORS.connected : 'rgba(142,142,147,0.45)',
      transition: `background 0.22s ${TONO_EASE}`,
    }}
  >
    <span
      aria-hidden
      style={{
        position: 'absolute',
        top: 2,
        left: checked ? 18 : 2,
        width: 16,
        height: 16,
        borderRadius: '50%',
        background: '#fff',
        boxShadow: '0 1px 2px rgba(0,0,0,0.25)',
        transition: `left 0.22s ${TONO_EASE}`,
      }}
    />
  </button>
)
