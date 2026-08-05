import delayManager from '@/services/delay'
import { TONO_COLORS } from '@/tono-ui/theme'

/** Delay capsule colors from the macOS thresholds (<200 / <400 / ≥400). */
export const latencyColor = (delay: number) =>
  delay < 200
    ? TONO_COLORS.latencyGood
    : delay < 400
      ? TONO_COLORS.protectedOffline
      : TONO_COLORS.error

/** Best-effort latency for a node: the delay manager's GLOBAL-group history. */
export const readNodeLatency = (name: string): number | null => {
  try {
    const update = delayManager.getDelayUpdate(name, 'GLOBAL')
    const delay = update?.delay ?? -1
    return delay > 0 && delay < 1e6 ? delay : null
  } catch {
    return null
  }
}
