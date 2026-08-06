import { useLocalStorage } from 'foxact/use-local-storage'
import { type MutableRefObject, useCallback, useEffect, useRef } from 'react'
import { type Message, type MihomoWebSocket } from 'tauri-plugin-mihomo-api'

import {
  getCacheData,
  removeCacheData,
  setCacheData,
  useQuery,
} from '@/services/query-client'

const RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000]
const RECONNECT_JITTER = 0.2
const CONNECT_TIMEOUT_MS = 10_000

interface SharedSubscriptionOwner {
  handleMessage: (data: string) => void
  onConnected?: (ws: MihomoWebSocket) => Promise<void> | void
  cleanup?: () => void
  isMounted: () => boolean
}

interface SharedSubscriptionEntry {
  refs: number
  ws: MihomoWebSocket | null
  reconnectTimer: ReturnType<typeof setTimeout> | null
  connecting: boolean
  refHolders: Set<MutableRefObject<MihomoWebSocket | null>>
  owners: Set<SharedSubscriptionOwner>
  activeOwner: SharedSubscriptionOwner | null
  closed: boolean
  connectWs: () => Promise<void>
  scheduleReconnect: () => Promise<void>
}

const sharedSubscriptions = new Map<string, SharedSubscriptionEntry>()
const initialSubscriptionDate = Date.now()

const syncSharedWsRefs = (entry: SharedSubscriptionEntry) => {
  entry.refHolders.forEach((ref) => {
    ref.current = entry.ws
  })
}

const pickActiveOwner = (entry: SharedSubscriptionEntry) => {
  if (entry.activeOwner?.isMounted()) return entry.activeOwner

  for (const owner of entry.owners) {
    if (owner.isMounted()) {
      entry.activeOwner = owner
      return owner
    }
  }

  entry.activeOwner = null
  return null
}

const closeSharedSocket = async (entry: SharedSubscriptionEntry) => {
  const ws = entry.ws
  if (!ws) return

  entry.ws = null
  syncSharedWsRefs(entry)
  await ws.close()
}

export const createSharedSubscriptionEntry = (
  connect: () => Promise<MihomoWebSocket>,
): SharedSubscriptionEntry => {
  const entry: SharedSubscriptionEntry = {
    refs: 0,
    ws: null,
    reconnectTimer: null,
    connecting: false,
    refHolders: new Set(),
    owners: new Set(),
    activeOwner: null,
    closed: false,
    connectWs: async () => {},
    scheduleReconnect: async () => {},
  }

  // Exponential backoff with jitter so a dead controller isn't hammered at
  // 1 Hz forever; reset whenever a connect succeeds.
  let reconnectAttempt = 0
  // Epoch of the latest connect attempt. A hung attempt is superseded by
  // bumping the epoch; the stale attempt then abandons its result instead of
  // holding `connecting` (and thus all future reconnects) hostage.
  let connectEpoch = 0
  let connectStartedAt = 0

  const nextReconnectDelay = () => {
    const base =
      RECONNECT_DELAYS_MS[
        Math.min(reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)
      ]
    reconnectAttempt += 1
    return Math.round(base * (1 + (Math.random() * 2 - 1) * RECONNECT_JITTER))
  }

  const clearReconnectTimer = () => {
    if (entry.reconnectTimer) {
      clearTimeout(entry.reconnectTimer)
      entry.reconnectTimer = null
    }
  }

  entry.connectWs = async () => {
    if (entry.closed || entry.ws) return
    if (
      entry.connecting &&
      Date.now() - connectStartedAt < CONNECT_TIMEOUT_MS
    ) {
      // An earlier attempt is still in flight and not yet stale: check back
      // later instead of silently giving up, so a connect that never settles
      // can never permanently block reconnection. Once the attempt ages past
      // CONNECT_TIMEOUT_MS the epoch bump below supersedes it.
      clearReconnectTimer()
      entry.reconnectTimer = setTimeout(entry.connectWs, nextReconnectDelay())
      return
    }

    entry.connecting = true
    connectStartedAt = Date.now()
    const attempt = ++connectEpoch
    try {
      const ws = await connect()
      if (attempt !== connectEpoch || entry.closed) {
        // Superseded by a newer attempt or torn down while connecting; don't
        // leak the late socket.
        await ws.close()
        return
      }

      entry.ws = ws
      syncSharedWsRefs(entry)
      clearReconnectTimer()
      reconnectAttempt = 0

      // Install the message listener before optional initialization. Otherwise messages emitted
      // while `onConnected` awaits its snapshot can be lost, and an exception leaves a live
      // socket with neither listener nor reconnect path.
      ws.addListener((msg: Message) => {
        if (msg.type !== 'Text') return
        const activeOwner = pickActiveOwner(entry)
        if (!activeOwner) return

        activeOwner.handleMessage(msg.data)
      })

      const owner = pickActiveOwner(entry)
      if (owner?.onConnected) {
        await owner.onConnected(ws)
        if (attempt !== connectEpoch) return
        if (entry.closed) {
          await closeSharedSocket(entry)
          return
        }
      }
    } catch (ignoreError) {
      if (attempt === connectEpoch && !entry.closed) {
        clearReconnectTimer()
        try {
          await closeSharedSocket(entry)
        } catch {
          // State was cleared before close; reconnect remains safe even when the stale transport
          // refuses its close handshake.
        }
        if (!entry.closed) {
          entry.reconnectTimer = setTimeout(
            entry.connectWs,
            nextReconnectDelay(),
          )
        }
      }
    } finally {
      if (attempt === connectEpoch) {
        entry.connecting = false
      }
    }
  }

  entry.scheduleReconnect = async () => {
    if (entry.closed) return

    clearReconnectTimer()
    try {
      await closeSharedSocket(entry)
    } catch {
      // A broken socket must not be allowed to suppress its own reconnect.
    } finally {
      if (!entry.closed) {
        entry.reconnectTimer = setTimeout(
          entry.connectWs,
          nextReconnectDelay(),
        )
      }
    }
  }

  return entry
}

/**
 * Mirrors SWR's MutatorCallback: consumers can pass either a plain value or a
 * functional updater `(current?: T) => T`.  The functional form is resolved
 * against the current cache entry before calling `setCacheData`.
 */
type NextFn<T> = (
  error?: any,
  data?: T | ((current?: T) => T | undefined),
) => void

interface HandlerContext<T> {
  next: NextFn<T>
  scheduleReconnect: () => Promise<void>
  isMounted: () => boolean
}

interface HandlerResult {
  handleMessage: (data: string) => void
  onConnected?: (ws: MihomoWebSocket) => Promise<void> | void
  cleanup?: () => void
}

interface UseMihomoWsSubscriptionOptions<T> {
  storageKey: string
  buildSubscriptKey: (date: number) => string | null
  fallbackData: T
  connect: () => Promise<MihomoWebSocket>
  /**
   * When > 0, coalesce rapid WebSocket messages by wrapping the `next`
   * function passed to `setupHandlers`.  Only the most recent value is
   * flushed, at most once per `throttleMs` milliseconds.
   *
   * Uses `setTimeout` (not `requestAnimationFrame`) so it keeps working
   * when the window is backgrounded or minimized.
   */
  throttleMs?: number
  setupHandlers: (ctx: HandlerContext<T>) => HandlerResult
}

export const useMihomoWsSubscription = <T>(
  options: UseMihomoWsSubscriptionOptions<T>,
) => {
  const {
    storageKey,
    buildSubscriptKey,
    fallbackData,
    connect,
    throttleMs,
    setupHandlers,
  } = options

  const [date, setDate] = useLocalStorage(storageKey, initialSubscriptionDate)
  const subscriptKey = buildSubscriptKey(date)
  const subscriptionCacheKey = subscriptKey ? `$sub$${subscriptKey}` : null
  const lastSubscriptionCacheKeyRef = useRef<string | null>(null)
  if (subscriptionCacheKey) {
    lastSubscriptionCacheKeyRef.current = subscriptionCacheKey
  }
  const responseCacheKey =
    subscriptionCacheKey ?? lastSubscriptionCacheKeyRef.current

  const wsRef = useRef<MihomoWebSocket | null>(null)

  const resolveNextData = useCallback(
    (
      data: T | ((current?: T) => T | undefined) | undefined,
      cacheKey: string,
    ): T => {
      if (typeof data === 'function') {
        const updater = data as (current?: T) => T | undefined
        const current = getCacheData<T>([cacheKey])
        return updater(current) ?? fallbackData
      }
      return data ?? fallbackData
    },
    [fallbackData],
  )

  const response = useQuery<T>({
    queryKey: responseCacheKey ? [responseCacheKey] : ['$sub$__disabled__'],
    queryFn: () => getCacheData<T>([responseCacheKey!]) ?? fallbackData,
    initialData: () =>
      getCacheData<T>([responseCacheKey ?? '$sub$__disabled__']) ??
      fallbackData,
    staleTime: Infinity,
    enabled: subscriptionCacheKey !== null,
  })

  useEffect(() => {
    if (!subscriptionCacheKey) return

    let isMounted = true
    let entry = sharedSubscriptions.get(subscriptionCacheKey)
    if (!entry) {
      entry = createSharedSubscriptionEntry(connect)
      sharedSubscriptions.set(subscriptionCacheKey, entry)
    }

    entry.refs += 1
    entry.refHolders.add(wsRef)
    wsRef.current = entry.ws

    let throttleCleanup: (() => void) | undefined
    let wrappedNext: NextFn<T>

    const baseNext: NextFn<T> = (error, data) => {
      if (error !== undefined && error !== null) {
        return
      }
      if (data === undefined) return
      const resolved = resolveNextData(data, subscriptionCacheKey)
      setCacheData<T>([subscriptionCacheKey], resolved)
    }

    if (throttleMs && throttleMs > 0) {
      let pendingData: T | ((current?: T) => T | undefined) | undefined
      let hasPending = false
      let timerId: ReturnType<typeof setTimeout> | null = null

      const flush = () => {
        timerId = null
        if (hasPending) {
          const data = pendingData
          pendingData = undefined
          hasPending = false
          baseNext(undefined, data)
        }
      }

      wrappedNext = (
        error?: any,
        data?: T | ((current?: T) => T | undefined),
      ) => {
        if (error !== undefined && error !== null) {
          baseNext(error, data)
          return
        }
        if (!timerId) {
          baseNext(undefined, data)
          timerId = setTimeout(flush, throttleMs)
        } else {
          pendingData = data
          hasPending = true
        }
      }

      throttleCleanup = () => {
        if (timerId) {
          clearTimeout(timerId)
          timerId = null
        }
      }
    } else {
      wrappedNext = baseNext
    }

    const {
      handleMessage: handleTextMessage,
      onConnected,
      cleanup,
    } = setupHandlers({
      next: wrappedNext,
      scheduleReconnect: entry.scheduleReconnect,
      isMounted: () => isMounted,
    })

    const owner: SharedSubscriptionOwner = {
      handleMessage: handleTextMessage,
      onConnected,
      cleanup: () => {
        throttleCleanup?.()
        cleanup?.()
      },
      isMounted: () => isMounted,
    }

    entry.owners.add(owner)
    if (!entry.activeOwner) {
      entry.activeOwner = owner
    }
    void entry.connectWs()

    return () => {
      isMounted = false
      entry.refHolders.delete(wsRef)
      wsRef.current = null
      entry.owners.delete(owner)
      owner.cleanup?.()

      if (entry.activeOwner === owner) {
        entry.activeOwner = null
        const nextOwner = pickActiveOwner(entry)
        if (entry.ws && nextOwner?.onConnected) {
          Promise.resolve(nextOwner.onConnected(entry.ws)).catch(() => {
            void entry.scheduleReconnect()
          })
        }
      }

      entry.refs -= 1
      if (entry.refs <= 0) {
        entry.closed = true
        if (entry.reconnectTimer) {
          clearTimeout(entry.reconnectTimer)
          entry.reconnectTimer = null
        }
        sharedSubscriptions.delete(subscriptionCacheKey)
        void closeSharedSocket(entry)
      }
    }
    // eslint-disable-next-line react-compiler/react-compiler
    // eslint-disable-next-line react-hooks/exhaustive-deps, @eslint-react/exhaustive-deps
  }, [subscriptionCacheKey])

  const refresh = useCallback(() => {
    if (subscriptionCacheKey) {
      removeCacheData([subscriptionCacheKey])
    }
    setDate(Date.now())
  }, [subscriptionCacheKey, setDate])

  return { response, refresh, subscriptionCacheKey: responseCacheKey, wsRef }
}
