import { useEffect, useRef } from 'react'

import { setCacheData, useQuery } from '@/services/query-client'
import {
  subscribeTonoStatus,
  tonoStatus,
  type TonoStatus,
} from '@/services/tono'

import { useVisibility } from './use-visibility'

export const tonoStatusQueryKey = ['tonoStatus'] as const
export const tonoAccountQueryKey = ['tonoAccount'] as const
export const tonoDevicesQueryKey = ['tonoDevices'] as const
export const tonoServersQueryKey = ['tonoServers'] as const
export const tonoConnectProgressQueryKey = ['tonoConnectProgress'] as const

/**
 * The Tono status snapshot: account state, connection state, kill switch.
 *
 * One query key, kept fresh by the `tono://status` push rather than polling; the 5s interval
 * is a safety net only. Between the first read and the listener registration there is a gap,
 * so the hook re-reads once the subscription is live.
 */
export function useTonoStatus() {
  const pageVisible = useVisibility()

  const {
    data: status,
    refetch: mutateTonoStatus,
    isLoading,
  } = useQuery({
    queryKey: tonoStatusQueryKey,
    queryFn: tonoStatus,
    // A safety net only: transitions are pushed, so this is not the primary path.
    refetchInterval: pageVisible ? 5000 : false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  })

  // query-client builds a fresh `refetch` closure on every render; keeping the
  // latest one in a ref lets the subscription below register exactly once per
  // mount instead of tearing down and re-listening (plus an extra invoke) on
  // every render.
  const mutateRef = useRef(mutateTonoStatus)
  useEffect(() => {
    mutateRef.current = mutateTonoStatus
  })

  useEffect(
    () =>
      subscribeTonoStatus(
        (next: TonoStatus) => setCacheData(tonoStatusQueryKey, next),
        () => void mutateRef.current(),
      ),
    [],
  )

  return {
    status,
    mutateTonoStatus,
    isLoading,
  }
}
