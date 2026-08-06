import { Box, CircularProgress } from '@mui/material'
import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router'

import { useTonoStatus } from '@/hooks/use-tono'

import { resolveTonoGuard } from './tono-guard'

/**
 * Layout-level Tono auth guard: redirects and the loading placeholder live here
 * so `_layout.tsx` only decides what the chrome looks like per route.
 */
export const TonoAuthGuard = ({ children }: { children: ReactNode }) => {
  const location = useLocation()
  const { status } = useTonoStatus()
  const action = resolveTonoGuard(status, location.pathname)

  if (action === 'loading') {
    return (
      <Box
        sx={{
          width: '100vw',
          height: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <CircularProgress />
      </Box>
    )
  }

  if (action === 'toLogin') {
    return <Navigate to="/login" replace />
  }

  if (action === 'toHome') {
    return <Navigate to="/" replace />
  }

  return children
}
