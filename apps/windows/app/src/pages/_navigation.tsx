import AccountCircleOutlinedIcon from '@mui/icons-material/AccountCircleOutlined'
import CloudOutlinedIcon from '@mui/icons-material/CloudOutlined'
import DashboardOutlinedIcon from '@mui/icons-material/DashboardOutlined'
import SettingsOutlinedIcon from '@mui/icons-material/SettingsOutlined'
import SupportAgentOutlinedIcon from '@mui/icons-material/SupportAgentOutlined'
import TimelineOutlinedIcon from '@mui/icons-material/TimelineOutlined'
import { type ComponentType, type ReactNode } from 'react'

import SettingsSvg from '@/assets/image/itemicon/settings.svg?react'

import { navigationItems } from './_navigation-meta'
import SettingPage from './settings'
import TonoAccountPage from './tono/account'
import TonoActivityPage from './tono/activity'
import TonoDashboardPage from './tono/dashboard'
import TonoLoginPage from './tono/login'
import TonoServersPage from './tono/servers'
import TonoSupportPage from './tono/support'

type NavigationGroup = 'main' | 'advanced'

type NavigationItem = {
  label: (typeof navigationItems)[keyof typeof navigationItems]['label']
  path: string
  icon: ReactNode[]
  group: NavigationGroup
  Component: ComponentType
}

export const navItems: NavigationItem[] = [
  {
    ...navigationItems.dashboard,
    icon: [
      <DashboardOutlinedIcon key="mui" />,
      <DashboardOutlinedIcon key="svg" />,
    ],
    group: 'main',
    Component: TonoDashboardPage,
  },
  {
    ...navigationItems.activity,
    icon: [
      <TimelineOutlinedIcon key="mui" />,
      <TimelineOutlinedIcon key="svg" />,
    ],
    group: 'main',
    Component: TonoActivityPage,
  },
  {
    ...navigationItems.servers,
    icon: [<CloudOutlinedIcon key="mui" />, <CloudOutlinedIcon key="svg" />],
    group: 'main',
    Component: TonoServersPage,
  },
  {
    ...navigationItems.account,
    icon: [
      <AccountCircleOutlinedIcon key="mui" />,
      <AccountCircleOutlinedIcon key="svg" />,
    ],
    group: 'main',
    Component: TonoAccountPage,
  },
  {
    ...navigationItems.support,
    icon: [
      <SupportAgentOutlinedIcon key="mui" />,
      <SupportAgentOutlinedIcon key="svg" />,
    ],
    group: 'main',
    Component: TonoSupportPage,
  },
  {
    ...navigationItems.settings,
    icon: [<SettingsOutlinedIcon key="mui" />, <SettingsSvg key="svg" />],
    group: 'main',
    Component: SettingPage,
  },
]

// Reachable by URL but not listed in the navigation: the sign-in screen,
// which the auth guard routes through.
export const hiddenRoutes = [{ path: '/login', Component: TonoLoginPage }]

export type { NavigationGroup, NavigationItem }
