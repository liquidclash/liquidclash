import { createBrowserRouter, RouteObject } from 'react-router'

import TonoLayout from '@/tono-ui/tono-layout'

import { hiddenRoutes, navItems } from './_navigation'

export const router = createBrowserRouter([
  {
    path: '/',
    Component: TonoLayout,
    children: [...navItems, ...hiddenRoutes].map(
      (item) =>
        ({
          path: item.path,
          Component: item.Component,
        }) as RouteObject,
    ),
  },
])
