import type { ReactNode } from 'react'
import type { NavKey } from '../nav'

// A handful of inline icons for the sidebar, drawn on a 20x20 grid in
// currentColor. Always decorative: the text beside them (or an sr-only label)
// names the thing.

export type IconName = NavKey | 'menu' | 'close' | 'collapse' | 'expand' | 'theme' | 'caret'

const PATHS: Record<IconName, ReactNode> = {
  overview: (
    <>
      <rect x="3" y="3" width="6" height="6" rx="1" />
      <rect x="11" y="3" width="6" height="4" rx="1" />
      <rect x="11" y="9" width="6" height="8" rx="1" />
      <rect x="3" y="11" width="6" height="6" rx="1" />
    </>
  ),
  alerts: <path d="M10 3a4.5 4.5 0 0 0-4.5 4.5V11L4 13.5h12L14.5 11V7.5A4.5 4.5 0 0 0 10 3ZM8.3 16a1.8 1.8 0 0 0 3.4 0" />,
  map: (
    <>
      <circle cx="5" cy="5" r="2" />
      <circle cx="15" cy="5" r="2" />
      <circle cx="10" cy="15" r="2" />
      <path d="M7 5h6M6 6.8l3 6.4M14 6.8l-3 6.4" />
    </>
  ),
  workloads: <path d="M10 3 17 6.5 10 10 3 6.5ZM3 10l7 3.5 7-3.5M3 13.5 10 17l7-3.5" />,
  pods: <path d="M10 2.8 16.5 6.5v7L10 17.2 3.5 13.5v-7ZM3.5 6.5 10 10.2l6.5-3.7M10 10.2v7" />,
  nodes: (
    <>
      <rect x="3" y="3.5" width="14" height="5.5" rx="1.2" />
      <rect x="3" y="11" width="14" height="5.5" rx="1.2" />
      <path d="M6 6.25h.01M6 13.75h.01M9 6.25h5M9 13.75h5" />
    </>
  ),
  agents: (
    <>
      <rect x="5.5" y="5.5" width="9" height="9" rx="1.2" />
      <path d="M8 2.5v3M12 2.5v3M8 14.5v3M12 14.5v3M2.5 8h3M2.5 12h3M14.5 8h3M14.5 12h3" />
    </>
  ),
  incidents: <path d="M11.5 2.5 4.5 11h5l-1 6.5L15.5 9h-5Z" />,
  findings: <path d="M4.5 17.5V3M4.5 3.5h10l-2.2 3.5 2.2 3.5h-10" />,
  memory: (
    <>
      <rect x="2.5" y="6" width="15" height="8" rx="1" />
      <path d="M6 9v2M10 9v2M14 9v2M5.5 14v2.5M14.5 14v2.5" />
    </>
  ),
  storage: (
    <>
      <ellipse cx="10" cy="5" rx="6" ry="2.2" />
      <path d="M4 5v10c0 1.2 2.7 2.2 6 2.2s6-1 6-2.2V5M4 10c0 1.2 2.7 2.2 6 2.2s6-1 6-2.2" />
    </>
  ),
  security: <path d="M10 2.5 16 5v4.5c0 4-2.6 6.7-6 8-3.4-1.3-6-4-6-8V5Z" />,
  certificates: (
    <>
      <circle cx="10" cy="8" r="4.5" />
      <path d="M7.3 11.6 6.2 17.5l3.8-2 3.8 2-1.1-5.9" />
    </>
  ),
  activity: <path d="M2.5 10H6l2-5 4 10 2-5h3.5" />,
  settings: (
    <>
      <circle cx="10" cy="10" r="2.6" />
      <path d="M10 2.5v2.2M10 15.3v2.2M2.5 10h2.2M15.3 10h2.2M4.7 4.7l1.6 1.6M13.7 13.7l1.6 1.6M4.7 15.3l1.6-1.6M13.7 6.3l1.6-1.6" />
    </>
  ),
  menu: <path d="M3.5 5.5h13M3.5 10h13M3.5 14.5h13" />,
  close: <path d="M5 5l10 10M15 5 5 15" />,
  collapse: <path d="M10.5 5 5.5 10l5 5M15.5 5l-5 5 5 5" />,
  expand: <path d="M9.5 5l5 5-5 5M4.5 5l5 5-5 5" />,
  theme: (
    <>
      <circle cx="10" cy="10" r="6.5" />
      <path d="M10 3.5a6.5 6.5 0 0 1 0 13Z" fill="currentColor" />
    </>
  ),
  caret: <path d="M6 8l4 4 4-4" />,
}

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg
      className={className ? `icon ${className}` : 'icon'}
      viewBox="0 0 20 20"
      width="18"
      height="18"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  )
}
