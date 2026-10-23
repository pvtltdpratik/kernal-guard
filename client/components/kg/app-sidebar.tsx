"use client"

import { Suspense } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  RiAlarmWarningLine,
  RiDashboardLine,
  RiFileList3Line,
  RiPulseLine,
  RiShieldKeyholeLine,
  RiStackLine,
  RiTerminalBoxLine,
} from "@remixicon/react"

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { useApi } from "@/hooks/use-api"
import type { HealthResponse } from "@/lib/api/types"

const NAV = [
  { href: "/", label: "Overview", icon: RiDashboardLine },
  { href: "/alerts", label: "Alerts", icon: RiAlarmWarningLine },
  { href: "/incidents", label: "Incidents", icon: RiStackLine },
  { href: "/events", label: "Event Explorer", icon: RiFileList3Line },
  { href: "/processes", label: "Processes", icon: RiTerminalBoxLine },
  { href: "/sensors", label: "Sensor Status", icon: RiPulseLine },
]

function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`)
}

function ApiHealth() {
  const health = useApi<HealthResponse>("/health", undefined, { refreshMs: 30_000 })
  const ok = health.data?.status === "ok" && !health.error
  const label = health.loading ? "Checking API…" : health.error ? "API unreachable" : ok ? `API ok · v${health.data?.version}` : "API degraded"
  return (
    <div className="flex items-center gap-2 px-2 text-xs text-muted-foreground" title={health.error?.message}>
      <span aria-hidden className={`size-1.5 rounded-full ${health.loading ? "bg-muted-foreground" : ok ? "bg-ok" : "bg-sev-critical"}`} />
      {label}
    </div>
  )
}

function NavItems({ pathname }: { pathname: string | null }) {
  return (
    <SidebarMenu>
      {NAV.map(({ href, label, icon: Icon }) => (
        <SidebarMenuItem key={href}>
          <SidebarMenuButton render={<Link href={href} />} isActive={pathname !== null && isActive(pathname, href)} tooltip={label}>
            <Icon />
            <span>{label}</span>
          </SidebarMenuButton>
        </SidebarMenuItem>
      ))}
    </SidebarMenu>
  )
}

// usePathname() is request-time URL data: keep it inside Suspense so the
// shell (and the nav, without the active highlight) can be prerendered.
function ActiveNavItems() {
  return <NavItems pathname={usePathname()} />
}

export function AppSidebar() {
  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" render={<Link href="/" />} tooltip="KernelGuard">
              <RiShieldKeyholeLine className="size-5!" />
              <span className="font-heading text-lg tracking-wide normal-case">KernelGuard</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Investigate</SidebarGroupLabel>
          <SidebarGroupContent>
            <Suspense fallback={<NavItems pathname={null} />}>
              <ActiveNavItems />
            </Suspense>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <ApiHealth />
      </SidebarFooter>
    </Sidebar>
  )
}
