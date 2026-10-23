"use client"

import * as React from "react"
import Link from "next/link"
import { RiAlertLine } from "@remixicon/react"

import { IncidentStatusBadge, ScoreMeter, SensorStateBadge, SeverityBadge, severityColor } from "@/components/kg/badges"
import { DataView, EmptyState, RefreshIndicator } from "@/components/kg/data-states"
import { PageBody, PageHeader, Section } from "@/components/kg/page-header"
import { VolumeChart } from "@/components/kg/volume-chart"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useApi } from "@/hooks/use-api"
import { SEVERITIES, type MetricsOverview } from "@/lib/api/types"
import { formatNumber, formatRelative } from "@/lib/format"

export default function OverviewPage() {
  const [range, setRange] = React.useState<"24h" | "7d">("24h")
  const overview = useApi<MetricsOverview>("/api/v1/metrics/overview", { window: range }, { refreshMs: 15_000 })

  return (
    <>
      <PageHeader
        title="Overview"
        description="Telemetry volume, active detections and sensor health for this host."
        actions={<RefreshIndicator state={overview} />}
      />
      <PageBody>
        <DataView state={overview}>{(data) => <Overview data={data} range={range} onRange={setRange} />}</DataView>
      </PageBody>
    </>
  )
}

function Overview({ data, range, onRange }: { data: MetricsOverview; range: "24h" | "7d"; onRange: (r: "24h" | "7d") => void }) {
  const noLiveSensor = data.sensors.every((s) => s.state !== "ok" || s.stale)
  const maxSeverity = Math.max(1, ...data.alerts_by_severity.map((s) => s.count))

  return (
    <>
      {noLiveSensor && (
        <Alert>
          <RiAlertLine />
          <AlertTitle>No sensor is currently collecting</AlertTitle>
          <AlertDescription>
            Stored data is shown, but nothing new is being observed.{" "}
            <Link href="/sensors" className="underline underline-offset-4">Check sensor status</Link>.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Total events" value={data.total_events} hint={`${formatNumber(data.events_last_24h)} in the last 24h`} href="/events" />
        <Stat label="Active alerts" value={data.active_alerts} hint="new or acknowledged" href="/alerts?status=new&status=acknowledged" />
        <Stat label="Open incidents" value={data.open_incidents} hint="open or investigating" href="/incidents?status=open&status=investigating" />
        <Stat
          label="Sensors collecting"
          value={data.sensors.filter((s) => s.state === "ok" && !s.stale).length}
          suffix={` / ${data.sensors.length}`}
          hint="healthy and recently polled"
          href="/sensors"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Event volume</CardTitle>
            <CardDescription>Events by {data.event_volume_bucket}, by activity time</CardDescription>
            <Tabs value={range} onValueChange={(v) => onRange(v as "24h" | "7d")} className="mt-2">
              <TabsList>
                <TabsTrigger value="24h">24 hours</TabsTrigger>
                <TabsTrigger value="7d">7 days</TabsTrigger>
              </TabsList>
            </Tabs>
          </CardHeader>
          <CardContent>
            {data.event_volume.some((p) => p.count > 0) ? (
              <VolumeChart points={data.event_volume} bucket={data.event_volume_bucket} />
            ) : (
              <EmptyState title="No events in this window">Older events may exist; widen the window or open the Event Explorer.</EmptyState>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Active alerts by severity</CardTitle>
            <CardDescription>New and acknowledged alerts</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {[...data.alerts_by_severity].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)).map(({ severity, count }) => (
              <Link key={severity} href={`/alerts?severity=${severity}&status=new&status=acknowledged`} className="group flex items-center gap-3">
                <span className="w-24"><SeverityBadge severity={severity} /></span>
                <div className="h-2 flex-1 bg-muted">
                  <div className="h-full" style={{ width: `${(count / maxSeverity) * 100}%`, background: severityColor(severity) }} />
                </div>
                <span className="w-10 text-end font-mono text-xs tabular-nums group-hover:underline">{count}</span>
              </Link>
            ))}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Section title="Recent incidents" actions={<Link href="/incidents" className="text-xs underline underline-offset-4">All incidents</Link>}>
          {data.recent_incidents.length === 0 ? (
              <EmptyState title="No incidents">Incidents appear when related alerts are correlated.</EmptyState>
            ) : (
              <ul className="divide-y border">
                {data.recent_incidents.map((incident) => (
                  <li key={incident.id}>
                    <Link href={`/incidents/${incident.id}`} className="flex flex-col gap-1 px-4 py-3 hover:bg-muted/50">
                      <span className="line-clamp-2 text-sm">{incident.title}</span>
                      <span className="flex flex-wrap items-center gap-3">
                        <SeverityBadge severity={incident.severity} />
                        <IncidentStatusBadge status={incident.status} />
                        <ScoreMeter score={incident.risk_score} severity={incident.severity} />
                        <span className="text-xs text-muted-foreground">{incident.alert_count} alerts · {formatRelative(incident.last_seen)}</span>
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
        </Section>

        <Section title="Sensor health" actions={<Link href="/sensors" className="text-xs underline underline-offset-4">Details</Link>}>
          <ul className="divide-y border">
            {data.sensors.map((sensor) => (
              <li key={sensor.sensor} className="flex items-center justify-between px-4 py-3">
                <span className="text-sm capitalize">{sensor.sensor}</span>
                <SensorStateBadge state={sensor.state} stale={sensor.stale} />
              </li>
            ))}
          </ul>
        </Section>

        <Section title="Top rules" description="By active alerts">
          {data.top_rules.length === 0 ? (
            <EmptyState title="No active alerts" />
          ) : (
            <ul className="divide-y border">
              {data.top_rules.map((rule) => (
                <li key={rule.rule_id}>
                  <Link href={`/alerts?rule_id=${rule.rule_id}`} className="flex items-center justify-between px-4 py-3 hover:bg-muted/50">
                    <span className="font-mono text-xs">{rule.rule_id}</span>
                    <span className="font-mono text-xs tabular-nums">{rule.active_alerts}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
      <p className="text-xs text-muted-foreground">
        Alerts are suspected activity derived from observations; none on its own confirms malware.
      </p>
    </>
  )
}

function Stat({ label, value, hint, href, suffix }: { label: string; value: number; hint: string; href: string; suffix?: string }) {
  return (
    <Link href={href} className="block">
      <Card className="h-full transition-colors hover:bg-muted/40">
        <CardHeader>
          <CardDescription className="text-[0.625rem] font-semibold tracking-widest uppercase">{label}</CardDescription>
          <CardTitle className="font-heading text-3xl tabular-nums">
            {formatNumber(value)}
            {suffix && <span className="text-base text-muted-foreground">{suffix}</span>}
          </CardTitle>
          <p className="text-xs text-muted-foreground">{hint}</p>
        </CardHeader>
      </Card>
    </Link>
  )
}
