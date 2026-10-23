"use client"

import * as React from "react"
import { RiErrorWarningLine } from "@remixicon/react"

import { SensorStateBadge, VisibilityBadge } from "@/components/kg/badges"
import { DataView, RefreshIndicator } from "@/components/kg/data-states"
import { KeyValues } from "@/components/kg/explain"
import { PageBody, PageHeader, Section } from "@/components/kg/page-header"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useApi } from "@/hooks/use-api"
import type { Capability, SensorStatus, SensorStatusResponse, Visibility } from "@/lib/api/types"
import { formatNumber, formatRelative, formatTime } from "@/lib/format"

const SETUP_COMMAND = String.raw`powershell -ExecutionPolicy Bypass -File .\server\scripts\setup-sysmon.ps1 -GrantEventLogRead`

export default function SensorsPage() {
  const status = useApi<SensorStatusResponse>("/api/v1/sensors/status", undefined, { refreshMs: 10_000 })
  const capabilities = useApi<Capability[]>("/api/v1/detection/capabilities", undefined, { refreshMs: 30_000 })

  return (
    <>
      <PageHeader
        title="Sensor Status"
        description="Collector state per telemetry source, ingestion problems, and what this host can currently observe."
        actions={<RefreshIndicator state={status} />}
      />
      <PageBody>
        <DataView state={status}>
          {(data) => (
            <>
              {data.collector_stale && (
                <Alert>
                  <RiErrorWarningLine />
                  <AlertTitle>The collector is not polling</AlertTitle>
                  <AlertDescription>
                    No enabled sensor has been polled in the last {data.collector_interval_seconds * 3}s. Start it in <code className="font-mono">server/</code>:{" "}
                    <code className="font-mono">.\.venv\Scripts\python.exe -m app.collectors</code>
                  </AlertDescription>
                </Alert>
              )}
              <div className="grid gap-6 lg:grid-cols-3">
                {data.sensors.map((sensor) => <SensorCard key={sensor.sensor} sensor={sensor} />)}
              </div>
            </>
          )}
        </DataView>

        <Section
          title="Capability matrix"
          description="Which techniques KernelGuard can observe by design, and on this host right now. 'Not observable' is a statement about telemetry, not about the host being clean."
        >
          <DataView state={capabilities}>{(caps) => <CapabilityTable capabilities={caps} />}</DataView>
        </Section>
      </PageBody>
    </>
  )
}

function sensorWarnings(s: SensorStatus): string[] {
  const warnings: string[] = []
  if (!s.enabled) warnings.push("Disabled in KG_COLLECTOR_SENSORS.")
  if (s.state === "unavailable" && s.sensor === "sysmon")
    warnings.push(`Sysmon is not installed. From an elevated PowerShell at the repository root: ${SETUP_COMMAND}`)
  if (s.state === "access_denied")
    warnings.push("Permission denied. Add the collector's account to 'Event Log Readers' (setup script -GrantEventLogRead, then sign out and in) or run the collector elevated.")
  if (s.sensor === "security" && s.state === "ok" && s.events_ingested === 0)
    warnings.push("No Security events collected yet: 4688 requires the 'Audit Process Creation' policy (auditpol /set /subcategory:\"Process Creation\" /success:enable).")
  if (s.records_missed > 0) warnings.push(`${formatNumber(s.records_missed)} record(s) were overwritten by log rotation before collection. Increase the channel size or poll more often.`)
  if (s.parse_failures > 0) warnings.push(`${formatNumber(s.parse_failures)} record(s) could not be parsed and were skipped.`)
  if (s.detection_failures > 0) warnings.push(`Detection failed for ${formatNumber(s.detection_failures)} event(s). Run: python -m app.detection rescan`)
  return warnings
}

function SensorCard({ sensor: s }: { sensor: SensorStatus }) {
  const warnings = sensorWarnings(s)
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="capitalize">{s.sensor}</CardTitle>
          <SensorStateBadge state={s.state} stale={s.stale} />
        </div>
        <CardDescription className="font-mono text-xs break-all">{s.channel}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <p className="text-sm text-muted-foreground">{s.description}</p>
        {s.detail && <p className="text-sm">{s.detail}</p>}
        {warnings.length > 0 && (
          <ul className="flex flex-col gap-2 border-s-2 border-sev-medium ps-3 text-sm">
            {warnings.map((w) => <li key={w} className="break-words">{w}</li>)}
          </ul>
        )}
        <KeyValues
          items={[
            ["Last attempt", s.last_attempt_at ? <span key="a" title={formatTime(s.last_attempt_at)}>{formatRelative(s.last_attempt_at)}</span> : null],
            ["Last success", s.last_success_at ? <span key="s" title={formatTime(s.last_success_at)}>{formatRelative(s.last_success_at)}</span> : null],
            ["Last error", s.last_error_at ? <span key="e" title={formatTime(s.last_error_at)}>{formatRelative(s.last_error_at)}</span> : null],
            ["Consecutive failures", s.consecutive_failures],
            ["Events ingested", formatNumber(s.events_ingested)],
            ["Duplicates skipped", formatNumber(s.duplicates_skipped)],
            ["Ignored (unhandled IDs)", formatNumber(s.records_ignored)],
          ]}
        />
        <p className="text-xs text-muted-foreground">Requires: {s.requirements.join("; ")}</p>
      </CardContent>
    </Card>
  )
}

function CapabilityTable({ capabilities }: { capabilities: Capability[] }) {
  const [filter, setFilter] = React.useState<"all" | Visibility>("all")
  const counts = capabilities.reduce<Record<string, number>>((acc, c) => ({ ...acc, [c.effective_visibility]: (acc[c.effective_visibility] ?? 0) + 1 }), {})
  const shown = filter === "all" ? capabilities : capabilities.filter((c) => c.effective_visibility === filter)
  return (
    <div className="flex flex-col gap-3">
      <Tabs value={filter} onValueChange={(v) => setFilter(v as typeof filter)}>
        <TabsList>
          <TabsTrigger value="all">All ({capabilities.length})</TabsTrigger>
          <TabsTrigger value="observable">Observable ({counts.observable ?? 0})</TabsTrigger>
          <TabsTrigger value="partially_observable">Partial ({counts.partially_observable ?? 0})</TabsTrigger>
          <TabsTrigger value="not_observable">Not observable ({counts.not_observable ?? 0})</TabsTrigger>
        </TabsList>
      </Tabs>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Technique</TableHead>
            <TableHead>By design</TableHead>
            <TableHead>On this host</TableHead>
            <TableHead>Evidence and gaps</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {shown.map((c) => (
            <TableRow key={`${c.technique_id}-${c.technique}`} className="align-top">
              <TableCell className="max-w-64 whitespace-normal">
                <p>{c.technique}</p>
                <p className="font-mono text-xs text-muted-foreground">{c.technique_id}{c.rules.length > 0 && ` · ${c.rules.join(", ")}`}</p>
              </TableCell>
              <TableCell><VisibilityBadge visibility={c.design_visibility} /></TableCell>
              <TableCell className="whitespace-normal">
                <VisibilityBadge visibility={c.effective_visibility} />
                {c.effective_note && <p className="mt-1 max-w-56 text-xs text-muted-foreground">{c.effective_note}</p>}
              </TableCell>
              <TableCell className="max-w-[28rem] text-xs whitespace-normal">
                <p>{c.evidence}</p>
                {c.gaps && <p className="mt-1 text-muted-foreground">Gap: {c.gaps}</p>}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
