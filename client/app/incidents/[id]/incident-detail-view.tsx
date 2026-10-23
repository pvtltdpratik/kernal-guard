"use client"

import Link from "next/link"
import { useParams } from "next/navigation"
import { RiAlarmWarningLine, RiFileList3Line } from "@remixicon/react"

import { AlertStatusBadge, IncidentStatusBadge, ScoreMeter, SeverityBadge } from "@/components/kg/badges"
import { DataView, RefreshIndicator } from "@/components/kg/data-states"
import { HistoryList, IncidentScoreBreakdown, Mono, ObservationList, UncertaintyList } from "@/components/kg/explain"
import { PageBody, PageHeader, Section } from "@/components/kg/page-header"
import { TriagePanel } from "@/components/kg/triage"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useApi } from "@/hooks/use-api"
import type { IncidentDetail, IncidentStatus, TimelineEntry } from "@/lib/api/types"
import { fileName, formatTime, humanize } from "@/lib/format"

const STATUSES: { value: IncidentStatus; label: string; hint: string }[] = [
  { value: "investigating", label: "Start investigating", hint: "Mark as under investigation" },
  { value: "closed", label: "Close", hint: "No further action; new related alerts open a new incident" },
  { value: "open", label: "Reopen", hint: "Return to open" },
]

export function IncidentDetailView() {
  const { id } = useParams<{ id: string }>()
  const incident = useApi<IncidentDetail>(`/api/v1/incidents/${encodeURIComponent(id)}`, undefined, { refreshMs: 30_000 })

  return (
    <>
      <PageHeader
        eyebrow={<Link href="/incidents" className="hover:underline">Incidents</Link>}
        title={incident.data?.title ?? "Incident"}
        actions={<RefreshIndicator state={incident} />}
      />
      <PageBody>
        <DataView state={incident}>
          {(i) => (
            <>
              <div className="flex flex-wrap items-center gap-4">
                <SeverityBadge severity={i.severity} />
                <ScoreMeter score={i.risk_score} severity={i.severity} />
                <IncidentStatusBadge status={i.status} />
                <span className="text-xs text-muted-foreground">
                  {formatTime(i.first_seen)} → {formatTime(i.last_seen)} · {i.alert_count} alerts
                </span>
              </div>

              <div className="grid gap-6 xl:grid-cols-3">
                <div className="flex min-w-0 flex-col gap-6 xl:col-span-2">
                  <Section title="Timeline" description="Evidence events and the alerts they triggered, in activity-time order">
                    <ol className="flex flex-col border-s">
                      {i.timeline.map((entry, index) => <TimelineItem key={index} entry={entry} />)}
                    </ol>
                  </Section>
                  <Card>
                    <CardHeader>
                      <CardTitle>Risk score</CardTitle>
                      <CardDescription>Each rule counts once; false positives add nothing</CardDescription>
                    </CardHeader>
                    <CardContent className="overflow-x-auto"><IncidentScoreBreakdown entries={i.score_breakdown} total={i.risk_score} /></CardContent>
                  </Card>
                </div>

                <div className="flex min-w-0 flex-col gap-6">
                  <Card>
                    <CardHeader><CardTitle>Status and notes</CardTitle></CardHeader>
                    <CardContent>
                      <TriagePanel<IncidentStatus, IncidentDetail>
                        endpoint={`/api/v1/incidents/${i.id}`}
                        current={i.status}
                        statuses={STATUSES}
                        onSaved={incident.setData}
                      />
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader>
                      <CardTitle>Evidence and uncertainty</CardTitle>
                      <CardDescription>Limits of what these observations can establish</CardDescription>
                    </CardHeader>
                    <CardContent><UncertaintyList items={i.uncertainty} /></CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>Rules fired</CardTitle></CardHeader>
                    <CardContent>
                      <ul className="flex flex-col gap-3 text-sm">
                        {i.rules_fired.map((r) => (
                          <li key={r.rule_id}>
                            <Link href={`/alerts?incident_id=${i.id}&rule_id=${r.rule_id}`} className="underline underline-offset-4">{r.name}</Link>
                            <p className="text-xs text-muted-foreground">
                              <span className="font-mono">{r.rule_id}</span> · {humanize(r.category)}
                              {r.mitre.map((m) => ` · ${m.technique_id}${m.relationship === "consistent_with" ? " (consistent with)" : ""}`).join("")}
                            </p>
                          </li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>Alerts</CardTitle></CardHeader>
                    <CardContent>
                      <ul className="flex flex-col gap-3">
                        {i.alerts.map((a) => (
                          <li key={a.id} className="flex flex-col gap-1">
                            <Link href={`/alerts/${a.id}`} className="text-sm hover:underline">{a.title}</Link>
                            <span className="flex flex-wrap items-center gap-2">
                              <SeverityBadge severity={a.severity} />
                              <AlertStatusBadge status={a.status} />
                            </span>
                          </li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>Shared entities</CardTitle></CardHeader>
                    <CardContent>
                      <ul className="flex flex-col gap-1">{i.entities.map((e) => <li key={e}><Mono>{e}</Mono></li>)}</ul>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>History</CardTitle></CardHeader>
                    <CardContent><HistoryList history={i.history} /></CardContent>
                  </Card>
                </div>
              </div>
            </>
          )}
        </DataView>
      </PageBody>
    </>
  )
}

function TimelineItem({ entry }: { entry: TimelineEntry }) {
  const isAlert = entry.kind === "alert"
  return (
    <li className="relative flex flex-col gap-2 py-3 ps-6">
      <span aria-hidden className={`absolute top-4 -start-[5px] size-2.5 rounded-full ${isAlert ? "bg-sev-high" : "bg-muted-foreground"}`} />
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span className="font-mono">{formatTime(entry.timestamp)}</span>
        {isAlert ? (
          <Badge className="text-sev-high"><RiAlarmWarningLine /> alert · {entry.rule_id}</Badge>
        ) : (
          <Badge variant="secondary"><RiFileList3Line /> observation</Badge>
        )}
      </div>
      {isAlert ? (
        <div className="flex flex-col gap-2">
          <Link href={`/alerts/${entry.alert_id}`} className="text-sm font-semibold hover:underline">{entry.title}</Link>
          <ObservationList observations={entry.observations} />
        </div>
      ) : entry.event ? (
        <Link href={`/events/${entry.event.id}`} className="text-sm hover:underline">
          {humanize(entry.event.category)}
          {entry.event.image && <span className="text-muted-foreground"> · {fileName(entry.event.image)}</span>}
          {entry.event.process_id !== null && <span className="font-mono text-xs text-muted-foreground"> PID {entry.event.process_id}</span>}
        </Link>
      ) : (
        <span className="text-sm">{entry.title}</span>
      )}
    </li>
  )
}
