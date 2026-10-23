"use client"

import Link from "next/link"
import { useParams } from "next/navigation"

import { AlertStatusBadge, ConfidenceBadge, ScoreMeter, SeverityBadge } from "@/components/kg/badges"
import { DataView, EmptyState, RefreshIndicator } from "@/components/kg/data-states"
import { EventTable } from "@/components/kg/event-table"
import {
  AlertScoreBreakdown,
  HistoryList,
  KeyValues,
  MitreList,
  Mono,
  ObservationList,
  RuleExplanation,
  UncertaintyList,
} from "@/components/kg/explain"
import { PageBody, PageHeader, Section } from "@/components/kg/page-header"
import { TriagePanel } from "@/components/kg/triage"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useApi } from "@/hooks/use-api"
import type { AlertDetail, AlertStatus } from "@/lib/api/types"
import { formatTime } from "@/lib/format"

const STATUSES: { value: AlertStatus; label: string; hint: string }[] = [
  { value: "acknowledged", label: "Acknowledge", hint: "Someone is looking at this" },
  { value: "reviewed", label: "Mark reviewed", hint: "Investigated; activity confirmed or accepted" },
  { value: "false_positive", label: "False positive", hint: "Benign; excluded from the incident score" },
  { value: "new", label: "Reopen", hint: "Return to the new queue" },
]

export function AlertDetailView() {
  const { id } = useParams<{ id: string }>()
  const alert = useApi<AlertDetail>(`/api/v1/alerts/${encodeURIComponent(id)}`, undefined, { refreshMs: 30_000 })

  return (
    <>
      <PageHeader
        eyebrow={<Link href="/alerts" className="hover:underline">Alerts</Link>}
        title={alert.data?.title ?? "Alert"}
        actions={<RefreshIndicator state={alert} />}
      />
      <PageBody>
        <DataView state={alert}>
          {(a) => (
            <>
              <div className="flex flex-wrap items-center gap-4">
                <SeverityBadge severity={a.severity} />
                <ConfidenceBadge confidence={a.confidence} />
                <ScoreMeter score={a.risk_score} severity={a.severity} />
                <AlertStatusBadge status={a.status} />
              </div>

              <div className="grid gap-6 xl:grid-cols-3">
                <div className="flex min-w-0 flex-col gap-6 xl:col-span-2">
                  <Card>
                    <CardHeader><CardTitle>What was observed</CardTitle></CardHeader>
                    <CardContent><ObservationList observations={a.observations} /></CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>What the evidence cannot show</CardTitle></CardHeader>
                    <CardContent><UncertaintyList items={a.uncertainty} /></CardContent>
                  </Card>
                  <Section title="Supporting evidence" description={`${a.evidence.length} linked event(s)`}>
                    {a.evidence_missing > 0 && (
                      <p className="text-sm text-muted-foreground">{a.evidence_missing} linked event(s) were removed by retention; the observations above still record them.</p>
                    )}
                    {a.evidence.length ? <EventTable events={a.evidence} /> : <EmptyState title="No stored evidence events" />}
                  </Section>
                  {a.rule && (
                    <Card>
                      <CardHeader><CardTitle>Rule explanation</CardTitle></CardHeader>
                      <CardContent><RuleExplanation rule={a.rule} /></CardContent>
                    </Card>
                  )}
                </div>

                <div className="flex min-w-0 flex-col gap-6">
                  <Card>
                    <CardHeader><CardTitle>Triage</CardTitle></CardHeader>
                    <CardContent>
                      <TriagePanel<AlertStatus, AlertDetail>
                        endpoint={`/api/v1/alerts/${a.id}`}
                        current={a.status}
                        statuses={STATUSES}
                        onSaved={alert.setData}
                      />
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>Details</CardTitle></CardHeader>
                    <CardContent>
                      <KeyValues
                        items={[
                          ["Rule", <Mono key="r">{a.rule_id}</Mono>],
                          ["First seen", formatTime(a.first_seen)],
                          ["Last seen", formatTime(a.last_seen)],
                          ["Occurrences", `${a.occurrence_count} (distinct evidence only)`],
                          ["Process", a.image ? (
                            a.process_guid ? <Link key="p" href={`/processes?process_guid=${encodeURIComponent(a.process_guid)}`} className="underline underline-offset-4 break-all">{a.image}</Link> : a.image
                          ) : null],
                          ["PID", a.process_id],
                          ["Incident", a.incident_id ? <Link key="i" href={`/incidents/${a.incident_id}`} className="font-mono text-xs underline underline-offset-4">{a.incident_id.slice(0, 8)}</Link> : null],
                          ["Host", <Mono key="h">{a.host_id}</Mono>],
                        ]}
                      />
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>Risk score</CardTitle></CardHeader>
                    <CardContent><AlertScoreBreakdown entries={a.score_breakdown} /></CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>MITRE ATT&CK</CardTitle></CardHeader>
                    <CardContent><MitreList mappings={a.mitre} /></CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>Correlation entities</CardTitle></CardHeader>
                    <CardContent>
                      <ul className="flex flex-col gap-1">{a.entities.map((e) => <li key={e}><Mono>{e}</Mono></li>)}</ul>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle>History</CardTitle></CardHeader>
                    <CardContent><HistoryList history={a.history} /></CardContent>
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
