"use client"

import Link from "next/link"
import { useParams } from "next/navigation"
import { RiArrowRightDownLine, RiArrowRightUpLine } from "@remixicon/react"

import { AlertStatusBadge, ScoreMeter, SeverityBadge } from "@/components/kg/badges"
import { DataView, EmptyState, RefreshIndicator } from "@/components/kg/data-states"
import { EventTable } from "@/components/kg/event-table"
import { KeyValues, Mono } from "@/components/kg/explain"
import { PageBody, PageHeader, Section } from "@/components/kg/page-header"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useApi } from "@/hooks/use-api"
import type { EventSummary, Page, ProcessDetail, ProcessSummary } from "@/lib/api/types"
import { fileName, formatRelative, formatTime, humanize } from "@/lib/format"

export function ProcessDetailView() {
  const { id } = useParams<{ id: string }>()
  const process = useApi<ProcessDetail>(`/api/v1/processes/${encodeURIComponent(id)}`, undefined, { refreshMs: 30_000 })
  return (
    <>
      <PageHeader
        eyebrow={<Link href="/processes" className="hover:underline">Processes</Link>}
        title={process.data ? `${fileName(process.data.image)}${process.data.process_id !== null ? ` (PID ${process.data.process_id})` : ""}` : "Process"}
        description={process.data?.image}
        actions={<RefreshIndicator state={process} />}
      />
      <PageBody>
        <DataView state={process}>{(p) => <ProcessBody process={p} />}</DataView>
      </PageBody>
    </>
  )
}

function ProcessLink({ process }: { process: ProcessSummary }) {
  return (
    <Link href={`/processes/${process.id}`} className="underline underline-offset-4">
      {fileName(process.image)}
      {process.process_id !== null && <span className="ms-1 font-mono text-xs text-muted-foreground">PID {process.process_id}</span>}
    </Link>
  )
}

function ProcessBody({ process: p }: { process: ProcessDetail }) {
  const related = useApi<Page<EventSummary>>(
    p.process_guid ? "/api/v1/events" : null,
    { process_guid: p.process_guid, page_size: 25, sort: "timestamp" }
  )
  const totalEvents = Object.values(p.event_counts).reduce((a, b) => a + b, 0)

  return (
    <div className="grid gap-6 xl:grid-cols-3">
      <div className="flex min-w-0 flex-col gap-6 xl:col-span-2">
        {!p.creation_observed && (
          <p className="border-s-2 border-sev-medium ps-3 text-sm text-muted-foreground">
            The creation event for this process was not observed (started before collection, filtered, or not yet delivered).
            Start time, command line and hashes are therefore unknown, not absent.
          </p>
        )}

        <Card>
          <CardHeader><CardTitle>Process tree</CardTitle></CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            <div className="flex items-center gap-2">
              <RiArrowRightUpLine className="size-4 text-muted-foreground" aria-hidden />
              <span className="text-[0.625rem] font-semibold tracking-widest text-muted-foreground uppercase">Parent</span>
              {p.parent ? <ProcessLink process={p.parent} /> : p.parent_image ? (
                <span>{fileName(p.parent_image)} <span className="text-xs text-muted-foreground">(not tracked)</span></span>
              ) : <span className="text-muted-foreground">unknown</span>}
            </div>
            <div className="ms-6 border-s ps-4 font-semibold">{fileName(p.image)}</div>
            <div className="ms-6 flex flex-col gap-1 border-s ps-4">
              {p.children.length === 0 ? (
                <span className="text-muted-foreground">No child processes observed</span>
              ) : (
                p.children.map((c) => (
                  <span key={c.id} className="flex items-center gap-2">
                    <RiArrowRightDownLine className="size-4 text-muted-foreground" aria-hidden />
                    <ProcessLink process={c} />
                    <span className="text-xs text-muted-foreground">{formatTime(c.start_time ?? c.first_seen)}</span>
                  </span>
                ))
              )}
            </div>
          </CardContent>
        </Card>

        <Section title="Alerts involving this process">
          {p.alerts.length === 0 ? <EmptyState title="No alerts" /> : (
            <ul className="divide-y border">
              {p.alerts.map((a) => (
                <li key={a.id}>
                  <Link href={`/alerts/${a.id}`} className="flex flex-wrap items-center gap-3 px-4 py-3 hover:bg-muted/50">
                    <SeverityBadge severity={a.severity} />
                    <span className="min-w-0 flex-1 text-sm">{a.title}</span>
                    <ScoreMeter score={a.risk_score} severity={a.severity} />
                    <AlertStatusBadge status={a.status} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Network activity" description="Outbound and inbound connections grouped by destination">
          {p.network.length === 0 ? <EmptyState title="No network connections observed">Sysmon event 3 is required.</EmptyState> : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Destination</TableHead>
                  <TableHead>Port</TableHead>
                  <TableHead className="text-end">Connections</TableHead>
                  <TableHead>First</TableHead>
                  <TableHead>Last</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {p.network.map((n, i) => (
                  <TableRow key={i}>
                    <TableCell><Mono>{n.destination_ip}</Mono>{n.destination_hostname && <p className="text-xs text-muted-foreground">{n.destination_hostname}</p>}</TableCell>
                    <TableCell className="font-mono text-xs">{n.destination_port}/{n.protocol}</TableCell>
                    <TableCell className="text-end font-mono text-xs tabular-nums">{n.connections}</TableCell>
                    <TableCell className="text-xs whitespace-nowrap">{formatTime(n.first_seen)}</TableCell>
                    <TableCell className="text-xs whitespace-nowrap">{formatRelative(n.last_seen)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Section>

        <Section
          title="Related events"
          description={`${totalEvents} event(s): ${Object.entries(p.event_counts).map(([k, v]) => `${v} ${humanize(k)}`).join(", ") || "none"}`}
          actions={p.process_guid ? <Link href={`/events?process_guid=${encodeURIComponent(p.process_guid)}`} className="text-xs underline underline-offset-4">Open in Event Explorer</Link> : undefined}
        >
          {!p.process_guid ? (
            <p className="text-sm text-muted-foreground">This process has no GUID (Security 4688); filter events by PID {p.process_id} and time instead.</p>
          ) : (
            <DataView state={related}>
              {(page) => page.items.length ? <EventTable events={page.items} /> : <EmptyState title="No events" />}
            </DataView>
          )}
        </Section>
      </div>

      <div className="flex min-w-0 flex-col gap-6">
        <Card>
          <CardHeader><CardTitle>Metadata</CardTitle></CardHeader>
          <CardContent>
            <KeyValues
              items={[
                ["Image", p.image ? <Mono key="i">{p.image}</Mono> : null],
                ["Command line", p.command_line ? <Mono key="c">{p.command_line}</Mono> : null],
                ["User", p.user],
                ["Integrity", p.integrity_level],
                ["Started", p.start_time ? formatTime(p.start_time) : null],
                ["Ended", p.end_time ? formatTime(p.end_time) : <span key="r" className="text-muted-foreground">no termination observed</span>],
                ["First / last seen", `${formatTime(p.first_seen)} → ${formatTime(p.last_seen)}`],
                ["PID", p.process_id],
                ["GUID", p.process_guid ? <Mono key="g">{p.process_guid}</Mono> : null],
                ["Sources", p.sources.join(", ")],
              ]}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>File identity</CardTitle>
            <CardDescription>Hashes from the process-creation event; signature only if an image-load event for this file was collected.</CardDescription>
          </CardHeader>
          <CardContent>
            <KeyValues
              items={[
                ["SHA-256", p.sha256 ? <Mono key="s">{p.sha256}</Mono> : null],
                ["SHA-1", p.sha1 ? <Mono key="s1">{p.sha1}</Mono> : null],
                ["MD5", p.md5 ? <Mono key="m">{p.md5}</Mono> : null],
                ["Imphash", p.imphash ? <Mono key="h">{p.imphash}</Mono> : null],
                ["Signature", p.signature ? (
                  <span key="sig">
                    {p.signature.signed ? "Signed" : "Not signed"}{p.signature.signature ? ` · ${p.signature.signature}` : ""}
                    {p.signature.status && <Badge variant="secondary" className="ms-2">{p.signature.status}</Badge>}
                  </span>
                ) : <span key="ns" className="text-muted-foreground">not observed</span>],
              ]}
            />
          </CardContent>
        </Card>
        {p.conflicts.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Conflicting evidence</CardTitle>
              <CardDescription>Later events disagreed with the first recorded value; the first value is kept.</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="flex flex-col gap-2 text-sm">
                {p.conflicts.map((c, i) => (
                  <li key={i}>
                    <span className="font-semibold">{humanize(c.field)}</span>: kept <Mono>{c.kept}</Mono>, observed <Mono>{c.observed}</Mono>{" "}
                    <Link href={`/events/${c.event_id}`} className="text-xs underline underline-offset-4">event</Link>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
