"use client"

import * as React from "react"
import Link from "next/link"
import { useParams } from "next/navigation"
import { RiCodeLine } from "@remixicon/react"

import { DataView, ErrorState } from "@/components/kg/data-states"
import { KeyValues, Mono } from "@/components/kg/explain"
import { PageBody, PageHeader } from "@/components/kg/page-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useApi } from "@/hooks/use-api"
import type { EventDetail } from "@/lib/api/types"
import { formatTime, humanize } from "@/lib/format"

export function EventDetailView() {
  const { id } = useParams<{ id: string }>()
  const event = useApi<EventDetail>(`/api/v1/events/${encodeURIComponent(id)}`)

  return (
    <>
      <PageHeader
        eyebrow={<Link href="/events" className="hover:underline">Event Explorer</Link>}
        title={event.data ? `${humanize(event.data.category)} · ${event.data.source === "sysmon" ? "Sysmon" : event.data.channel} ${event.data.source_event_id}` : "Event"}
      />
      <PageBody>
        <DataView state={event}>{(e) => <EventBody event={e} />}</DataView>
      </PageBody>
    </>
  )
}

function EventBody({ event: e }: { event: EventDetail }) {
  const [showRaw, setShowRaw] = React.useState(false)
  // Raw XML is fetched only on request: it can contain sensitive command lines.
  const raw = useApi<EventDetail>(showRaw ? `/api/v1/events/${e.id}` : null, { include_raw: true })
  const data = Object.entries(e.data).filter(([k]) => !k.startsWith("_kg_"))

  return (
    <div className="grid gap-6 xl:grid-cols-3">
      <div className="flex min-w-0 flex-col gap-6 xl:col-span-2">
        <Card>
          <CardHeader>
            <CardTitle>Event data</CardTitle>
            <CardDescription>All fields as reported by the source; nothing is inferred.</CardDescription>
          </CardHeader>
          <CardContent>
            <KeyValues items={data.map(([k, v]) => [k, v === null || v === "" ? null : <Mono key={k}>{String(v)}</Mono>])} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Original source event</CardTitle>
            <CardDescription>Raw Windows event XML. May contain sensitive command-line arguments.</CardDescription>
          </CardHeader>
          <CardContent>
            {!showRaw ? (
              <Button size="xs" variant="outline" onClick={() => setShowRaw(true)}>
                <RiCodeLine data-icon="inline-start" /> Show raw XML
              </Button>
            ) : raw.error ? (
              <ErrorState error={raw.error} onRetry={raw.reload} />
            ) : raw.data ? (
              raw.data.raw_xml ? (
                <pre className="max-h-96 overflow-auto bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">{raw.data.raw_xml}</pre>
              ) : (
                <p className="text-sm text-muted-foreground">Raw XML was not stored (KG_STORE_RAW_XML=false when collected).</p>
              )
            ) : (
              <p className="text-sm text-muted-foreground">Loading…</p>
            )}
          </CardContent>
        </Card>
      </div>
      <div className="flex min-w-0 flex-col gap-6">
        <Card>
          <CardHeader><CardTitle>Normalised fields</CardTitle></CardHeader>
          <CardContent>
            <KeyValues
              items={[
                ["Activity time", formatTime(e.timestamp)],
                ["Logged", formatTime(e.logged_at)],
                ["Ingested", formatTime(e.ingested_at)],
                ["Collection", e.collection_status === "complete" ? "complete" : (
                  <span key="c" className="flex flex-col gap-1">
                    <Badge variant="secondary">{e.collection_status}</Badge>
                    {e.missing_fields.length > 0 && <span className="text-xs text-muted-foreground">Missing: {e.missing_fields.join(", ")}</span>}
                  </span>
                )],
                ["Process", e.image ? <Mono key="i">{e.image}</Mono> : null],
                ["PID", e.process_id],
                ["Process GUID", e.process_guid ? <Link key="g" href={`/processes?process_guid=${encodeURIComponent(e.process_guid)}`} className="font-mono text-xs underline underline-offset-4 break-all">{e.process_guid}</Link> : null],
                ["Parent", e.parent_image ? <Mono key="pi">{e.parent_image}</Mono> : null],
                ["Parent PID", e.parent_process_id],
                ["User", e.user],
                ["SHA-256", e.sha256 ? <Mono key="s">{e.sha256}</Mono> : null],
                ["Signed", e.signed === null ? null : `${e.signed ? "yes" : "no"}${e.signature ? ` · ${e.signature}` : ""}${e.signature_status ? ` (${e.signature_status})` : ""}`],
                ["Provider", e.provider],
                ["Record", <Mono key="r">{`${e.channel} #${e.record_id}`}</Mono>],
                ["Host", e.hostname ?? <Mono key="h">{e.host_id}</Mono>],
              ]}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
