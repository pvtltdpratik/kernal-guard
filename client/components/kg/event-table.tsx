"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"

import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import type { EventSummary } from "@/lib/api/types"
import { fileName, formatTime, humanize } from "@/lib/format"

export function EventTable({ events }: { events: EventSummary[] }) {
  const router = useRouter()
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Time (activity)</TableHead>
          <TableHead>Category</TableHead>
          <TableHead>Source</TableHead>
          <TableHead>Process</TableHead>
          <TableHead className="text-end">PID</TableHead>
          <TableHead>Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((e) => (
          <TableRow key={e.id} className="cursor-pointer" onClick={() => router.push(`/events/${e.id}`)}>
            <TableCell className="font-mono text-xs whitespace-nowrap">
              <Link href={`/events/${e.id}`} onClick={(ev) => ev.stopPropagation()} className="hover:underline">
                {formatTime(e.timestamp)}
              </Link>
            </TableCell>
            <TableCell>{humanize(e.category)}</TableCell>
            <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
              {e.source === "sysmon" ? "Sysmon" : e.channel} {e.source_event_id}
            </TableCell>
            <TableCell className="max-w-72 truncate" title={e.image ?? undefined}>{fileName(e.image)}</TableCell>
            <TableCell className="text-end font-mono text-xs tabular-nums">{e.process_id ?? "—"}</TableCell>
            <TableCell>
              {e.collection_status !== "complete" && <Badge variant="secondary">{e.collection_status}</Badge>}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
