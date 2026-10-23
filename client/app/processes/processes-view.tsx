"use client"

import * as React from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"

import { DataView, EmptyState, RefreshIndicator } from "@/components/kg/data-states"
import { FilterBar, TextFilter } from "@/components/kg/filters"
import { Pager } from "@/components/kg/pager"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useApi } from "@/hooks/use-api"
import { useUrlState } from "@/hooks/use-url-state"
import type { Page, ProcessSummary } from "@/lib/api/types"
import { fileName, formatRelative, formatTime } from "@/lib/format"

const PAGE_SIZE = 50

export function ProcessesView() {
  const router = useRouter()
  const url = useUrlState()
  const pid = url.get("process_id")
  const guid = url.get("process_guid")
  const processes = useApi<Page<ProcessSummary>>(
    "/api/v1/processes",
    { image: url.get("image"), process_guid: guid, process_id: /^\d+$/.test(pid) ? pid : undefined, page: url.page, page_size: PAGE_SIZE },
    { refreshMs: 30_000 }
  )

  // Arriving from an alert or event with a GUID: go straight to the process.
  const only = guid && processes.data?.total === 1 ? processes.data.items[0] : undefined
  React.useEffect(() => {
    if (only) router.replace(`/processes/${only.id}`)
  }, [only, router])

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <FilterBar canClear={url.hasFilters} onClear={() => router.replace("/processes")}>
          <TextFilter label="Image" value={url.get("image")} onChange={(v) => url.update({ image: v || null })} placeholder="Path or file name" />
          <TextFilter label="PID" value={pid} onChange={(v) => url.update({ process_id: v || null })} type="number" width="w-24" />
          <TextFilter label="Process GUID" value={guid} onChange={(v) => url.update({ process_guid: v || null })} placeholder="{…}" />
        </FilterBar>
        <RefreshIndicator state={processes} />
      </div>
      <DataView state={processes}>
        {(page) =>
          page.items.length === 0 ? (
            <EmptyState title="No processes found">
              {url.hasFilters
                ? "No tracked process matches. Processes are only tracked from events that identify them (Sysmon or Security 4688)."
                : "Processes appear once Sysmon or Security 4688 events are collected."}
            </EmptyState>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Image</TableHead>
                    <TableHead className="text-end">PID</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Last activity</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {page.items.map((p) => (
                    <TableRow key={p.id} className="cursor-pointer" onClick={() => router.push(`/processes/${p.id}`)}>
                      <TableCell className="max-w-96">
                        <Link href={`/processes/${p.id}`} onClick={(e) => e.stopPropagation()} className="hover:underline">{fileName(p.image)}</Link>
                        <p className="truncate text-xs text-muted-foreground" title={p.image ?? undefined}>{p.image ?? "image unknown"}</p>
                      </TableCell>
                      <TableCell className="text-end font-mono text-xs tabular-nums">{p.process_id ?? "—"}</TableCell>
                      <TableCell className="text-xs">{p.user ?? "—"}</TableCell>
                      <TableCell className="text-xs whitespace-nowrap">
                        {p.creation_observed ? formatTime(p.start_time) : <Badge variant="secondary">not observed</Badge>}
                      </TableCell>
                      <TableCell className="text-xs whitespace-nowrap">{formatRelative(p.last_seen)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <Pager page={page.page} pageSize={page.page_size} total={page.total} onPage={url.setPage} />
            </>
          )
        }
      </DataView>
    </div>
  )
}
