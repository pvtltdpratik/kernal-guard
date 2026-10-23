"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"

import { IncidentStatusBadge, ScoreMeter, SeverityBadge } from "@/components/kg/badges"
import { DataView, EmptyState, RefreshIndicator } from "@/components/kg/data-states"
import { FilterBar, SelectFilter, TextFilter } from "@/components/kg/filters"
import { Pager } from "@/components/kg/pager"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useApi } from "@/hooks/use-api"
import { useUrlState } from "@/hooks/use-url-state"
import { INCIDENT_STATUSES, SEVERITIES, type IncidentSummary, type Page } from "@/lib/api/types"
import { formatRelative, formatTime } from "@/lib/format"

const PAGE_SIZE = 25

export function IncidentsView() {
  const router = useRouter()
  const url = useUrlState()
  const incidents = useApi<Page<IncidentSummary>>(
    "/api/v1/incidents",
    {
      status: url.getAll("status"),
      severity: url.getAll("severity"),
      q: url.get("q"),
      sort: url.get("sort") || "-last_seen",
      page: url.page,
      page_size: PAGE_SIZE,
    },
    { refreshMs: 20_000 }
  )

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <FilterBar canClear={url.hasFilters} onClear={() => router.replace("/incidents")}>
          <TextFilter label="Search" value={url.get("q")} onChange={(q) => url.update({ q: q || null })} placeholder="Title" />
          <SelectFilter label="Status" value={url.getAll("status").length === 1 ? url.get("status") : ""} options={INCIDENT_STATUSES}
            allLabel={url.getAll("status").length > 1 ? url.getAll("status").join(" + ") : "All"} onChange={(v) => url.update({ status: v || null })} />
          <SelectFilter label="Severity" value={url.get("severity")} options={SEVERITIES} onChange={(v) => url.update({ severity: v || null })} />
          <SelectFilter label="Sort" value={url.get("sort")} options={["-risk_score", "-severity"]} allLabel="Most recent"
            format={(v) => (v === "-risk_score" ? "Highest score" : "Highest severity")} onChange={(v) => url.update({ sort: v || null })} />
        </FilterBar>
        <RefreshIndicator state={incidents} />
      </div>
      <DataView state={incidents}>
        {(page) =>
          page.items.length === 0 ? (
            <EmptyState title={url.hasFilters ? "No incidents match these filters" : "No incidents"}>
              Incidents are created when alerts are correlated by shared process, parent or file.
            </EmptyState>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Severity</TableHead>
                    <TableHead>Incident</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-end">Alerts</TableHead>
                    <TableHead>Active</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {page.items.map((i) => (
                    <TableRow key={i.id} className="cursor-pointer" onClick={() => router.push(`/incidents/${i.id}`)}>
                      <TableCell><SeverityBadge severity={i.severity} /></TableCell>
                      <TableCell className="max-w-[32rem]">
                        <Link href={`/incidents/${i.id}`} onClick={(e) => e.stopPropagation()} className="line-clamp-2 [overflow-wrap:anywhere] hover:underline">{i.title}</Link>
                      </TableCell>
                      <TableCell><ScoreMeter score={i.risk_score} severity={i.severity} /></TableCell>
                      <TableCell><IncidentStatusBadge status={i.status} /></TableCell>
                      <TableCell className="text-end font-mono text-xs tabular-nums">{i.alert_count}</TableCell>
                      <TableCell className="text-xs whitespace-nowrap" title={`${formatTime(i.first_seen)} → ${formatTime(i.last_seen)}`}>
                        {formatRelative(i.last_seen)}
                      </TableCell>
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
