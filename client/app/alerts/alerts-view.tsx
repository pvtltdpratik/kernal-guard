"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"

import { AlertStatusBadge, ScoreMeter, SeverityBadge } from "@/components/kg/badges"
import { DataView, EmptyState, RefreshIndicator } from "@/components/kg/data-states"
import { FilterBar, SelectFilter, TextFilter } from "@/components/kg/filters"
import { Pager } from "@/components/kg/pager"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useApi } from "@/hooks/use-api"
import { useUrlState } from "@/hooks/use-url-state"
import { ALERT_STATUSES, SEVERITIES, type AlertSummary, type Page, type Rule } from "@/lib/api/types"
import { fileName, formatRelative, formatTime } from "@/lib/format"

const PAGE_SIZE = 25
const SORTS = ["-last_seen", "-risk_score", "-severity", "-first_seen", "last_seen"] as const
const SORT_LABELS: Record<(typeof SORTS)[number], string> = {
  "-last_seen": "Most recent",
  "-risk_score": "Highest score",
  "-severity": "Highest severity",
  "-first_seen": "Newest first seen",
  last_seen: "Oldest",
}

export function AlertsView() {
  const router = useRouter()
  const url = useUrlState()
  const rules = useApi<Rule[]>("/api/v1/detection/rules")
  const query = {
    status: url.getAll("status"),
    severity: url.getAll("severity"),
    rule_id: url.get("rule_id"),
    incident_id: url.get("incident_id"),
    q: url.get("q"),
    min_score: url.get("min_score"),
    sort: url.get("sort") || "-last_seen",
    page: url.page,
    page_size: PAGE_SIZE,
  }
  const alerts = useApi<Page<AlertSummary>>("/api/v1/alerts", query, { refreshMs: 20_000 })

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <FilterBar canClear={url.hasFilters} onClear={() => router.replace("/alerts")}>
          <TextFilter label="Search" value={url.get("q")} onChange={(q) => url.update({ q })} placeholder="Title or image path" />
          <SelectFilter label="Status" value={url.getAll("status").length === 1 ? url.get("status") : ""} options={ALERT_STATUSES}
            allLabel={url.getAll("status").length > 1 ? url.getAll("status").join(" + ") : "All"} onChange={(v) => url.update({ status: v || null })} />
          <SelectFilter label="Severity" value={url.getAll("severity").length === 1 ? url.get("severity") : ""} options={SEVERITIES}
            onChange={(v) => url.update({ severity: v || null })} />
          <SelectFilter label="Rule" value={url.get("rule_id")} options={(rules.data ?? []).map((r) => r.rule_id)}
            format={(id) => `${id} · ${rules.data?.find((r) => r.rule_id === id)?.name ?? ""}`} onChange={(v) => url.update({ rule_id: v || null })} />
          <SelectFilter label="Min score" value={url.get("min_score")} options={["25", "50", "70", "85"]} allLabel="Any"
            format={(v) => `≥ ${v}`} onChange={(v) => url.update({ min_score: v || null })} />
          <SelectFilter label="Sort" value={url.get("sort")} options={SORTS.slice(1)} allLabel={SORT_LABELS["-last_seen"]}
            format={(v) => SORT_LABELS[v as (typeof SORTS)[number]]} onChange={(v) => url.update({ sort: v || null })} />
        </FilterBar>
        <RefreshIndicator state={alerts} />
      </div>

      <DataView state={alerts}>
        {(page) =>
          page.items.length === 0 ? (
            <EmptyState title={url.hasFilters ? "No alerts match these filters" : "No alerts"}>
              {url.hasFilters ? "Clear filters to see all alerts." : "Detections appear here when rules fire on collected telemetry."}
            </EmptyState>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Severity</TableHead>
                    <TableHead>Alert</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-end">Seen</TableHead>
                    <TableHead>Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {page.items.map((a) => (
                    <TableRow key={a.id} className="cursor-pointer" onClick={() => router.push(`/alerts/${a.id}`)}>
                      <TableCell><SeverityBadge severity={a.severity} /></TableCell>
                      <TableCell className="max-w-[32rem]">
                        <Link href={`/alerts/${a.id}`} onClick={(e) => e.stopPropagation()} className="line-clamp-2 [overflow-wrap:anywhere] hover:underline">{a.title}</Link>
                        <span className="text-xs text-muted-foreground">
                          <span className="font-mono">{a.rule_id}</span> · {a.confidence} confidence{a.image ? ` · ${fileName(a.image)}` : ""}
                        </span>
                      </TableCell>
                      <TableCell><ScoreMeter score={a.risk_score} severity={a.severity} /></TableCell>
                      <TableCell><AlertStatusBadge status={a.status} /></TableCell>
                      <TableCell className="text-end font-mono text-xs tabular-nums" title="Distinct evidence occurrences">{a.occurrence_count}×</TableCell>
                      <TableCell className="text-xs whitespace-nowrap" title={formatTime(a.last_seen)}>{formatRelative(a.last_seen)}</TableCell>
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
