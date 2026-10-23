"use client"

import { useRouter } from "next/navigation"

import { DataView, EmptyState, RefreshIndicator } from "@/components/kg/data-states"
import { EventTable } from "@/components/kg/event-table"
import { FilterBar, SelectFilter, TextFilter, localInputToIso } from "@/components/kg/filters"
import { Pager } from "@/components/kg/pager"
import { useApi } from "@/hooks/use-api"
import { useUrlState } from "@/hooks/use-url-state"
import { EVENT_CATEGORIES, type EventSummary, type Page } from "@/lib/api/types"

const PAGE_SIZE = 50

export function EventsView() {
  const router = useRouter()
  const url = useUrlState()
  const pid = url.get("process_id")
  const query = {
    category: url.getAll("category"),
    source: url.get("source"),
    image: url.get("image"),
    process_guid: url.get("process_guid"),
    process_id: /^\d+$/.test(pid) ? pid : undefined,
    since: localInputToIso(url.get("since")),
    until: localInputToIso(url.get("until")),
    sort: url.get("sort") || "-timestamp",
    page: url.page,
    page_size: PAGE_SIZE,
  }
  const events = useApi<Page<EventSummary>>("/api/v1/events", query, { refreshMs: 15_000 })

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <FilterBar canClear={url.hasFilters} onClear={() => router.replace("/events")}>
          <SelectFilter label="Category" value={url.get("category")} options={EVENT_CATEGORIES} onChange={(v) => url.update({ category: v || null })} />
          <SelectFilter label="Source" value={url.get("source")} options={["sysmon", "windows_eventlog"]}
            format={(v) => (v === "sysmon" ? "Sysmon" : "Windows Event Log")} onChange={(v) => url.update({ source: v || null })} />
          <TextFilter label="Process image" value={url.get("image")} onChange={(image) => url.update({ image: image || null })} placeholder="e.g. powershell.exe" />
          <TextFilter label="PID" value={pid} onChange={(v) => url.update({ process_id: v || null })} type="number" width="w-24" />
          <TextFilter label="Process GUID" value={url.get("process_guid")} onChange={(v) => url.update({ process_guid: v || null })} placeholder="{…}" />
          <TextFilter label="From" value={url.get("since")} onChange={(v) => url.update({ since: v || null })} type="datetime-local" width="w-52" />
          <TextFilter label="To" value={url.get("until")} onChange={(v) => url.update({ until: v || null })} type="datetime-local" width="w-52" />
          <SelectFilter label="Order" value={url.get("sort")} options={["timestamp"]} allLabel="Newest first"
            format={() => "Oldest first"} onChange={(v) => url.update({ sort: v || null })} />
        </FilterBar>
        <RefreshIndicator state={events} />
      </div>

      <DataView state={events}>
        {(page) =>
          page.items.length === 0 ? (
            <EmptyState title={url.hasFilters ? "No events match these filters" : "No events collected yet"}>
              {url.hasFilters ? "Widen the time range or clear filters." : "Start the collector: python -m app.collectors (in server/)."}
            </EmptyState>
          ) : (
            <>
              <EventTable events={page.items} />
              <Pager page={page.page} pageSize={page.page_size} total={page.total} onPage={url.setPage} />
            </>
          )
        }
      </DataView>
    </div>
  )
}
