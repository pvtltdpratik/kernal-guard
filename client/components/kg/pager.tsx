"use client"

import { RiArrowLeftSLine, RiArrowRightSLine } from "@remixicon/react"

import { Button } from "@/components/ui/button"
import { formatNumber } from "@/lib/format"

export function Pager({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(total, page * pageSize)
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
      <span>
        {formatNumber(from)}–{formatNumber(to)} of {formatNumber(total)}
      </span>
      <div className="flex items-center gap-2">
        <Button size="xs" variant="outline" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          <RiArrowLeftSLine data-icon="inline-start" /> Prev
        </Button>
        <span className="tabular-nums">
          Page {page} / {formatNumber(pages)}
        </span>
        <Button size="xs" variant="outline" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          Next <RiArrowRightSLine data-icon="inline-end" />
        </Button>
      </div>
    </div>
  )
}
