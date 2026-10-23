"use client"

import * as React from "react"
import { RiCloseLine, RiSearchLine } from "@remixicon/react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { humanize } from "@/lib/format"

export function FilterBar({ children, onClear, canClear }: { children: React.ReactNode; onClear: () => void; canClear: boolean }) {
  return (
    <div className="flex flex-wrap items-end gap-x-4 gap-y-3">
      {children}
      {canClear && (
        <Button size="xs" variant="ghost" onClick={onClear}>
          <RiCloseLine data-icon="inline-start" /> Clear filters
        </Button>
      )}
    </div>
  )
}

function Labelled({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex min-w-0 flex-col gap-1">
      <span className="text-[0.625rem] font-semibold tracking-widest text-muted-foreground uppercase">{label}</span>
      {children}
    </label>
  )
}

export function SelectFilter({ label, value, options, onChange, allLabel = "All", format = humanize }: {
  label: string
  value: string
  options: readonly string[]
  onChange: (value: string) => void
  allLabel?: string
  format?: (value: string) => string
}) {
  return (
    <Labelled label={label}>
      <NativeSelect size="sm" value={value} onChange={(e) => onChange(e.target.value)} className="min-w-36">
        <NativeSelectOption value="">{allLabel}</NativeSelectOption>
        {options.map((option) => (
          <NativeSelectOption key={option} value={option}>
            {format(option)}
          </NativeSelectOption>
        ))}
      </NativeSelect>
    </Labelled>
  )
}

/** Text input that commits on Enter or blur, not per keystroke. */
export function TextFilter({ label, value, onChange, placeholder, type = "text", width = "w-56" }: {
  label: string
  value: string
  onChange: (value: string) => void
  placeholder?: string
  type?: "text" | "number" | "datetime-local"
  width?: string
}) {
  const [draft, setDraft] = React.useState(value)
  const [synced, setSynced] = React.useState(value)
  if (value !== synced) {
    // URL changed externally (e.g. "Clear filters"): follow it.
    setSynced(value)
    setDraft(value)
  }
  const commit = () => {
    if (draft.trim() !== value) onChange(draft.trim())
  }
  return (
    <Labelled label={label}>
      <div className={`relative ${width} max-w-full`}>
        {type === "text" && <RiSearchLine aria-hidden className="pointer-events-none absolute top-1/2 start-0 size-3.5 -translate-y-1/2 text-muted-foreground" />}
        <Input
          type={type}
          value={draft}
          placeholder={placeholder}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => e.key === "Enter" && commit()}
          className={type === "text" ? "ps-5" : undefined}
        />
      </div>
    </Labelled>
  )
}

/** datetime-local works in local time; the API needs ISO 8601 with a timezone. */
export function localInputToIso(value: string): string | undefined {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}
