"use client"

import * as React from "react"

import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { ApiError, apiPatch } from "@/lib/api/client"
import { humanize } from "@/lib/format"

/**
 * Status buttons plus an optional note, sent as one PATCH. Every change is
 * recorded server-side in the investigation history. Nothing here deletes
 * data or acts on the endpoint.
 */
export function TriagePanel<TStatus extends string, TResult>({
  endpoint,
  current,
  statuses,
  onSaved,
}: {
  endpoint: string
  current: TStatus
  statuses: { value: TStatus; label: string; hint: string }[]
  onSaved: (result: TResult) => void
}) {
  const [note, setNote] = React.useState("")
  const [pending, setPending] = React.useState<string | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  const submit = async (status: TStatus | null) => {
    if (status === null && !note.trim()) return
    setPending(status ?? "note")
    setError(null)
    try {
      const body: Record<string, string> = {}
      if (status !== null) body.status = status
      if (note.trim()) body.note = note.trim()
      const result = await apiPatch<TResult>(endpoint, body)
      setNote("")
      onSaved(result)
    } catch (err) {
      setError(err instanceof ApiError ? `${err.message}${err.requestId ? ` (request ${err.requestId})` : ""}` : String(err))
    } finally {
      setPending(null)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm">
        Current status: <strong>{humanize(current)}</strong>
      </p>
      <div className="flex flex-wrap gap-2">
        {statuses
          .filter((s) => s.value !== current)
          .map((s) => (
            <Button key={s.value} size="xs" variant="outline" disabled={pending !== null} onClick={() => submit(s.value)} title={s.hint}>
              {pending === s.value ? "Saving…" : s.label}
            </Button>
          ))}
      </div>
      <Textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        maxLength={4000}
        placeholder="Investigation note (saved with the next action, or on its own)"
        rows={3}
      />
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-muted-foreground">{note.length}/4000</span>
        <Button size="xs" disabled={pending !== null || !note.trim()} onClick={() => submit(null)}>
          {pending === "note" ? "Saving…" : "Add note"}
        </Button>
      </div>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  )
}
