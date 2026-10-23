import type * as React from "react"
import Link from "next/link"
import { RiEyeLine, RiLightbulbLine, RiQuestionLine } from "@remixicon/react"

import { Badge } from "@/components/ui/badge"
import type { InvestigationAction, MitreMapping, Observation, Rule, ScoreEntry } from "@/lib/api/types"
import { formatTime, humanize } from "@/lib/format"

export function ObservationList({ observations }: { observations: Observation[] }) {
  return (
    <ul className="flex flex-col gap-2">
      {observations.map((o, i) => (
        <li key={i} className="flex gap-3 text-sm">
          {o.kind === "observed" ? (
            <RiEyeLine className="mt-0.5 size-4 shrink-0 text-foreground" aria-label="Observed" />
          ) : (
            <RiLightbulbLine className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-label="Inferred" />
          )}
          <div className="min-w-0">
            <span className="me-2 text-[0.625rem] font-semibold tracking-widest text-muted-foreground uppercase">{o.kind}</span>
            <span className={o.kind === "inferred" ? "text-muted-foreground italic" : undefined}>{o.text}</span>
            {o.event_id && (
              <Link href={`/events/${o.event_id}`} className="ms-2 font-mono text-xs underline underline-offset-4">
                event
              </Link>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}

export function UncertaintyList({ items }: { items: string[] }) {
  if (items.length === 0) return <p className="text-sm text-muted-foreground">No limitations recorded for this evidence.</p>
  return (
    <ul className="flex flex-col gap-2">
      {items.map((item) => (
        <li key={item} className="flex gap-3 text-sm text-muted-foreground">
          <RiQuestionLine className="mt-0.5 size-4 shrink-0" aria-hidden />
          {item}
        </li>
      ))}
    </ul>
  )
}

export function MitreList({ mappings }: { mappings: MitreMapping[] }) {
  if (mappings.length === 0) return <p className="text-sm text-muted-foreground">No ATT&CK technique is claimed for this evidence.</p>
  return (
    <ul className="flex flex-col gap-2">
      {mappings.map((m) => (
        <li key={m.technique_id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-sm">
          <a
            href={`https://attack.mitre.org/techniques/${m.technique_id.replace(".", "/")}/`}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-xs underline underline-offset-4"
          >
            {m.technique_id}
          </a>
          <span>{m.name}</span>
          <span className="text-xs text-muted-foreground">{m.tactic}</span>
          <Badge variant={m.relationship === "observed" ? "default" : "secondary"}>{humanize(m.relationship)}</Badge>
        </li>
      ))}
    </ul>
  )
}

/** Alert-level breakdown: severity, adjustments, confidence, total. */
export function AlertScoreBreakdown({ entries }: { entries: ScoreEntry[] }) {
  return (
    <table className="w-full text-sm">
      <tbody className="divide-y">
        {entries.map((e, i) => (
          <tr key={i}>
            <td className="py-1.5 pe-4 text-muted-foreground">
              {e.factor === "severity" && `Severity: ${e.value}`}
              {e.factor === "adjustment" && e.reason}
              {e.factor === "confidence" && `Confidence: ${e.value}`}
              {e.factor === "total" && <span className="font-semibold text-foreground">Risk score{e.capped ? " (capped at 100)" : ""}</span>}
            </td>
            <td className="py-1.5 text-end font-mono text-xs tabular-nums">
              {e.factor === "confidence" ? `× ${e.multiplier}` : e.factor === "adjustment" ? `+${e.points}` : e.points}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Incident-level breakdown: per-alert contribution with reason. */
export function IncidentScoreBreakdown({ entries, total }: { entries: ScoreEntry[]; total: number }) {
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-[0.625rem] tracking-widest text-muted-foreground uppercase">
          <th className="pb-2 text-start font-semibold">Rule</th>
          <th className="pb-2 text-start font-semibold">Reason</th>
          <th className="pb-2 text-end font-semibold">Score</th>
          <th className="pb-2 text-end font-semibold">Weight</th>
          <th className="pb-2 text-end font-semibold">Adds</th>
        </tr>
      </thead>
      <tbody className="divide-y">
        {entries.map((e, i) => (
          <tr key={i} className={e.contribution === 0 ? "text-muted-foreground" : undefined}>
            <td className="py-1.5 pe-3 font-mono text-xs">
              {e.alert_id ? <Link href={`/alerts/${e.alert_id}`} className="underline underline-offset-4">{e.rule_id}</Link> : e.rule_id}
            </td>
            <td className="py-1.5 pe-3">{e.reason}</td>
            <td className="py-1.5 text-end font-mono text-xs tabular-nums">{e.score}</td>
            <td className="py-1.5 text-end font-mono text-xs tabular-nums">{e.weight}</td>
            <td className="py-1.5 text-end font-mono text-xs tabular-nums">{e.contribution}</td>
          </tr>
        ))}
        <tr>
          <td colSpan={4} className="py-1.5 font-semibold">Incident score (capped at 100)</td>
          <td className="py-1.5 text-end font-mono text-xs font-semibold tabular-nums">{total}</td>
        </tr>
      </tbody>
    </table>
  )
}

export function RuleExplanation({ rule }: { rule: Rule }) {
  return (
    <div className="flex flex-col gap-4 text-sm">
      <div>
        <p className="font-semibold">{rule.name} <span className="font-mono text-xs text-muted-foreground">{rule.rule_id} v{rule.version}</span></p>
        <p className="mt-1 text-muted-foreground">{rule.description}</p>
      </div>
      <Field label="Why this matters">{rule.rationale}</Field>
      <Field label="Required evidence">
        <ul className="list-disc ps-5">{rule.required_evidence.map((e) => <li key={e}>{e}</li>)}</ul>
      </Field>
      <Field label="Known false positives">
        <ul className="list-disc ps-5">{rule.false_positives.map((e) => <li key={e}>{e}</li>)}</ul>
      </Field>
      {Object.keys(rule.thresholds).length > 0 && (
        <Field label="Thresholds">
          <span className="font-mono text-xs">{Object.entries(rule.thresholds).map(([k, v]) => `${k}=${v}`).join(", ")}</span>
        </Field>
      )}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="mb-1 text-[0.625rem] font-semibold tracking-widest text-muted-foreground uppercase">{label}</p>
      <div>{children}</div>
    </div>
  )
}

export function HistoryList({ history }: { history: InvestigationAction[] }) {
  if (history.length === 0) return <p className="text-sm text-muted-foreground">No analyst actions yet.</p>
  return (
    <ol className="flex flex-col gap-3 border-s ps-4">
      {history.map((h) => (
        <li key={h.id} className="text-sm">
          <p className="text-xs text-muted-foreground">
            {formatTime(h.created_at)} · {h.actor}
          </p>
          {h.action === "status_change" ? (
            <p>
              Status <span className="text-muted-foreground">{humanize(h.from_status ?? "")}</span> → <strong>{humanize(h.to_status ?? "")}</strong>
            </p>
          ) : (
            <p className="whitespace-pre-wrap">{h.note}</p>
          )}
        </li>
      ))}
    </ol>
  )
}

export function KeyValues({ items }: { items: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-[max-content_1fr]">
      {items.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-[0.625rem] font-semibold tracking-widest text-muted-foreground uppercase sm:pt-0.5">{key}</dt>
          <dd className="min-w-0 break-words">{value ?? <span className="text-muted-foreground">—</span>}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-xs break-all">{children}</span>
}
