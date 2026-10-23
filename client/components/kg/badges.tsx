import { cn } from "cn"

import { Badge } from "@/components/ui/badge"
import { humanize } from "@/lib/format"
import type { AlertStatus, Confidence, IncidentStatus, SensorState, Severity, Visibility } from "@/lib/api/types"

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  informational: "text-sev-info",
}

const SEVERITY_DOT: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  informational: "bg-sev-info",
}

export function severityColor(severity: Severity): string {
  return `var(--sev-${severity === "informational" ? "info" : severity})`
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge className={cn(SEVERITY_CLASS[severity], className)}>
      <span aria-hidden className={cn("size-1.5 rounded-full", SEVERITY_DOT[severity])} />
      {severity === "informational" ? "info" : severity}
    </Badge>
  )
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  return <Badge variant="secondary">{confidence} confidence</Badge>
}

const ALERT_STATUS_VARIANT: Record<AlertStatus, "default" | "secondary" | "ghost"> = {
  new: "default",
  acknowledged: "default",
  reviewed: "secondary",
  false_positive: "ghost",
}

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return (
    <Badge variant={ALERT_STATUS_VARIANT[status]} className={status === "new" ? "text-sev-high" : undefined}>
      {humanize(status)}
    </Badge>
  )
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return <Badge variant={status === "closed" ? "secondary" : "default"}>{status}</Badge>
}

export function SensorStateBadge({ state, stale }: { state: SensorState; stale?: boolean }) {
  const tone = state === "ok" ? (stale ? "text-sev-medium" : "text-ok") : state === "never_run" ? "text-muted-foreground" : "text-sev-critical"
  return (
    <Badge className={tone}>
      <span aria-hidden className="size-1.5 rounded-full bg-current" />
      {state === "ok" && stale ? "ok · stale" : humanize(state)}
    </Badge>
  )
}

export function VisibilityBadge({ visibility }: { visibility: Visibility }) {
  const tone = visibility === "observable" ? "text-ok" : visibility === "partially_observable" ? "text-sev-medium" : "text-muted-foreground"
  return <Badge className={tone}>{humanize(visibility)}</Badge>
}

export function ScoreMeter({ score, severity }: { score: number; severity: Severity }) {
  return (
    <div className="flex items-center gap-2" title={`Risk score ${score}/100`}>
      <div className="h-1 w-14 bg-muted" aria-hidden>
        <div className={cn("h-full", SEVERITY_DOT[severity])} style={{ width: `${Math.max(2, score)}%` }} />
      </div>
      <span className="font-mono text-xs tabular-nums">{score}</span>
    </div>
  )
}
