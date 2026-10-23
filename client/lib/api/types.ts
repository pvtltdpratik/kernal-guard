// TypeScript mirrors of the KernelGuard API schemas (server/app/schemas).
// Keep in sync with the backend; field names match the JSON exactly.

export type Severity = "informational" | "low" | "medium" | "high" | "critical"
export type Confidence = "low" | "medium" | "high"
export type AlertStatus = "new" | "acknowledged" | "reviewed" | "false_positive"
export type IncidentStatus = "open" | "investigating" | "closed"
export type CollectionStatus = "complete" | "partial" | "truncated"
export type EventSource = "sysmon" | "windows_eventlog"
export type SensorState = "ok" | "unavailable" | "access_denied" | "error" | "never_run"
export type Visibility = "observable" | "partially_observable" | "not_observable"

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"]
export const ALERT_STATUSES: AlertStatus[] = ["new", "acknowledged", "reviewed", "false_positive"]
export const INCIDENT_STATUSES: IncidentStatus[] = ["open", "investigating", "closed"]

export const EVENT_CATEGORIES = [
  "process_creation",
  "process_termination",
  "network_connection",
  "dns_query",
  "image_load",
  "driver_load",
  "process_access",
  "remote_thread",
  "process_tampering",
  "file_create",
  "file_time_change",
  "file_stream",
  "file_delete",
  "raw_access_read",
  "registry_key",
  "registry_value_set",
  "registry_rename",
  "pipe",
  "wmi",
  "service_install",
  "log_cleared",
  "sensor_state",
  "other",
] as const
export type EventCategory = (typeof EVENT_CATEGORIES)[number]

export interface Page<T> {
  items: T[]
  page: number
  page_size: number
  total: number
}

export interface ApiErrorBody {
  error: {
    code: string
    message: string
    details: unknown
    request_id: string | null
  }
}

// ----------------------------------------------------------------- health

export interface ComponentHealth {
  status: "ok" | "error"
  detail: string | null
}

export interface HealthResponse {
  status: "ok" | "degraded"
  version: string
  environment: string
  timestamp: string
  components: Record<string, ComponentHealth>
}

// ----------------------------------------------------------------- events

export interface EventSummary {
  id: string
  source: EventSource
  channel: string
  source_event_id: number
  record_id: number
  timestamp: string
  ingested_at: string
  host_id: string
  hostname: string | null
  category: EventCategory
  process_guid: string | null
  process_id: number | null
  image: string | null
  parent_process_id: number | null
  parent_image: string | null
  user: string | null
  collection_status: CollectionStatus
}

export interface EventDetail extends EventSummary {
  provider: string | null
  logged_at: string
  parent_process_guid: string | null
  sha256: string | null
  sha1: string | null
  md5: string | null
  imphash: string | null
  signed: boolean | null
  signature: string | null
  signature_status: string | null
  data: Record<string, unknown>
  missing_fields: string[]
  raw_xml: string | null
}

// -------------------------------------------------------------- detection

export interface MitreMapping {
  technique_id: string
  name: string
  tactic: string
  relationship: "observed" | "consistent_with"
}

export interface Observation {
  kind: "observed" | "inferred"
  text: string
  event_id: string | null
}

export interface Rule {
  rule_id: string
  name: string
  description: string
  category: string
  kind: "event" | "correlation"
  severity: Severity
  confidence: Confidence
  rationale: string
  required_evidence: string[]
  false_positives: string[]
  mitre: MitreMapping[]
  thresholds: Record<string, number>
  version: number
  enabled: boolean
}

// Score breakdown entries are heterogeneous by design (see server scoring.py).
export type ScoreEntry = {
  factor?: "severity" | "adjustment" | "confidence" | "total"
  value?: string
  reason?: string
  points?: number
  multiplier?: number
  capped?: boolean
  alert_id?: string
  rule_id?: string
  score?: number
  weight?: number
  contribution?: number
}

export interface InvestigationAction {
  id: string
  action: "status_change" | "note"
  from_status: string | null
  to_status: string | null
  note: string | null
  actor: string
  created_at: string
}

export interface AlertSummary {
  id: string
  rule_id: string
  title: string
  severity: Severity
  confidence: Confidence
  risk_score: number
  status: AlertStatus
  host_id: string
  process_guid: string | null
  process_id: number | null
  image: string | null
  occurrence_count: number
  first_seen: string
  last_seen: string
  incident_id: string | null
}

export interface AlertDetail extends AlertSummary {
  rule: Rule | null
  observations: Observation[]
  uncertainty: string[]
  entities: string[]
  mitre: MitreMapping[]
  score_breakdown: ScoreEntry[]
  evidence: EventSummary[]
  evidence_missing: number
  history: InvestigationAction[]
  created_at: string
  updated_at: string
}

export interface IncidentSummary {
  id: string
  title: string
  status: IncidentStatus
  severity: Severity
  risk_score: number
  host_id: string
  first_seen: string
  last_seen: string
  alert_count: number
}

export interface TimelineEntry {
  timestamp: string
  kind: "event" | "alert"
  event: EventSummary | null
  alert_id: string | null
  rule_id: string | null
  title: string
  observations: Observation[]
}

export interface IncidentDetail extends IncidentSummary {
  entities: string[]
  score_breakdown: ScoreEntry[]
  alerts: AlertSummary[]
  rules_fired: Rule[]
  timeline: TimelineEntry[]
  uncertainty: string[]
  history: InvestigationAction[]
  created_at: string
  updated_at: string
}

export interface ProcessSummary {
  id: string
  key: string
  host_id: string
  process_guid: string | null
  process_id: number | null
  image: string | null
  user: string | null
  start_time: string | null
  end_time: string | null
  first_seen: string
  last_seen: string
  creation_observed: boolean
}

export interface NetworkSummary {
  destination_ip: string | null
  destination_port: string | null
  destination_hostname: string | null
  protocol: string | null
  connections: number
  first_seen: string
  last_seen: string
}

export interface ProcessDetail extends ProcessSummary {
  command_line: string | null
  integrity_level: string | null
  parent_process_guid: string | null
  parent_process_id: number | null
  parent_image: string | null
  sha256: string | null
  sha1: string | null
  md5: string | null
  imphash: string | null
  sources: string[]
  conflicts: { field: string; kept: string; observed: string; event_id: string }[]
  signature: { signed: boolean | null; signature: string | null; status: string | null; observed_at: string; event_id: string } | null
  parent: ProcessSummary | null
  children: ProcessSummary[]
  event_counts: Record<string, number>
  network: NetworkSummary[]
  alerts: AlertSummary[]
}

export interface Capability {
  technique_id: string
  technique: string
  design_visibility: Visibility
  effective_visibility: Visibility
  effective_note: string | null
  sensors: string[]
  evidence: string
  gaps: string
  rules: string[]
}

// ---------------------------------------------------------------- sensors

export interface SensorStatus {
  sensor: string
  channel: string
  description: string
  requirements: string[]
  enabled: boolean
  state: SensorState
  detail: string | null
  stale: boolean
  last_attempt_at: string | null
  last_success_at: string | null
  last_error_at: string | null
  consecutive_failures: number
  events_ingested: number
  duplicates_skipped: number
  parse_failures: number
  records_ignored: number
  records_missed: number
  detection_failures: number
}

export interface SensorStatusResponse {
  generated_at: string
  collector_interval_seconds: number
  collector_stale: boolean
  sensors: SensorStatus[]
}

// ---------------------------------------------------------------- metrics

export interface MetricsOverview {
  generated_at: string
  total_events: number
  events_last_24h: number
  active_alerts: number
  alerts_by_severity: { severity: Severity; count: number }[]
  open_incidents: number
  recent_incidents: IncidentSummary[]
  sensors: { sensor: string; state: SensorState; stale: boolean }[]
  event_volume: { bucket_start: string; count: number }[]
  event_volume_bucket: "hour" | "day"
  top_rules: { rule_id: string; active_alerts: number }[]
}
