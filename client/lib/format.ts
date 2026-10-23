import { format, formatDistanceToNowStrict } from "date-fns"

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—"
  return format(new Date(value), "yyyy-MM-dd HH:mm:ss")
}

export function formatRelative(value: string | Date | null | undefined): string {
  if (!value) return "never"
  return `${formatDistanceToNowStrict(new Date(value))} ago`
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}

export function humanize(value: string): string {
  return value.replace(/_/g, " ")
}

/** Last path component of a Windows path, for compact tables. */
export function fileName(path: string | null | undefined): string {
  if (!path) return "—"
  return path.split(/[\\/]/).pop() || path
}

export function shortId(id: string): string {
  return id.slice(0, 8)
}
