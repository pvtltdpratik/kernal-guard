"use client"

import type * as React from "react"
import { RiErrorWarningLine, RiInboxLine, RiRefreshLine, RiTimeLine, RiWifiOffLine } from "@remixicon/react"

import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import type { ApiState } from "@/hooks/use-api"
import { API_BASE_URL, type ApiError } from "@/lib/api/client"
import { formatRelative } from "@/lib/format"

export function LoadingRows({ rows = 6 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
      ))}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const offline = error.isNetworkError
  return (
    <Alert variant="destructive">
      {offline ? <RiWifiOffLine /> : <RiErrorWarningLine />}
      <AlertTitle>{offline ? "KernelGuard API unreachable" : `Request failed (${error.status})`}</AlertTitle>
      <AlertDescription>
        <p>{error.message}</p>
        {offline && (
          <p className="text-muted-foreground">
            Start it with <code className="font-mono">python -m app</code> in <code className="font-mono">server/</code>,
            or set <code className="font-mono">NEXT_PUBLIC_KG_API_URL</code> (currently {API_BASE_URL}).
          </p>
        )}
        {error.requestId && <p className="font-mono text-xs text-muted-foreground">request id {error.requestId}</p>}
      </AlertDescription>
      {onRetry && (
        <AlertAction>
          <Button size="xs" variant="outline" onClick={onRetry}>
            <RiRefreshLine data-icon="inline-start" /> Retry
          </Button>
        </AlertAction>
      )}
    </Alert>
  )
}

export function EmptyState({ title, children, icon }: { title: string; children?: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <Empty className="border border-dashed">
      <EmptyHeader>
        <EmptyMedia variant="icon">{icon ?? <RiInboxLine />}</EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        {children && <EmptyDescription>{children}</EmptyDescription>}
      </EmptyHeader>
    </Empty>
  )
}

/** Shown above data when the last refresh failed or data is old. */
export function StaleNotice({ state }: { state: Pick<ApiState<unknown>, "stale" | "error" | "lastUpdated" | "reload"> }) {
  if (!state.stale) return null
  return (
    <Alert>
      <RiTimeLine />
      <AlertTitle>Showing data from {formatRelative(state.lastUpdated)}</AlertTitle>
      <AlertDescription>
        {state.error ? `Latest refresh failed: ${state.error.message}` : "Data has not refreshed recently."}
      </AlertDescription>
      <AlertAction>
        <Button size="xs" variant="outline" onClick={state.reload}>
          <RiRefreshLine data-icon="inline-start" /> Refresh
        </Button>
      </AlertAction>
    </Alert>
  )
}

/**
 * Renders loading / error / data for one ApiState. Children receive the data;
 * a stale notice is shown above it when appropriate.
 */
export function DataView<T>({
  state,
  children,
  loading,
}: {
  state: ApiState<T>
  children: (data: T) => React.ReactNode
  loading?: React.ReactNode
}) {
  if (state.data === undefined) {
    if (state.error) return <ErrorState error={state.error} onRetry={state.reload} />
    return <>{loading ?? <LoadingRows />}</>
  }
  return (
    <>
      <StaleNotice state={state} />
      {children(state.data)}
    </>
  )
}

export function RefreshIndicator({ state }: { state: Pick<ApiState<unknown>, "refreshing" | "lastUpdated" | "reload"> }) {
  return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      {state.refreshing ? <Spinner className="size-3" /> : null}
      <span>Updated {formatRelative(state.lastUpdated)}</span>
      <Button size="icon-xs" variant="ghost" onClick={state.reload} aria-label="Refresh">
        <RiRefreshLine />
      </Button>
    </div>
  )
}
