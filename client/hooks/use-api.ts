"use client"

import * as React from "react"

import { ApiError, apiGet, type Query } from "@/lib/api/client"

export interface ApiState<T> {
  data: T | undefined
  error: ApiError | undefined
  /** First load in progress (no data yet). */
  loading: boolean
  /** A background refresh is in progress while data is shown. */
  refreshing: boolean
  lastUpdated: Date | undefined
  /** Data is shown but the latest refresh failed, or it is older than 3 refresh intervals. */
  stale: boolean
  reload: () => void
  /** Replace data locally (e.g. with a PATCH response) without refetching. */
  setData: (data: T) => void
}

/**
 * Fetches `path` and optionally re-polls every `refreshMs`.
 *
 * Polling runs inside an effect, so it stops automatically while Next.js
 * keeps the page hidden in <Activity> after navigation and resumes on return.
 * Pass `path = null` to skip fetching.
 */
export function useApi<T>(path: string | null, query?: Query, options: { refreshMs?: number } = {}): ApiState<T> {
  const { refreshMs } = options
  const [data, setData] = React.useState<T>()
  const [error, setError] = React.useState<ApiError>()
  const [inFlight, setInFlight] = React.useState(false)
  const [lastUpdated, setLastUpdated] = React.useState<Date>()
  const [nonce, setNonce] = React.useState(0)
  // Wall-clock of the last completed request, for staleness. Not read from
  // Date.now() during render: that would freeze a build-time value into prerendered HTML.
  const [now, setNow] = React.useState(0)

  // Stable key so callers can pass object literals.
  const key = path === null ? null : `${path}?${JSON.stringify(query ?? {})}`
  const previousKey = React.useRef<string | null>(null)

  React.useEffect(() => {
    if (key === null || path === null) return
    if (previousKey.current !== key) {
      // Different resource: don't show the old resource's data as if current.
      previousKey.current = key
      setData(undefined)
      setLastUpdated(undefined)
    }
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined

    const load = async () => {
      setInFlight(true)
      try {
        const result = await apiGet<T>(path, query, controller.signal)
        setData(result)
        setError(undefined)
        setLastUpdated(new Date())
      } catch (err) {
        if (controller.signal.aborted) return
        setError(err instanceof ApiError ? err : new ApiError(String(err), 0, "unknown"))
      } finally {
        if (!controller.signal.aborted) {
          setInFlight(false)
          setNow(Date.now())
          if (refreshMs) timer = setTimeout(load, refreshMs)
        }
      }
    }
    load()
    return () => {
      controller.abort()
      if (timer) clearTimeout(timer)
    }
    // `query` is captured through `key`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, refreshMs, nonce])

  const reload = React.useCallback(() => setNonce((n) => n + 1), [])
  const tooOld = refreshMs !== undefined && lastUpdated !== undefined && now - lastUpdated.getTime() > refreshMs * 3

  return {
    data,
    error,
    loading: data === undefined && error === undefined,
    refreshing: inFlight && data !== undefined,
    lastUpdated,
    stale: data !== undefined && (error !== undefined || tooOld),
    reload,
    setData,
  }
}
