// Single entry point for KernelGuard API requests.
//
// NEXT_PUBLIC_KG_API_URL is inlined into the browser bundle at build time:
// it must only ever hold a URL, never a credential.

import type { ApiErrorBody } from "./types"

export const API_BASE_URL = (process.env.NEXT_PUBLIC_KG_API_URL ?? "http://127.0.0.1:8000").replace(/\/+$/, "")

const REQUEST_TIMEOUT_MS = 15_000

export type QueryValue = string | number | boolean | null | undefined | (string | number)[]
export type Query = Record<string, QueryValue>

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly details: unknown = null,
    readonly requestId: string | null = null
  ) {
    super(message)
    this.name = "ApiError"
  }

  /** True when the API could not be reached at all (server down, CORS, timeout). */
  get isNetworkError() {
    return this.status === 0
  }
}

export function buildUrl(path: string, query?: Query): string {
  const url = new URL(path.startsWith("/") ? path : `/${path}`, API_BASE_URL)
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === "") continue
    for (const item of Array.isArray(value) ? value : [value]) {
      url.searchParams.append(key, String(item))
    }
  }
  return url.toString()
}

async function request<T>(method: "GET" | "PATCH", path: string, init: { query?: Query; body?: unknown; signal?: AbortSignal }): Promise<T> {
  const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS)
  const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout

  let response: Response
  try {
    response = await fetch(buildUrl(path, init.query), {
      method,
      signal,
      headers: init.body === undefined ? { Accept: "application/json" } : { Accept: "application/json", "Content-Type": "application/json" },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      cache: "no-store",
    })
  } catch (error) {
    if (init.signal?.aborted) throw error // caller cancelled; not an API failure
    const reason = timeout.aborted ? "timed out" : "unreachable"
    throw new ApiError(`KernelGuard API ${reason} at ${API_BASE_URL}`, 0, timeout.aborted ? "timeout" : "network_error")
  }

  const requestId = response.headers.get("X-Request-ID")
  if (!response.ok) {
    let body: Partial<ApiErrorBody> = {}
    try {
      body = await response.json()
    } catch {
      // non-JSON error (proxy, crash page): fall through to a generic message
    }
    throw new ApiError(
      body.error?.message ?? `Request failed (${response.status})`,
      response.status,
      body.error?.code ?? "http_error",
      body.error?.details ?? null,
      body.error?.request_id ?? requestId
    )
  }
  return (await response.json()) as T
}

export function apiGet<T>(path: string, query?: Query, signal?: AbortSignal): Promise<T> {
  return request<T>("GET", path, { query, signal })
}

export function apiPatch<T>(path: string, body: unknown): Promise<T> {
  return request<T>("PATCH", path, { body })
}
