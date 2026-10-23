"use client"

import * as React from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"

/**
 * Filters, sorting and paging stored in the URL query string, so views are
 * shareable and survive reloads. Changing any filter resets `page`.
 * Components using this must render inside a <Suspense> boundary.
 */
export function useUrlState() {
  const router = useRouter()
  const pathname = usePathname()
  const params = useSearchParams()

  const get = React.useCallback((key: string) => params.get(key) ?? "", [params])
  const getAll = React.useCallback((key: string) => params.getAll(key), [params])
  const page = Math.max(1, Number(params.get("page")) || 1)

  const update = React.useCallback(
    (changes: Record<string, string | string[] | null>, options: { keepPage?: boolean } = {}) => {
      const next = new URLSearchParams(params.toString())
      for (const [key, value] of Object.entries(changes)) {
        next.delete(key)
        for (const item of Array.isArray(value) ? value : value ? [value] : []) next.append(key, item)
      }
      if (!options.keepPage) next.delete("page")
      const query = next.toString()
      router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false })
    },
    [params, pathname, router]
  )

  const setPage = React.useCallback((value: number) => update({ page: value > 1 ? String(value) : null }, { keepPage: true }), [update])

  return { get, getAll, page, update, setPage, hasFilters: params.toString().replace(/(^|&)page=\d+/, "") !== "" }
}
