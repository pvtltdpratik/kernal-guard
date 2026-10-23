# Dashboard (client/)

Next.js 16.4 (App Router, Cache Components) + React 19.3 + Tailwind v4, using
the project's existing shadcn/ui components (`base-sera` style, Base UI
primitives, Remix Icon). No UI or data-fetching libraries were added.

## Run

```powershell
cd client
Copy-Item .env.example .env.local   # optional; defaults to http://127.0.0.1:8000
npm run dev                          # http://localhost:3000
# or production:
npm run build; npm run start
```

The API must be running (`cd server; .\.venv\Scripts\python.exe -m app`). Its
CORS allowlist already includes `http://localhost:3000` and
`http://127.0.0.1:3000`.

`NEXT_PUBLIC_KG_API_URL` is inlined into the browser bundle at **build time**.
It holds a URL only. Never put a credential in a `NEXT_PUBLIC_` variable.

## Pages

| Route | Purpose |
|---|---|
| `/` | Overview: totals, active alerts by severity, event volume (24h/7d), recent incidents, sensor health, top rules |
| `/alerts` | Search, filter (status, severity, rule, min score), sort, paginate |
| `/alerts/[id]` | Observed vs inferred, uncertainty, rule explanation, evidence, score breakdown, ATT&CK, triage (status + notes), history |
| `/incidents`, `/incidents/[id]` | Timeline of evidence and alerts, rules fired, per-rule score contribution, uncertainty, status and notes |
| `/events`, `/events/[id]` | Filter by category, source, image, PID, GUID, time; structured fields; raw XML only on request |
| `/processes`, `/processes/[id]` | Metadata, parent/children, alerts, network summary, hashes/signature, conflicting evidence, related events |
| `/sensors` | Collector state, counters, specific fix-it guidance per failure, capability matrix (effective visibility) |

Filters, sort and page live in the URL, so views are shareable and survive
reloads.

## Data flow and states

- `lib/api/client.ts` is the single request path. It handles timeouts,
  `ApiError` (status, code, request id) and network-vs-HTTP errors.
- `lib/api/types.ts` mirrors `server/app/schemas` field for field.
- `hooks/use-api.ts` fetches on the client and polls (10–30 s per page). It
  exposes `loading`, `error`, `refreshing`, `lastUpdated` and `stale`. Polling
  runs in an effect, so it pauses while Next.js keeps a page hidden in
  `<Activity>` after navigation.
- `components/kg/data-states.tsx` renders the four states: loading skeleton,
  error (with API-unreachable guidance and retry), empty, and **stale** (data
  kept on screen with "Showing data from N ago, latest refresh failed").

Pages that read URL data (`useSearchParams`, `useParams`, `usePathname`)
render inside `<Suspense>`. Next 16 refuses to prerender otherwise, so the
static shell streams and only the data parts render at runtime.

## Verified (2026-10-23)

- `tsc --noEmit` clean. ESLint is clean for all new code. One pre-existing
  error remains in the unused generated `components/ui/carousel.tsx`.
- `next build`: list routes are prerendered static, and the detail routes are
  Partial Prerender.
- Browser-tested in production mode against the live API:
  - Real database (72 System 7045 events): Overview, Event Explorer, event
    detail with raw XML, and Sensor Status (Sysmon unavailable, Security
    access denied, collector stale).
  - Scratch database with the synthetic test scenario (no real detections
    exist yet): alerts list, filter, detail, triage `PATCH` (false positive +
    note recorded in history), incident timeline and score, and process
    page with GUID redirect.
  - No console errors. Incident detail: DOM ready at about 100 ms, data
    rendered at about 200 ms.
  - API stopped: the stale notice appears on open pages, and fresh loads
    show the unreachable error.
  - 375 px width: no page-level horizontal scroll; wide tables scroll
    inside their own container.
- UI testing surfaced a backend correlation gap (the hook-DLL alert didn't
  join its loader's incident). It's fixed, with a regression test.

## Pre-existing files changed

- `components/ui/spinner.tsx`: prop type fixed (`<svg>` props included
  `children`, which the Remix icon rejects; this broke `tsc` and `next build`).
- `hooks/use-mobile.ts`: rewritten with `useSyncExternalStore` (same
  behaviour). React 19 lint rejected `setState` inside an effect.
- `app/layout.tsx`: app shell (sidebar) and metadata. Fonts unchanged.
- `app/page.tsx`: the create-next-app placeholder replaced by the Overview.
- `app/globals.css`: severity and OK colour tokens **added** for light and
  dark. Existing tokens are untouched.
- `.gitignore`: `!.env.example` so the example file can be committed.

## Known limitations

- No authentication: anyone who can reach the API can triage alerts. Actions
  are attributed to `local` (see `docs/security.md`).
- Detail pages keep the default document title ("KernelGuard"), because their
  data loads on the client.
- The Event Explorer's Process column is empty for events with no acting
  process (for example 7045). The service binary is shown on the event detail
  page.
- Detection pages have only been exercised against synthetic detections.
  Real Sysmon telemetry is still pending Sysmon installation.
