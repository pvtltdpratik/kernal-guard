import { Suspense } from "react"
import type { Metadata } from "next"

import { LoadingRows } from "@/components/kg/data-states"
import { PageBody, PageHeader } from "@/components/kg/page-header"
import { EventsView } from "./events-view"

export const metadata: Metadata = { title: "Event Explorer" }

export default function EventsPage() {
  return (
    <>
      <PageHeader title="Event Explorer" description="Normalised telemetry from Sysmon and the Windows Event Log. Times are activity time in your local timezone." />
      <PageBody>
        <Suspense fallback={<LoadingRows />}>
          <EventsView />
        </Suspense>
      </PageBody>
    </>
  )
}
