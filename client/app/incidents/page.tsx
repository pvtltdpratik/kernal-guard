import { Suspense } from "react"
import type { Metadata } from "next"

import { LoadingRows } from "@/components/kg/data-states"
import { PageBody, PageHeader } from "@/components/kg/page-header"
import { IncidentsView } from "./incidents-view"

export const metadata: Metadata = { title: "Incidents" }

export default function IncidentsPage() {
  return (
    <>
      <PageHeader
        title="Incidents"
        description="Alerts grouped because they share a process, parent process or file within a time window."
      />
      <PageBody>
        <Suspense fallback={<LoadingRows />}>
          <IncidentsView />
        </Suspense>
      </PageBody>
    </>
  )
}
