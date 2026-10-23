import { Suspense } from "react"
import type { Metadata } from "next"

import { LoadingRows } from "@/components/kg/data-states"
import { PageBody, PageHeader } from "@/components/kg/page-header"
import { ProcessesView } from "./processes-view"

export const metadata: Metadata = { title: "Processes" }

export default function ProcessesPage() {
  return (
    <>
      <PageHeader
        title="Process Investigation"
        description="Processes assembled from every event that mentions them. Identity is the Sysmon process GUID (or PID + start time), so reused PIDs stay separate."
      />
      <PageBody>
        <Suspense fallback={<LoadingRows />}>
          <ProcessesView />
        </Suspense>
      </PageBody>
    </>
  )
}
