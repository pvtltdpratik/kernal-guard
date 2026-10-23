import { Suspense } from "react"
import type { Metadata } from "next"

import { LoadingRows } from "@/components/kg/data-states"
import { PageBody, PageHeader } from "@/components/kg/page-header"
import { AlertsView } from "./alerts-view"

export const metadata: Metadata = { title: "Alerts" }

export default function AlertsPage() {
  return (
    <>
      <PageHeader
        title="Alerts"
        description="Rule findings about suspected activity. Each alert shows what was observed, what was inferred, and what the evidence cannot show."
      />
      <PageBody>
        <Suspense fallback={<LoadingRows />}>
          <AlertsView />
        </Suspense>
      </PageBody>
    </>
  )
}
