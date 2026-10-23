import { Suspense } from "react"

import { LoadingRows } from "@/components/kg/data-states"
import { IncidentDetailView } from "./incident-detail-view"

export default function IncidentDetailPage() {
  return (
    <Suspense fallback={<div className="p-8"><LoadingRows /></div>}>
      <IncidentDetailView />
    </Suspense>
  )
}
