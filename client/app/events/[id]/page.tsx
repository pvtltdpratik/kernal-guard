import { Suspense } from "react"

import { LoadingRows } from "@/components/kg/data-states"
import { EventDetailView } from "./event-detail-view"

export default function EventDetailPage() {
  return (
    <Suspense fallback={<div className="p-8"><LoadingRows /></div>}>
      <EventDetailView />
    </Suspense>
  )
}
