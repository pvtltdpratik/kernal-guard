import { Suspense } from "react"

import { LoadingRows } from "@/components/kg/data-states"
import { AlertDetailView } from "./alert-detail-view"

export default function AlertDetailPage() {
  return (
    <Suspense fallback={<div className="p-8"><LoadingRows /></div>}>
      <AlertDetailView />
    </Suspense>
  )
}
