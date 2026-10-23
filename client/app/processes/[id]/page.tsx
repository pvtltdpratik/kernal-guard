import { Suspense } from "react"

import { LoadingRows } from "@/components/kg/data-states"
import { ProcessDetailView } from "./process-detail-view"

export default function ProcessDetailPage() {
  return (
    <Suspense fallback={<div className="p-8"><LoadingRows /></div>}>
      <ProcessDetailView />
    </Suspense>
  )
}
