"use client"

import { format } from "date-fns"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"

import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"

const config = {
  count: { label: "Events", color: "var(--chart-2)" },
} satisfies ChartConfig

export function VolumeChart({ points, bucket }: { points: { bucket_start: string; count: number }[]; bucket: "hour" | "day" }) {
  const data = points.map((p) => ({
    label: format(new Date(p.bucket_start), bucket === "hour" ? "HH:mm" : "MMM d"),
    full: format(new Date(p.bucket_start), bucket === "hour" ? "MMM d, HH:00" : "EEE MMM d"),
    count: p.count,
  }))
  return (
    <ChartContainer config={config} className="aspect-auto h-56 w-full">
      <BarChart data={data} margin={{ left: 0, right: 8, top: 8 }}>
        <CartesianGrid vertical={false} />
        <XAxis dataKey="label" tickLine={false} axisLine={false} minTickGap={24} />
        <YAxis tickLine={false} axisLine={false} width={40} allowDecimals={false} />
        <ChartTooltip cursor={false} content={<ChartTooltipContent labelKey="full" />} />
        <Bar dataKey="count" fill="var(--color-count)" />
      </BarChart>
    </ChartContainer>
  )
}
