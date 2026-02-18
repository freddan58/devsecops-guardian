"use client";

import {
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

interface OWASPData {
  category: string;
  score: number;
  findings_count: number;
}

function shortenCategory(cat: string): string {
  // "A01:2021 - Broken Access Control" -> "A01 Broken Access"
  const match = cat.match(/^(A\d+).*?-\s*(.+)$/);
  if (!match) return cat;
  const words = match[2].split(" ").slice(0, 2).join(" ");
  return `${match[1]} ${words}`;
}

export function OWASPRadarChart({ data }: { data: OWASPData[] }) {
  const chartData = data.map((d) => ({
    subject: shortenCategory(d.category),
    score: d.score,
    fullName: d.category,
    findings: d.findings_count,
  }));

  return (
    <ResponsiveContainer width="100%" height={350}>
      <RadarChart data={chartData} cx="50%" cy="50%" outerRadius="70%">
        <PolarGrid stroke="#2a2a4e" />
        <PolarAngleAxis
          dataKey="subject"
          tick={{ fill: "#94a3b8", fontSize: 10 }}
        />
        <PolarRadiusAxis
          angle={90}
          domain={[0, 100]}
          tick={{ fill: "#64748b", fontSize: 9 }}
        />
        <Radar
          name="Risk Score"
          dataKey="score"
          stroke="#3b82f6"
          fill="#3b82f6"
          fillOpacity={0.2}
          strokeWidth={2}
        />
        <Tooltip
          contentStyle={{
            background: "#1a1a2e",
            border: "1px solid #2a2a4e",
            borderRadius: "8px",
            fontSize: "12px",
          }}
          itemStyle={{ color: "#e2e8f0" }}
          labelStyle={{ color: "#94a3b8" }}
          formatter={(value: unknown) => [
            `Score: ${value}`,
            "",
          ]}
        />
      </RadarChart>
    </ResponsiveContainer>
  );
}
