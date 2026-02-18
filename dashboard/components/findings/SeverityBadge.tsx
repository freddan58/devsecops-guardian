"use client";

import { severityColor } from "@/lib/utils";

export function SeverityBadge({ severity }: { severity: string }) {
  const colors = severityColor[severity.toUpperCase()] || severityColor.INFO;
  return (
    <span className={`badge ${colors}`}>
      {severity}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: string }) {
  const isConfirmed = verdict === "CONFIRMED";
  return (
    <span
      className={`badge ${
        isConfirmed
          ? "text-red-400 bg-red-400/10 border-red-400/30"
          : "text-green-400 bg-green-400/10 border-green-400/30"
      }`}
    >
      {isConfirmed ? "Confirmed" : "False Positive"}
    </span>
  );
}

export function FixStatusBadge({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    SUCCESS: "text-green-400 bg-green-400/10 border-green-400/30",
    DRY_RUN: "text-blue-400 bg-blue-400/10 border-blue-400/30",
    FAILED: "text-red-400 bg-red-400/10 border-red-400/30",
    PENDING: "text-gray-400 bg-gray-400/10 border-gray-400/30",
  };
  return (
    <span className={`badge ${colorMap[status] || colorMap.PENDING}`}>
      {status === "DRY_RUN" ? "Dry Run" : status}
    </span>
  );
}
