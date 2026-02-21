/**
 * DevSecOps Guardian - Utility Functions
 */

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function timeAgo(iso: string): string {
  const seconds = Math.floor(
    (Date.now() - new Date(iso).getTime()) / 1000
  );
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export const severityColor: Record<string, string> = {
  CRITICAL: "text-red-500 bg-red-500/10 border-red-500/30",
  HIGH: "text-orange-500 bg-orange-500/10 border-orange-500/30",
  MEDIUM: "text-yellow-500 bg-yellow-500/10 border-yellow-500/30",
  LOW: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  INFO: "text-gray-400 bg-gray-400/10 border-gray-400/30",
};

export const severityDot: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
  LOW: "bg-blue-400",
  INFO: "bg-gray-400",
};

export const verdictColor: Record<string, string> = {
  CONFIRMED: "text-red-400 bg-red-400/10 border-red-400/30",
  FALSE_POSITIVE: "text-green-400 bg-green-400/10 border-green-400/30",
};

export const fixStatusColor: Record<string, string> = {
  SUCCESS: "text-green-400 bg-green-400/10 border-green-400/30",
  DRY_RUN: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  FAILED: "text-red-400 bg-red-400/10 border-red-400/30",
  PENDING: "text-gray-400 bg-gray-400/10 border-gray-400/30",
  FIX_GENERATED: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  PARTIAL: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  N_A: "text-gray-400 bg-gray-400/10 border-gray-400/30",
};

export const statusChangeColor: Record<string, string> = {
  NEW: "text-red-400 bg-red-400/10 border-red-400/30",
  RESOLVED: "text-green-400 bg-green-400/10 border-green-400/30",
  PERSISTENT: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  REGRESSION: "text-orange-400 bg-orange-400/10 border-orange-400/30",
};

export const statusColor: Record<string, string> = {
  QUEUED: "text-gray-400",
  SCANNING: "text-blue-400",
  ANALYZING: "text-purple-400",
  FIXING: "text-orange-400",
  PROFILING: "text-cyan-400",
  COMPLIANCE_CHECK: "text-emerald-400",
  COMPLETED: "text-green-400",
  FAILED: "text-red-400",
};

export const complianceStatusColor: Record<string, string> = {
  COMPLIANT: "text-green-400 bg-green-400/10",
  PARTIALLY_COMPLIANT: "text-yellow-400 bg-yellow-400/10",
  NON_COMPLIANT: "text-red-400 bg-red-400/10",
};

export const riskLevelColor: Record<string, string> = {
  CRITICAL: "text-red-500",
  HIGH: "text-orange-500",
  MEDIUM: "text-yellow-500",
  LOW: "text-blue-400",
  MINIMAL: "text-green-400",
  UNKNOWN: "text-gray-400",
};

export function riskScoreColor(score: number): string {
  if (score >= 80) return "#ef4444";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#eab308";
  if (score >= 20) return "#3b82f6";
  return "#22c55e";
}
