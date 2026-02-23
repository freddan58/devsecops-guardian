"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
} from "recharts";
import type { ScanComparison, ScanComparisonFinding } from "@/lib/api";
import { SeverityBadge, StatusChangeBadge } from "@/components/findings/SeverityBadge";

const STATUS_COLORS: Record<string, string> = {
  NEW: "#ef4444",
  RESOLVED: "#22c55e",
  PERSISTENT: "#eab308",
  REGRESSION: "#f97316",
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

interface ComparisonReportProps {
  comparison: ScanComparison;
}

export function ComparisonReport({ comparison }: ComparisonReportProps) {
  const [activeTab, setActiveTab] = useState<string>("all");

  const { severityBreakdown, pieData, totalDelta, groupedFindings } = useMemo(() => {
    const findings = comparison.findings || [];

    // Group by severity and status_change
    const bySeverity: Record<string, Record<string, number>> = {};
    for (const f of findings) {
      const sev = f.severity?.toUpperCase() || "UNKNOWN";
      if (!bySeverity[sev]) bySeverity[sev] = {};
      const sc = f.status_change || "UNKNOWN";
      bySeverity[sev][sc] = (bySeverity[sev][sc] || 0) + 1;
    }

    // Build severity breakdown chart data
    const severityBreakdown = SEVERITY_ORDER
      .filter((s) => bySeverity[s])
      .map((s) => ({
        severity: s,
        NEW: bySeverity[s]?.NEW || 0,
        RESOLVED: bySeverity[s]?.RESOLVED || 0,
        PERSISTENT: bySeverity[s]?.PERSISTENT || 0,
      }));

    // Pie data for overview
    const pieData = [
      { name: "New", value: comparison.new_findings, color: STATUS_COLORS.NEW },
      { name: "Resolved", value: comparison.resolved_findings, color: STATUS_COLORS.RESOLVED },
      { name: "Persistent", value: comparison.persistent_findings, color: STATUS_COLORS.PERSISTENT },
      { name: "Regressions", value: comparison.regression_findings, color: STATUS_COLORS.REGRESSION },
    ].filter((d) => d.value > 0);

    const totalDelta = comparison.new_findings - comparison.resolved_findings;

    // Group findings by status_change
    const grouped: Record<string, ScanComparisonFinding[]> = {};
    for (const f of findings) {
      const sc = f.status_change || "UNKNOWN";
      if (!grouped[sc]) grouped[sc] = [];
      grouped[sc].push(f);
    }
    // Sort within each group by severity order
    for (const key of Object.keys(grouped)) {
      grouped[key].sort((a, b) => {
        const ai = SEVERITY_ORDER.indexOf(a.severity?.toUpperCase());
        const bi = SEVERITY_ORDER.indexOf(b.severity?.toUpperCase());
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      });
    }

    return { severityBreakdown, pieData, totalDelta, groupedFindings: grouped };
  }, [comparison]);

  const tabs = [
    { key: "all", label: "All", count: comparison.findings?.length || 0 },
    { key: "NEW", label: "New", count: comparison.new_findings },
    { key: "RESOLVED", label: "Resolved", count: comparison.resolved_findings },
    { key: "PERSISTENT", label: "Persistent", count: comparison.persistent_findings },
  ];

  const visibleFindings = activeTab === "all"
    ? (comparison.findings || [])
    : (groupedFindings[activeTab] || []);

  return (
    <div className="space-y-6">
      {/* Report Header */}
      <div className="card border-blue-500/30 bg-gradient-to-br from-blue-500/5 to-purple-500/5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
              <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">Re-Scan Comparison Report</h3>
              <p className="text-xs text-slate-400">
                Comparing with parent scan{" "}
                <Link
                  href={`/scans/${comparison.parent_scan_id}`}
                  className="text-blue-400 hover:underline"
                >
                  {comparison.parent_scan_id.slice(0, 16)}...
                </Link>
              </p>
            </div>
          </div>
          <div className={`text-sm font-medium px-3 py-1.5 rounded-lg ${
            totalDelta < 0
              ? "bg-green-500/10 text-green-400 border border-green-500/30"
              : totalDelta > 0
              ? "bg-red-500/10 text-red-400 border border-red-500/30"
              : "bg-slate-500/10 text-slate-400 border border-slate-500/30"
          }`}>
            {totalDelta > 0 ? "+" : ""}{totalDelta} net findings
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="rounded-lg bg-[#0f0f1a] border border-red-500/20 p-4">
            <div className="flex items-center gap-2 mb-2">
              <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
              <span className="text-xs text-slate-400 uppercase tracking-wider">New</span>
            </div>
            <div className="text-3xl font-bold text-red-400">+{comparison.new_findings}</div>
            <div className="text-xs text-slate-500 mt-1">vulnerabilities introduced</div>
          </div>

          <div className="rounded-lg bg-[#0f0f1a] border border-green-500/20 p-4">
            <div className="flex items-center gap-2 mb-2">
              <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="text-xs text-slate-400 uppercase tracking-wider">Resolved</span>
            </div>
            <div className="text-3xl font-bold text-green-400">-{comparison.resolved_findings}</div>
            <div className="text-xs text-slate-500 mt-1">vulnerabilities fixed</div>
          </div>

          <div className="rounded-lg bg-[#0f0f1a] border border-yellow-500/20 p-4">
            <div className="flex items-center gap-2 mb-2">
              <svg className="w-4 h-4 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="text-xs text-slate-400 uppercase tracking-wider">Persistent</span>
            </div>
            <div className="text-3xl font-bold text-yellow-400">{comparison.persistent_findings}</div>
            <div className="text-xs text-slate-500 mt-1">still present</div>
          </div>

          <div className="rounded-lg bg-[#0f0f1a] border border-orange-500/20 p-4">
            <div className="flex items-center gap-2 mb-2">
              <svg className="w-4 h-4 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              <span className="text-xs text-slate-400 uppercase tracking-wider">Regressions</span>
            </div>
            <div className="text-3xl font-bold text-orange-400">{comparison.regression_findings}</div>
            <div className="text-xs text-slate-500 mt-1">re-introduced</div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Distribution Pie Chart */}
        {pieData.length > 0 && (
          <div className="card">
            <h4 className="text-sm font-medium text-slate-300 mb-4">Finding Distribution</h4>
            <div className="flex items-center">
              <ResponsiveContainer width="50%" height={200}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#1a1a2e",
                      border: "1px solid #2a2a4e",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                    itemStyle={{ color: "#e2e8f0" }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-3 flex-1">
                {pieData.map((d) => (
                  <div key={d.name} className="flex items-center gap-3">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: d.color }} />
                    <div className="flex-1">
                      <div className="text-sm text-slate-300">{d.name}</div>
                    </div>
                    <div className="text-sm font-semibold text-white">{d.value}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Severity Breakdown Bar Chart */}
        {severityBreakdown.length > 0 && (
          <div className="card">
            <h4 className="text-sm font-medium text-slate-300 mb-4">Changes by Severity</h4>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={severityBreakdown} barGap={2}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a4e" />
                <XAxis
                  dataKey="severity"
                  tick={{ fill: "#94a3b8", fontSize: 11 }}
                  axisLine={{ stroke: "#2a2a4e" }}
                />
                <YAxis
                  tick={{ fill: "#64748b", fontSize: 11 }}
                  axisLine={{ stroke: "#2a2a4e" }}
                  allowDecimals={false}
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
                />
                <Bar dataKey="NEW" name="New" fill={STATUS_COLORS.NEW} radius={[4, 4, 0, 0]} />
                <Bar dataKey="RESOLVED" name="Resolved" fill={STATUS_COLORS.RESOLVED} radius={[4, 4, 0, 0]} />
                <Bar dataKey="PERSISTENT" name="Persistent" fill={STATUS_COLORS.PERSISTENT} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Findings Table */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-sm font-medium text-slate-300">Detailed Findings</h4>
          <div className="flex gap-1 bg-[#0f0f1a] rounded-lg p-1">
            {tabs.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  activeTab === tab.key
                    ? "bg-blue-600 text-white"
                    : "text-slate-400 hover:text-white hover:bg-[#1a1a2e]"
                }`}
              >
                {tab.label}
                {tab.count > 0 && (
                  <span className="ml-1.5 text-[10px] opacity-70">({tab.count})</span>
                )}
              </button>
            ))}
          </div>
        </div>

        {visibleFindings.length === 0 ? (
          <div className="text-center py-8 text-slate-500 text-sm">
            No findings in this category
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#2a2a4e]">
                  <th className="text-left text-xs text-slate-400 uppercase tracking-wider py-3 px-3">Status</th>
                  <th className="text-left text-xs text-slate-400 uppercase tracking-wider py-3 px-3">Severity</th>
                  <th className="text-left text-xs text-slate-400 uppercase tracking-wider py-3 px-3">Vulnerability</th>
                  <th className="text-left text-xs text-slate-400 uppercase tracking-wider py-3 px-3">CWE</th>
                  <th className="text-left text-xs text-slate-400 uppercase tracking-wider py-3 px-3">File</th>
                </tr>
              </thead>
              <tbody>
                {visibleFindings.map((f, i) => (
                  <tr
                    key={`${f.cwe}-${f.file}-${i}`}
                    className="border-b border-[#2a2a4e]/50 hover:bg-[#1a1a2e]/50 transition-colors"
                  >
                    <td className="py-3 px-3">
                      <StatusChangeBadge status={f.status_change} />
                    </td>
                    <td className="py-3 px-3">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-3 px-3">
                      <span className="text-sm text-slate-200 line-clamp-1" title={f.vulnerability}>
                        {f.vulnerability}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className="mono text-xs text-slate-400">{f.cwe}</span>
                    </td>
                    <td className="py-3 px-3">
                      <span className="mono text-xs text-slate-400 line-clamp-1" title={f.file}>
                        {f.file}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
