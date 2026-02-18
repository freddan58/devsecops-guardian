"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { getFindings, type Finding, type FindingsResponse } from "@/lib/api";
import { SeverityBadge, VerdictBadge, FixStatusBadge } from "@/components/findings/SeverityBadge";

export default function FindingsPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [data, setData] = useState<FindingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("");

  const fetchFindings = useCallback(async () => {
    try {
      const result = await getFindings(scanId, {
        severity: severityFilter || undefined,
        verdict: verdictFilter || undefined,
      });
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, [scanId, severityFilter, verdictFilter]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  if (loading) {
    return <div className="p-6 text-center text-slate-400">Loading findings...</div>;
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="card text-center py-8">
          <p className="text-red-400">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link href="/scans" className="hover:text-white transition-colors">Scans</Link>
        <span>/</span>
        <Link href={`/scans/${scanId}`} className="mono text-blue-400 hover:text-blue-300 transition-colors">
          {scanId}
        </Link>
        <span>/</span>
        <span className="text-white">Findings</span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Vulnerability Findings</h1>
          <p className="text-sm text-slate-400 mt-1">
            {data?.total || 0} findings &middot;{" "}
            <span className="text-red-400">{data?.confirmed || 0} confirmed</span> &middot;{" "}
            <span className="text-green-400">{data?.fixed || 0} fixed</span>
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-4">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-1.5 rounded-lg bg-[#1a1a2e] border border-[#2a2a4e] text-sm text-white"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select
          value={verdictFilter}
          onChange={(e) => setVerdictFilter(e.target.value)}
          className="px-3 py-1.5 rounded-lg bg-[#1a1a2e] border border-[#2a2a4e] text-sm text-white"
        >
          <option value="">All Verdicts</option>
          <option value="CONFIRMED">Confirmed</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>
      </div>

      {/* Findings Table */}
      <div className="card overflow-hidden p-0">
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Vulnerability</th>
              <th>File</th>
              <th>CWE</th>
              <th>Score</th>
              <th>Verdict</th>
              <th>Fix</th>
            </tr>
          </thead>
          <tbody>
            {data?.findings.map((f, i) => (
              <tr key={i}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td>
                  <div className="font-medium text-white text-sm">{f.vulnerability}</div>
                  <div className="text-xs text-slate-400 mt-0.5 max-w-xs truncate">
                    {f.description}
                  </div>
                </td>
                <td>
                  <div className="mono text-xs text-blue-300">{f.file}</div>
                  <div className="text-xs text-slate-500">Line {f.line}</div>
                </td>
                <td className="mono text-xs text-slate-300">{f.cwe}</td>
                <td>
                  <div className={`font-bold text-sm ${
                    f.exploitability_score >= 80 ? "text-red-400" :
                    f.exploitability_score >= 60 ? "text-orange-400" :
                    f.exploitability_score >= 40 ? "text-yellow-400" :
                    "text-blue-400"
                  }`}>
                    {f.exploitability_score}
                  </div>
                </td>
                <td><VerdictBadge verdict={f.verdict} /></td>
                <td>
                  <div className="flex items-center gap-2">
                    <FixStatusBadge status={f.fix_status} />
                    {f.pr_url && (
                      <a
                        href={f.pr_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:text-blue-300 text-xs"
                      >
                        PR #{f.pr_number}
                      </a>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {(!data?.findings || data.findings.length === 0) && (
          <div className="text-center py-8 text-slate-400 text-sm">
            No findings match the current filters
          </div>
        )}
      </div>
    </div>
  );
}
