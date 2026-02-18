"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { getCompliance, type ComplianceResponse } from "@/lib/api";
import { SeverityBadge } from "@/components/findings/SeverityBadge";

export default function CompliancePage() {
  const params = useParams();
  const scanId = params.id as string;
  const [data, setData] = useState<ComplianceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchCompliance = useCallback(async () => {
    try {
      const result = await getCompliance(scanId);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load compliance data");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchCompliance();
  }, [fetchCompliance]);

  if (loading) {
    return <div className="p-6 text-center text-slate-400">Loading compliance data...</div>;
  }

  if (error || !data) {
    return (
      <div className="p-6">
        <div className="card text-center py-8">
          <p className="text-red-400">{error || "No data"}</p>
        </div>
      </div>
    );
  }

  const complianceStatusStyle: Record<string, string> = {
    COMPLIANT: "text-green-400 bg-green-400/10 border-green-400/30",
    PARTIALLY_COMPLIANT: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
    NON_COMPLIANT: "text-red-400 bg-red-400/10 border-red-400/30",
  };

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
        <span className="text-white">Compliance</span>
      </div>

      <h1 className="text-2xl font-bold text-white mb-6">PCI-DSS 4.0 Compliance</h1>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        <div className="card">
          <div className="text-xs text-slate-400 uppercase tracking-wide mb-1">Overall Risk</div>
          <div className={`text-2xl font-bold ${
            data.overall_risk_rating === "CRITICAL" ? "text-red-500" :
            data.overall_risk_rating === "HIGH" ? "text-orange-500" :
            data.overall_risk_rating === "MEDIUM" ? "text-yellow-500" :
            "text-green-400"
          }`}>
            {data.overall_risk_rating}
          </div>
          <div className="text-xs text-slate-500 mt-1">{data.framework}</div>
        </div>
        <div className="card">
          <div className="text-xs text-slate-400 uppercase tracking-wide mb-1">Compliant</div>
          <div className="text-2xl font-bold text-green-400">{data.compliant_count}</div>
          <div className="text-xs text-slate-500 mt-1">Requirements met</div>
        </div>
        <div className="card">
          <div className="text-xs text-slate-400 uppercase tracking-wide mb-1">Non-Compliant</div>
          <div className="text-2xl font-bold text-red-400">{data.non_compliant_count}</div>
          <div className="text-xs text-slate-500 mt-1">Requirements failing</div>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="card mb-6">
        <h3 className="text-sm font-medium text-slate-300 mb-2">Executive Summary</h3>
        <p className="text-sm text-slate-300 leading-relaxed">
          {data.executive_summary}
        </p>
      </div>

      {/* Findings with Requirements */}
      <div className="space-y-4">
        {data.findings.map((finding, i) => (
          <div key={i} className="card">
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <span className="font-medium text-white">{finding.vulnerability}</span>
                <span className="mono text-xs text-slate-400">{finding.cwe}</span>
              </div>
              <span className={`badge ${
                finding.risk_rating === "CRITICAL" ? "text-red-400 bg-red-400/10 border-red-400/30" :
                finding.risk_rating === "HIGH" ? "text-orange-400 bg-orange-400/10 border-orange-400/30" :
                "text-yellow-400 bg-yellow-400/10 border-yellow-400/30"
              }`}>
                {finding.risk_rating}
              </span>
            </div>

            {finding.regulatory_impact && (
              <p className="text-xs text-slate-400 mb-3">{finding.regulatory_impact}</p>
            )}

            {/* Requirements Table */}
            <div className="overflow-hidden rounded-lg border border-[#2a2a4e]">
              <table className="data-table">
                <thead>
                  <tr className="bg-[#0a0a0f]">
                    <th className="text-xs">Requirement</th>
                    <th className="text-xs">Status</th>
                    <th className="text-xs">Remediation</th>
                  </tr>
                </thead>
                <tbody>
                  {finding.pci_dss_requirements.map((req, j) => (
                    <tr key={j}>
                      <td>
                        <div className="mono text-xs text-blue-300">{req.requirement_id}</div>
                        <div className="text-xs text-slate-300 mt-0.5">{req.requirement_title}</div>
                      </td>
                      <td>
                        <span className={`badge ${
                          complianceStatusStyle[req.compliance_status] ||
                          "text-gray-400 bg-gray-400/10 border-gray-400/30"
                        }`}>
                          {req.compliance_status.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${
                          req.remediation_status === "FIXED"
                            ? "text-green-400 bg-green-400/10 border-green-400/30"
                            : req.remediation_status === "FIX_PENDING_REVIEW"
                            ? "text-yellow-400 bg-yellow-400/10 border-yellow-400/30"
                            : "text-red-400 bg-red-400/10 border-red-400/30"
                        }`}>
                          {req.remediation_status.replace(/_/g, " ")}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </div>

      {/* Recommendations */}
      {data.recommendations.length > 0 && (
        <div className="card mt-6">
          <h3 className="text-sm font-medium text-slate-300 mb-3">Recommendations</h3>
          <ul className="space-y-2">
            {data.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="text-blue-400 mt-0.5">&#8226;</span>
                {rec}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
