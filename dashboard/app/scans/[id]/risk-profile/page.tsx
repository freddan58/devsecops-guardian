"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { getRiskProfile, type RiskProfileResponse } from "@/lib/api";
import { RiskScoreGauge } from "@/components/risk/RiskScoreGauge";
import { OWASPRadarChart } from "@/components/risk/OWASPRadarChart";

export default function RiskProfilePage() {
  const params = useParams();
  const scanId = params.id as string;
  const [data, setData] = useState<RiskProfileResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchRiskProfile = useCallback(async () => {
    try {
      const result = await getRiskProfile(scanId);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load risk profile");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchRiskProfile();
  }, [fetchRiskProfile]);

  if (loading) {
    return <div className="p-6 text-center text-slate-400">Loading risk profile...</div>;
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
        <span className="text-white">Risk Profile</span>
      </div>

      <h1 className="text-2xl font-bold text-white mb-6">OWASP Risk Profile</h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Risk Score Gauge */}
        <div className="card flex flex-col items-center py-6">
          <h3 className="text-sm font-medium text-slate-300 mb-4">Overall Risk Score</h3>
          <RiskScoreGauge score={data.overall_risk_score} level={data.risk_level} />
        </div>

        {/* OWASP Radar Chart */}
        <div className="card">
          <h3 className="text-sm font-medium text-slate-300 mb-2">OWASP Top 10 Coverage</h3>
          <OWASPRadarChart data={data.owasp_top_10} />
        </div>
      </div>

      {/* Attack Surface */}
      {data.attack_surface && Object.keys(data.attack_surface).length > 0 && (
        <div className="card mb-6">
          <h3 className="text-sm font-medium text-slate-300 mb-3">Attack Surface</h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {Object.entries(data.attack_surface).map(([key, value]) => (
              <div key={key}>
                <div className="text-2xl font-bold text-white">{value}</div>
                <div className="text-xs text-slate-400 capitalize">
                  {key.replace(/_/g, " ")}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Executive Summary */}
      {data.executive_summary && (
        <div className="card">
          <h3 className="text-sm font-medium text-slate-300 mb-2">Executive Summary</h3>
          <p className="text-sm text-slate-300 leading-relaxed">
            {data.executive_summary}
          </p>
        </div>
      )}

      {/* OWASP Categories Table */}
      <div className="card mt-6 p-0 overflow-hidden">
        <table className="data-table">
          <thead>
            <tr>
              <th>Category</th>
              <th>Score</th>
              <th>Findings</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {data.owasp_top_10.map((cat, i) => (
              <tr key={i}>
                <td className="text-sm text-white">{cat.category}</td>
                <td>
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-2 bg-[#2a2a4e] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${cat.score}%`,
                          backgroundColor:
                            cat.score >= 80 ? "#ef4444" :
                            cat.score >= 60 ? "#f97316" :
                            cat.score >= 40 ? "#eab308" :
                            cat.score > 0 ? "#3b82f6" : "#2a2a4e",
                        }}
                      />
                    </div>
                    <span className="text-xs text-slate-400 mono">{cat.score}</span>
                  </div>
                </td>
                <td className="text-sm text-white">{cat.findings_count}</td>
                <td>
                  <span className={`badge ${
                    cat.score >= 80 ? "text-red-400 bg-red-400/10 border-red-400/30" :
                    cat.score >= 60 ? "text-orange-400 bg-orange-400/10 border-orange-400/30" :
                    cat.score >= 40 ? "text-yellow-400 bg-yellow-400/10 border-yellow-400/30" :
                    cat.score > 0 ? "text-blue-400 bg-blue-400/10 border-blue-400/30" :
                    "text-green-400 bg-green-400/10 border-green-400/30"
                  }`}>
                    {cat.score >= 80 ? "CRITICAL" :
                     cat.score >= 60 ? "HIGH" :
                     cat.score >= 40 ? "MEDIUM" :
                     cat.score > 0 ? "LOW" : "CLEAR"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
