"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { getPractices, type PracticesSummary } from "@/lib/api";

function MaturityScoreRing({ score }: { score: number }) {
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 70 ? "#22c55e" : score >= 40 ? "#eab308" : "#ef4444";

  return (
    <div className="relative w-32 h-32">
      <svg className="w-32 h-32 transform -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={radius} fill="none" stroke="#1a1a2e" strokeWidth="8" />
        <circle
          cx="50" cy="50" r={radius} fill="none"
          stroke={color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{score}</span>
        <span className="text-xs text-slate-400">/ 100</span>
      </div>
    </div>
  );
}

export default function PracticesPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [data, setData] = useState<PracticesSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchPractices = useCallback(async () => {
    try {
      const result = await getPractices(scanId);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load practices");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchPractices();
  }, [fetchPractices]);

  if (loading) return <div className="p-6 text-center text-slate-400">Loading practices...</div>;
  if (error) return <div className="p-6"><div className="card text-center py-8"><p className="text-red-400">{error}</p></div></div>;
  if (!data) return null;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link href="/scans" className="hover:text-white transition-colors">Scans</Link>
        <span>/</span>
        <Link href={`/scans/${scanId}`} className="mono text-blue-400 hover:text-blue-300 transition-colors">{scanId}</Link>
        <span>/</span>
        <span className="text-white">Best Practices</span>
      </div>

      {/* Header with Maturity Score */}
      <div className="flex items-center gap-8 mb-8">
        <MaturityScoreRing score={data.maturity_score} />
        <div>
          <h1 className="text-2xl font-bold text-white">Security Maturity Score</h1>
          <p className="text-sm text-slate-400 mt-1">
            {data.total_violations} violations &middot; {data.total_followed} good practices
          </p>
          <p className="text-xs text-slate-500 mt-2">
            Score based on the ratio of followed to violated security best practices across all findings.
          </p>
        </div>
      </div>

      {/* Category Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        {Object.entries(data.categories).map(([category, stats]) => {
          const total = stats.violations + stats.followed;
          const pct = total > 0 ? Math.round((stats.followed / total) * 100) : 0;
          return (
            <div key={category} className="card">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-white">{category}</span>
                <span className={`text-sm font-bold ${pct >= 70 ? "text-green-400" : pct >= 40 ? "text-yellow-400" : "text-red-400"}`}>
                  {pct}%
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-[#1a1a2e] overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${pct}%`,
                    backgroundColor: pct >= 70 ? "#22c55e" : pct >= 40 ? "#eab308" : "#ef4444",
                  }}
                />
              </div>
              <div className="flex justify-between mt-1 text-xs text-slate-500">
                <span>{stats.followed} followed</span>
                <span>{stats.violations} violated</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Anti-Patterns */}
      {data.anti_patterns.length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-bold text-white mb-4">Recurring Anti-Patterns</h2>
          <div className="space-y-3">
            {data.anti_patterns.map((ap, i) => (
              <div key={i} className="card flex items-center gap-4 border-red-500/20">
                <div className="w-12 h-12 rounded-lg bg-red-500/10 flex items-center justify-center">
                  <span className="text-xl font-bold text-red-400">{ap.occurrences}x</span>
                </div>
                <div>
                  <div className="text-sm font-medium text-white">{ap.practice}</div>
                  <div className="text-xs text-slate-400">{ap.category}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top Violations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div>
          <h2 className="text-lg font-bold text-red-400 mb-4">Top Violations</h2>
          <div className="space-y-2">
            {data.top_violations.map((v, i) => (
              <div key={i} className="card border-red-500/20 p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-white">{v.practice}</span>
                  <span className="text-xs text-slate-500 badge">{v.category}</span>
                </div>
                <p className="text-xs text-slate-400">{v.current_state}</p>
                <p className="text-xs text-green-400 mt-1">{v.recommended_state}</p>
              </div>
            ))}
            {data.top_violations.length === 0 && (
              <p className="text-sm text-slate-400">No violations found</p>
            )}
          </div>
        </div>

        <div>
          <h2 className="text-lg font-bold text-green-400 mb-4">Good Practices</h2>
          <div className="space-y-2">
            {data.top_followed.map((fp, i) => (
              <div key={i} className="card border-green-500/20 p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-white">{fp.practice}</span>
                  <span className="text-xs text-slate-500 badge">{fp.category}</span>
                </div>
                <p className="text-xs text-slate-400">{fp.detail}</p>
              </div>
            ))}
            {data.top_followed.length === 0 && (
              <p className="text-sm text-slate-400">No good practices found</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
