"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { listScans, type ScanSummary } from "@/lib/api";
import { formatDate, statusColor, severityColor } from "@/lib/utils";
import { NewScanDialog } from "@/components/scans/NewScanDialog";
import { PipelineStatus } from "@/components/scans/PipelineStatus";

export default function ScansPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [showDialog, setShowDialog] = useState(false);

  const fetchScans = useCallback(async () => {
    try {
      const data = await listScans();
      setScans(data);
    } catch {
      // API might not be running
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
    // Poll every 3 seconds if any scan is in progress
    const interval = setInterval(() => {
      if (scans.some((s) => !["COMPLETED", "FAILED"].includes(s.status))) {
        fetchScans();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [fetchScans, scans]);

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Scans</h1>
          <p className="text-sm text-slate-400 mt-1">
            Manage and monitor AI-powered security scans
          </p>
        </div>
        <button
          onClick={() => setShowDialog(true)}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-blue-600 text-white hover:bg-blue-500 text-sm font-medium transition-colors"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Scan
        </button>
      </div>

      {/* Scans List */}
      {loading ? (
        <div className="text-center py-20 text-slate-400">Loading scans...</div>
      ) : scans.length === 0 ? (
        <div className="card text-center py-16">
          <svg className="w-12 h-12 mx-auto text-slate-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <h3 className="text-lg font-medium text-white mb-1">No scans yet</h3>
          <p className="text-sm text-slate-400 mb-4">
            Start your first security scan to analyze your codebase
          </p>
          <button
            onClick={() => setShowDialog(true)}
            className="px-4 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-500 text-sm font-medium"
          >
            Start First Scan
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => (
            <Link
              key={scan.id}
              href={`/scans/${scan.id}`}
              className="card block hover:border-[#3a3a5e] transition-colors"
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="mono text-blue-400">{scan.id}</span>
                    <span className={`badge ${
                      scan.status === "COMPLETED"
                        ? "text-green-400 bg-green-400/10 border-green-400/30"
                        : scan.status === "FAILED"
                        ? "text-red-400 bg-red-400/10 border-red-400/30"
                        : "text-blue-400 bg-blue-400/10 border-blue-400/30"
                    }`}>
                      {scan.status}
                    </span>
                    {scan.dry_run && (
                      <span className="badge text-gray-400 bg-gray-400/10 border-gray-400/30">
                        DRY RUN
                      </span>
                    )}
                  </div>
                  <div className="text-sm text-slate-400 mt-1">
                    {scan.repository_path} &middot; {formatDate(scan.created_at)}
                  </div>
                </div>

                {/* Summary stats */}
                {scan.status === "COMPLETED" && (
                  <div className="flex gap-4 text-right">
                    <div>
                      <div className="text-lg font-bold text-white">{scan.total_findings}</div>
                      <div className="text-xs text-slate-400">Findings</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold text-red-400">{scan.confirmed_findings}</div>
                      <div className="text-xs text-slate-400">Confirmed</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold text-green-400">{scan.fixed_findings}</div>
                      <div className="text-xs text-slate-400">Fixed</div>
                    </div>
                    {scan.compliance_rating && (
                      <div>
                        <div className={`text-lg font-bold ${
                          severityColor[scan.compliance_rating]?.split(" ")[0] || "text-gray-400"
                        }`}>
                          {scan.compliance_rating}
                        </div>
                        <div className="text-xs text-slate-400">Risk</div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Error message */}
              {scan.error && (
                <div className="p-2 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-xs mb-2">
                  {scan.error}
                </div>
              )}
            </Link>
          ))}
        </div>
      )}

      <NewScanDialog
        open={showDialog}
        onClose={() => setShowDialog(false)}
        onCreated={fetchScans}
      />
    </div>
  );
}
