"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { getScan, type ScanDetail } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { PipelineStatus } from "@/components/scans/PipelineStatus";

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchScan = useCallback(async () => {
    try {
      const data = await getScan(scanId);
      setScan(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchScan();
    const interval = setInterval(() => {
      if (scan && !["COMPLETED", "FAILED"].includes(scan.status)) {
        fetchScan();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [fetchScan, scan]);

  if (loading) {
    return (
      <div className="p-6 text-center text-slate-400">Loading scan...</div>
    );
  }

  if (error || !scan) {
    return (
      <div className="p-6">
        <div className="card text-center py-8">
          <p className="text-red-400">{error || "Scan not found"}</p>
          <Link href="/scans" className="text-blue-400 text-sm mt-2 inline-block hover:underline">
            Back to Scans
          </Link>
        </div>
      </div>
    );
  }

  const navTabs = [
    { label: "Findings", href: `/scans/${scanId}/findings`, ready: !!scan.analyzer_output },
    { label: "Risk Profile", href: `/scans/${scanId}/risk-profile`, ready: !!scan.analyzer_output },
    { label: "Compliance", href: `/scans/${scanId}/compliance`, ready: !!scan.compliance_output },
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link href="/scans" className="hover:text-white transition-colors">
          Scans
        </Link>
        <span>/</span>
        <span className="mono text-blue-400">{scan.id}</span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            Scan Overview
            <span className={`badge ${
              scan.status === "COMPLETED"
                ? "text-green-400 bg-green-400/10 border-green-400/30"
                : scan.status === "FAILED"
                ? "text-red-400 bg-red-400/10 border-red-400/30"
                : "text-blue-400 bg-blue-400/10 border-blue-400/30"
            }`}>
              {scan.status}
            </span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            {scan.repository_path} &middot; Started {formatDate(scan.created_at)}
          </p>
        </div>
      </div>

      {/* Pipeline Status */}
      <div className="card mb-6">
        <h3 className="text-sm font-medium text-slate-300 mb-3">Pipeline Progress</h3>
        <PipelineStatus
          stages={scan.stages}
          currentStage={scan.current_stage}
          status={scan.status}
        />
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="card">
          <div className="text-xs text-slate-400 uppercase tracking-wide mb-1">Total Findings</div>
          <div className="text-3xl font-bold text-white">{scan.total_findings}</div>
          <div className="text-xs text-slate-500 mt-1">Detected by Scanner</div>
        </div>
        <div className="card">
          <div className="text-xs text-slate-400 uppercase tracking-wide mb-1">Confirmed</div>
          <div className="text-3xl font-bold text-red-400">{scan.confirmed_findings}</div>
          <div className="text-xs text-slate-500 mt-1">Verified by Analyzer</div>
        </div>
        <div className="card">
          <div className="text-xs text-slate-400 uppercase tracking-wide mb-1">Fixed</div>
          <div className="text-3xl font-bold text-green-400">{scan.fixed_findings}</div>
          <div className="text-xs text-slate-500 mt-1">Draft PRs Created</div>
        </div>
        <div className="card">
          <div className="text-xs text-slate-400 uppercase tracking-wide mb-1">Risk Rating</div>
          <div className={`text-3xl font-bold ${
            scan.compliance_rating === "CRITICAL" ? "text-red-500" :
            scan.compliance_rating === "HIGH" ? "text-orange-500" :
            scan.compliance_rating === "MEDIUM" ? "text-yellow-500" :
            "text-green-400"
          }`}>
            {scan.compliance_rating || "--"}
          </div>
          <div className="text-xs text-slate-500 mt-1">PCI-DSS 4.0</div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex gap-3">
        {navTabs.map((tab) => (
          <Link
            key={tab.href}
            href={tab.ready ? tab.href : "#"}
            className={`px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
              tab.ready
                ? "bg-[#1a1a2e] border border-[#2a2a4e] text-white hover:border-blue-500/50"
                : "bg-[#1a1a2e]/50 border border-[#2a2a4e]/50 text-slate-500 cursor-not-allowed"
            }`}
          >
            {tab.label}
            {!tab.ready && (
              <span className="ml-2 text-xs text-slate-600">Pending</span>
            )}
          </Link>
        ))}
      </div>
    </div>
  );
}
