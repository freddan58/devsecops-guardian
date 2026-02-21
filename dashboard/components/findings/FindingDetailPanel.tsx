"use client";

import { useState, useEffect } from "react";
import type { Finding } from "@/lib/api";
import { SeverityBadge, VerdictBadge, FixStatusBadge } from "./SeverityBadge";
import { CodeBlock } from "./CodeBlock";

interface FindingDetailPanelProps {
  finding: Finding | null;
  onClose: () => void;
}

const TABS = ["Overview", "Code", "Analysis", "Fix", "Compliance", "Best Practices"] as const;
type Tab = typeof TABS[number];

export function FindingDetailPanel({ finding, onClose }: FindingDetailPanelProps) {
  const [activeTab, setActiveTab] = useState<Tab>("Overview");

  useEffect(() => {
    setActiveTab("Overview");
  }, [finding?.scan_id]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  if (!finding) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Slide-over Panel */}
      <div className="fixed inset-y-0 right-0 w-[60%] min-w-[600px] max-w-[900px] bg-[#0d0d14] border-l border-[#2a2a4e] z-50 flex flex-col overflow-hidden animate-slide-in">
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#2a2a4e] flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge severity={finding.severity} />
              <VerdictBadge verdict={finding.verdict} />
              <FixStatusBadge status={finding.fix_status} />
            </div>
            <h2 className="text-lg font-bold text-white truncate">{finding.vulnerability}</h2>
            <p className="text-sm text-slate-400 mono mt-1">{finding.file}:{finding.line}</p>
            <p className="text-xs text-slate-500 mt-1">{finding.cwe} &middot; Score: {finding.exploitability_score}/100</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tab Bar */}
        <div className="px-6 border-b border-[#2a2a4e] flex gap-1 overflow-x-auto">
          {TABS.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab
                  ? "border-blue-500 text-blue-400"
                  : "border-transparent text-slate-400 hover:text-white"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          {activeTab === "Overview" && <OverviewTab finding={finding} />}
          {activeTab === "Code" && <CodeTab finding={finding} />}
          {activeTab === "Analysis" && <AnalysisTab finding={finding} />}
          {activeTab === "Fix" && <FixTab finding={finding} />}
          {activeTab === "Compliance" && <ComplianceTab finding={finding} />}
          {activeTab === "Best Practices" && <BestPracticesTab finding={finding} />}
        </div>
      </div>
    </>
  );
}

/* ========== TAB COMPONENTS ========== */

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-2">{title}</h3>
      {children}
    </div>
  );
}

function InfoCard({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg bg-[#1a1a2e] border border-[#2a2a4e] p-4 ${className}`}>
      {children}
    </div>
  );
}

function OverviewTab({ finding }: { finding: Finding }) {
  return (
    <>
      <Section title="Description">
        <InfoCard>
          <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>
        </InfoCard>
      </Section>

      <Section title="Evidence">
        <CodeBlock code={finding.evidence} language="javascript" fileName={finding.file} />
      </Section>

      <Section title="Recommendation">
        <InfoCard>
          <p className="text-sm text-slate-300 leading-relaxed">{finding.recommendation}</p>
        </InfoCard>
      </Section>

      {finding.attack_scenario && (
        <Section title="Attack Scenario">
          <InfoCard className="border-red-500/30">
            <p className="text-sm text-red-300 leading-relaxed">{finding.attack_scenario}</p>
          </InfoCard>
        </Section>
      )}

      <div className="grid grid-cols-2 gap-3">
        {finding.auth_context && (
          <Section title="Auth Context">
            <InfoCard>
              <p className="text-xs text-slate-300 mono">{finding.auth_context}</p>
            </InfoCard>
          </Section>
        )}
        {finding.data_sensitivity && (
          <Section title="Data Sensitivity">
            <InfoCard>
              <p className="text-xs text-slate-300 mono">{finding.data_sensitivity}</p>
            </InfoCard>
          </Section>
        )}
      </div>
    </>
  );
}

function CodeTab({ finding }: { finding: Finding }) {
  const ctx = finding.code_context;

  if (!ctx?.vulnerable_code) {
    return (
      <InfoCard>
        <p className="text-sm text-slate-400 text-center py-4">
          No code context available. Run a new scan to capture code context.
        </p>
      </InfoCard>
    );
  }

  return (
    <>
      <Section title="Vulnerable Code">
        <CodeBlock
          code={ctx.vulnerable_code}
          language="javascript"
          highlightLine={finding.line}
          fileName={finding.file}
        />
      </Section>

      {ctx.related_files && ctx.related_files.length > 0 && (
        <Section title="Related Files">
          <div className="space-y-3">
            {ctx.related_files.map((rf, i) => (
              <div key={i}>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs mono text-blue-300">{rf.file}</span>
                  <span className="text-xs text-slate-500">&mdash; {rf.relevance}</span>
                </div>
                <CodeBlock
                  code={rf.snippet || ""}
                  language="javascript"
                  fileName={rf.file}
                />
              </div>
            ))}
          </div>
        </Section>
      )}
    </>
  );
}

function AnalysisTab({ finding }: { finding: Finding }) {
  return (
    <>
      {finding.analysis_reasoning && (
        <Section title="Analysis Reasoning">
          <InfoCard>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
              {finding.analysis_reasoning}
            </p>
          </InfoCard>
        </Section>
      )}

      <div className="grid grid-cols-2 gap-4">
        <Section title="Verdict">
          <InfoCard>
            <div className="flex items-center gap-2 mb-2">
              <VerdictBadge verdict={finding.verdict} />
              <span className="text-2xl font-bold text-white">{finding.exploitability_score}/100</span>
            </div>
          </InfoCard>
        </Section>

        <Section title="Auth Context">
          <InfoCard>
            <p className="text-sm text-slate-300">{finding.auth_context || "N/A"}</p>
          </InfoCard>
        </Section>
      </div>

      {finding.confirmed_evidence && (
        <Section title="Confirmed Evidence">
          <CodeBlock code={finding.confirmed_evidence} language="javascript" />
        </Section>
      )}

      {finding.false_positive_reason && (
        <Section title="False Positive Reason">
          <InfoCard className="border-green-500/30">
            <p className="text-sm text-green-300">{finding.false_positive_reason}</p>
          </InfoCard>
        </Section>
      )}
    </>
  );
}

function FixTab({ finding }: { finding: Finding }) {
  return (
    <>
      <Section title="Fix Status">
        <InfoCard>
          <div className="flex items-center gap-3 mb-3">
            <FixStatusBadge status={finding.fix_status} />
            {finding.pr_url && (
              <a
                href={finding.pr_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 hover:text-blue-300 text-sm underline"
              >
                PR #{finding.pr_number}
              </a>
            )}
          </div>
          {finding.fix_summary && (
            <p className="text-sm text-slate-300">{finding.fix_summary}</p>
          )}
          {finding.fix_error && (
            <p className="text-sm text-red-400 mt-2">{finding.fix_error}</p>
          )}
        </InfoCard>
      </Section>

      {finding.fix_explanation && (
        <Section title="Fix Explanation">
          <InfoCard>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
              {finding.fix_explanation}
            </p>
          </InfoCard>
        </Section>
      )}

      {finding.fixed_code && (
        <Section title="Fixed Code">
          <CodeBlock
            code={finding.fixed_code}
            language="javascript"
            fileName={`${finding.file} (fixed)`}
          />
        </Section>
      )}

      {!finding.fixed_code && finding.fix_status === "PENDING" && (
        <InfoCard>
          <p className="text-sm text-slate-400 text-center py-4">
            Fix has not been generated yet.
          </p>
        </InfoCard>
      )}
    </>
  );
}

function ComplianceTab({ finding }: { finding: Finding }) {
  return (
    <InfoCard>
      <p className="text-sm text-slate-400 text-center py-4">
        View detailed PCI-DSS 4.0 compliance mapping on the{" "}
        <span className="text-blue-400">Compliance</span> page.
      </p>
      <div className="text-center mt-2">
        <span className="text-xs text-slate-500">
          CWE: {finding.cwe} &middot; Severity: {finding.severity}
        </span>
      </div>
    </InfoCard>
  );
}

function BestPracticesTab({ finding }: { finding: Finding }) {
  const bp = finding.best_practices_analysis;

  if (!bp) {
    return (
      <InfoCard>
        <p className="text-sm text-slate-400 text-center py-4">
          No best practices analysis available. Run a new scan to generate this data.
        </p>
      </InfoCard>
    );
  }

  return (
    <>
      {bp.violated_practices.length > 0 && (
        <Section title={`Violated Practices (${bp.violated_practices.length})`}>
          <div className="space-y-2">
            {bp.violated_practices.map((v, i) => (
              <InfoCard key={i} className="border-red-500/20">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-red-400">{v.practice}</span>
                  <span className="text-xs text-slate-500 badge">{v.category}</span>
                </div>
                <p className="text-xs text-slate-400 mb-1">
                  <span className="text-slate-500">Current:</span> {v.current_state}
                </p>
                <p className="text-xs text-green-400">
                  <span className="text-slate-500">Recommended:</span> {v.recommended_state}
                </p>
                {v.owasp_reference && (
                  <p className="text-xs text-slate-500 mt-1">{v.owasp_reference}</p>
                )}
              </InfoCard>
            ))}
          </div>
        </Section>
      )}

      {bp.followed_practices.length > 0 && (
        <Section title={`Followed Practices (${bp.followed_practices.length})`}>
          <div className="space-y-2">
            {bp.followed_practices.map((fp, i) => (
              <InfoCard key={i} className="border-green-500/20">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-green-400">{fp.practice}</span>
                  <span className="text-xs text-slate-500 badge">{fp.category}</span>
                </div>
                <p className="text-xs text-slate-400">{fp.detail}</p>
              </InfoCard>
            ))}
          </div>
        </Section>
      )}
    </>
  );
}
