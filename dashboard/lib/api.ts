/**
 * DevSecOps Guardian - API Client
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "https://ca-api-gateway.agreeablesand-6566841b.eastus.azurecontainerapps.io";

async function fetchAPI<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(error.detail || `API error: ${res.status}`);
  }

  return res.json();
}

// Health
export async function getHealth() {
  return fetchAPI<{
    status: string;
    version: string;
    agents: Record<string, string>;
  }>("/api/health");
}

// Scans
export interface ScanSummary {
  id: string;
  status: string;
  repository_path: string;
  ref: string | null;
  dry_run: boolean;
  created_at: string;
  updated_at: string;
  total_findings: number;
  confirmed_findings: number;
  fixed_findings: number;
  risk_level: string | null;
  compliance_rating: string | null;
  current_stage: string | null;
  error: string | null;
  parent_scan_id: string | null;
  scan_number: number;
}

export interface ScanDetail extends ScanSummary {
  scanner_output: Record<string, unknown> | null;
  analyzer_output: Record<string, unknown> | null;
  fixer_output: Record<string, unknown> | null;
  risk_profile_output: Record<string, unknown> | null;
  compliance_output: Record<string, unknown> | null;
  stages: Record<string, string>;
  comparison: ScanComparison | null;
}

export async function createScan(body: {
  repository_path: string;
  ref?: string;
  dry_run?: boolean;
}) {
  return fetchAPI<ScanSummary>("/api/scans", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function listScans() {
  return fetchAPI<ScanSummary[]>("/api/scans");
}

export async function getScan(id: string) {
  return fetchAPI<ScanDetail>(`/api/scans/${id}`);
}

// Findings
export interface CodeContext {
  vulnerable_code: string;
  related_files: Array<{
    file: string;
    relevance: string;
    snippet: string;
  }>;
}

export interface BestPracticeViolation {
  practice: string;
  category: string;
  current_state: string;
  recommended_state: string;
  owasp_reference: string;
}

export interface BestPracticeFollowed {
  practice: string;
  category: string;
  detail: string;
}

export interface BestPracticesAnalysis {
  violated_practices: BestPracticeViolation[];
  followed_practices: BestPracticeFollowed[];
}

export interface Finding {
  scan_id: string;
  anlz_id: string;
  file: string;
  line: number;
  vulnerability: string;
  cwe: string;
  severity: string;
  description: string;
  evidence: string;
  recommendation: string;
  verdict: string;
  exploitability_score: number;
  fix_status: string;
  fix_summary: string | null;
  pr_url: string | null;
  pr_number: number | null;
  // New fields
  code_context: CodeContext | null;
  analysis_reasoning: string;
  best_practices_analysis: BestPracticesAnalysis | null;
  fixed_code: string;
  fix_explanation: string;
  fix_error: string;
  auth_context: string;
  data_sensitivity: string;
  attack_scenario: string | null;
  false_positive_reason: string | null;
  confirmed_evidence: string | null;
  status_change: string | null;
}

export interface FindingsResponse {
  scan_id: string;
  total: number;
  confirmed: number;
  false_positives: number;
  fixed: number;
  findings: Finding[];
}

export async function getFindings(scanId: string, params?: {
  severity?: string;
  verdict?: string;
}) {
  const query = new URLSearchParams();
  if (params?.severity) query.set("severity", params.severity);
  if (params?.verdict) query.set("verdict", params.verdict);
  const qs = query.toString();
  return fetchAPI<FindingsResponse>(
    `/api/scans/${scanId}/findings${qs ? `?${qs}` : ""}`
  );
}

// Risk Profile
export interface OWASPCategory {
  category: string;
  score: number;
  findings_count: number;
  description: string;
}

export interface RiskProfileResponse {
  scan_id: string;
  overall_risk_score: number;
  risk_level: string;
  owasp_top_10: OWASPCategory[];
  attack_surface: Record<string, number>;
  executive_summary: string;
}

export async function getRiskProfile(scanId: string) {
  return fetchAPI<RiskProfileResponse>(`/api/scans/${scanId}/risk-profile`);
}

// Compliance
export interface ComplianceRequirement {
  requirement_id: string;
  requirement_title: string;
  relevance: string;
  compliance_status: string;
  evidence: string;
  remediation_status: string;
  remediation_evidence: string;
}

export interface ComplianceFinding {
  scan_id: string;
  vulnerability: string;
  cwe: string;
  severity: string;
  pci_dss_requirements: ComplianceRequirement[];
  risk_rating: string;
  risk_justification: string;
  regulatory_impact: string;
}

export interface ComplianceResponse {
  scan_id: string;
  framework: string;
  overall_risk_rating: string;
  compliant_count: number;
  non_compliant_count: number;
  executive_summary: string;
  findings: ComplianceFinding[];
  recommendations: string[];
}

export async function getCompliance(scanId: string) {
  return fetchAPI<ComplianceResponse>(`/api/scans/${scanId}/compliance`);
}

// Scan Comparison
export interface ScanComparisonFinding {
  scan_id: string;
  vulnerability: string;
  cwe: string;
  file: string;
  severity: string;
  status_change: string;
}

export interface ScanComparison {
  current_scan_id: string;
  parent_scan_id: string;
  new_findings: number;
  resolved_findings: number;
  persistent_findings: number;
  regression_findings: number;
  findings: ScanComparisonFinding[];
}

// Practices
export interface PracticesSummary {
  scan_id: string;
  total_violations: number;
  total_followed: number;
  maturity_score: number;
  categories: Record<string, { violations: number; followed: number }>;
  top_violations: BestPracticeViolation[];
  top_followed: BestPracticeFollowed[];
  anti_patterns: Array<{
    practice: string;
    occurrences: number;
    category: string;
  }>;
}

export async function getScanHistory(scanId: string) {
  return fetchAPI<ScanSummary[]>(`/api/scans/${scanId}/history`);
}

export async function getPractices(scanId: string) {
  return fetchAPI<PracticesSummary>(`/api/scans/${scanId}/practices`);
}
