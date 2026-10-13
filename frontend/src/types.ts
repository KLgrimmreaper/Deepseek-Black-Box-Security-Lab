export type Run = {
  id: number;
  target: string;
  status: string;
  stage: string;
  model: string;
  notes: string;
  summary: string;
  summary_source: string;
  request_count: number;
  error: string | null;
  started_at: string;
  finished_at: string | null;
  finding_count?: number;
};

export type CheckResult = {
  id: number;
  check_id: string;
  name: string;
  severity: string;
  result: string;
  detail: string;
  reason: string;
  evidence_path: string | null;
  requests_used: number;
};

export type Finding = {
  id: number;
  check_id: string;
  title: string;
  severity: string;
  status: string;
  evidence_path: string;
  description: string;
  impact: string;
  remediation: string;
  model_generated: number;
};

export type Plan = {
  source: string;
  checks: { id: string; reason: string }[];
  skipped: { id: string; reason: string }[];
};

export type RunDetail = {
  run: Run;
  plan: Plan;
  results: CheckResult[];
  findings: Finding[];
};

export type Health = {
  status: string;
  mock_agent: boolean;
  has_api_key: boolean;
  model: string;
  allowed_targets: string[];
  max_requests_per_run: number;
  checks: number;
};

export type CatalogueEntry = {
  id: string;
  name: string;
  category: string;
  severity: string;
  description: string;
  fix: string;
};
