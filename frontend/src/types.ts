export type Run = {
  id: number;
  target: string;
  status: string;
  stage: string;
  model: string;
  notes: string;
  summary: string;
  summary_source: string;
  profile_json: string;
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
  run_id: number;
  check_id: string;
  title: string;
  severity: string;
  status: string;
  evidence_path: string;
  description: string;
  impact: string;
  remediation: string;
  model_generated: number;
  target?: string;
  started_at?: string;
};

export type Plan = {
  source: string;
  checks: { id: string; reason: string; round?: number }[];
  skipped: { id: string; reason: string }[];
  rounds?: { round: number; note: string; done: boolean }[];
};

export type ObservedFacts = {
  application_shape?: string;
  login_shape?: string;
  login_form?: { action?: string; path?: string; same_origin?: boolean; fields?: string[] } | null;
  search_endpoint?: { path?: string; status?: number; present?: boolean };
  unknown_path_status?: number;
  unknown_path_returns_app_shell?: boolean;
  root_status?: number;
  root_content_type?: string;
  untrusted?: { title?: string; server_header?: string; powered_by?: string };
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

export type Counter = {
  label: string;
  value: number;
};

export type Stats = {
  totals: {
    runs: number;
    finished: number;
    failed: number;
    checks_run: number;
    findings: number;
    requests: number;
  };
  by_severity: Counter[];
  by_result: Counter[];
  top_failing_checks: Counter[];
  trend: Counter[];
};
