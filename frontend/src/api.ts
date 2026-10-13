import type { CatalogueEntry, Health, Run, RunDetail } from "./types";

const BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(BASE + path, options);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body.detail) {
        detail = String(body.detail);
      }
    } catch {
      // the error body was not json, the status text is good enough
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

export function getHealth(): Promise<Health> {
  return request<Health>("/health");
}

export function getChecks(): Promise<{ checks: CatalogueEntry[] }> {
  return request<{ checks: CatalogueEntry[] }>("/checks");
}

export function getRuns(): Promise<{ runs: Run[] }> {
  return request<{ runs: Run[] }>("/runs");
}

export function getRun(runId: number): Promise<RunDetail> {
  return request<RunDetail>(`/runs/${runId}`);
}

export function startRun(target: string, notes: string): Promise<{ run_id: number }> {
  return request<{ run_id: number }>("/runs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, notes }),
  });
}

export function getReport(runId: number): Promise<string> {
  return fetch(`${BASE}/runs/${runId}/report`).then((response) => {
    if (!response.ok) {
      throw new Error(`the report could not be loaded (${response.status})`);
    }
    return response.text();
  });
}

export function getEvidence(runId: number, checkId: string): Promise<string> {
  return fetch(`${BASE}/runs/${runId}/evidence/${checkId}`).then((response) => {
    if (!response.ok) {
      throw new Error(`the evidence could not be loaded (${response.status})`);
    }
    return response.text();
  });
}
