import { useState } from "react";
import { getEvidence } from "../api";
import type { Finding } from "../types";

type Props = {
  finding: Finding;
  runId: number;
};

export default function FindingCard({ finding, runId }: Props) {
  const [evidence, setEvidence] = useState("");
  const [error, setError] = useState("");

  async function toggleEvidence() {
    if (evidence) {
      setEvidence("");
      return;
    }
    try {
      setEvidence(await getEvidence(runId, finding.check_id));
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : String(problem));
    }
  }

  return (
    <article className={`finding ${finding.severity}`}>
      <header>
        <span className={`badge ${finding.severity}`}>{finding.severity}</span>
        <h4>{finding.title}</h4>
        <span className="status">{finding.status}</span>
      </header>
      <p>{finding.description}</p>
      <p>
        <strong>impact:</strong> {finding.impact}
      </p>
      <p>
        <strong>remediation:</strong> {finding.remediation}
      </p>
      {finding.model_generated === 1 && <p className="hint">impact and remediation written by the model</p>}
      <p className="hint">
        evidence: <code>{finding.evidence_path}</code>
      </p>
      <button type="button" onClick={toggleEvidence}>
        {evidence ? "hide evidence" : "show evidence"}
      </button>
      {error && <p className="error">{error}</p>}
      {evidence && <pre className="evidence">{evidence}</pre>}
    </article>
  );
}
