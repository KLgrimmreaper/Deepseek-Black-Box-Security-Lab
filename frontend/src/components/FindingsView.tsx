import { useEffect, useState } from "react";
import { getFindings } from "../api";
import { SEVERITY_ORDER } from "../theme";
import type { Finding } from "../types";
import FindingCard from "./FindingCard";

const FILTERS = ["all", ...SEVERITY_ORDER];

export default function FindingsView() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState("");

  function load() {
    getFindings()
      .then((data) => {
        setFindings(data.findings);
        setError("");
      })
      .catch((problem: unknown) => setError(problem instanceof Error ? problem.message : String(problem)));
  }

  useEffect(load, []);

  const shown = filter === "all" ? findings : findings.filter((finding) => finding.severity === filter);
  const countFor = (name: string) =>
    name === "all" ? findings.length : findings.filter((finding) => finding.severity === name).length;

  return (
    <>
      <div className="toolbar">
        <div className="pills">
          {FILTERS.map((name) => (
            <button
              key={name}
              type="button"
              className={name === filter ? "pill active" : "pill"}
              onClick={() => setFilter(name)}
            >
              {name}
              <span className="pill-count">{countFor(name)}</span>
            </button>
          ))}
        </div>
        <button type="button" className="ghost" onClick={load}>
          refresh
        </button>
      </div>

      {error && <p className="error">{error}</p>}
      {findings.length === 0 && !error && (
        <section className="card">
          <h3>no findings yet</h3>
          <p className="hint">
            a finding is only stored when a check actually failed and its evidence file was written. run some checks
            first.
          </p>
        </section>
      )}

      {shown.map((finding) => (
        <div key={finding.id}>
          {finding.target && (
            <p className="finding-source">
              run #{finding.run_id} against {finding.target} on {finding.started_at}
            </p>
          )}
          <FindingCard finding={finding} runId={finding.run_id} />
        </div>
      ))}
    </>
  );
}
