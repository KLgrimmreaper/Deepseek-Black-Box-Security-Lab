import { useEffect, useState } from "react";
import { getReport } from "../api";
import type { RunDetail as RunDetailData } from "../types";
import FindingCard from "./FindingCard";

type Props = {
  detail: RunDetailData;
};

export default function RunDetail({ detail }: Props) {
  const { run, plan, results, findings } = detail;
  const [report, setReport] = useState("");
  const [showReport, setShowReport] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    // a different run was picked, so the old report text would be wrong
    setReport("");
    setShowReport(false);
  }, [run.id]);

  async function toggleReport() {
    if (!showReport && !report) {
      try {
        setReport(await getReport(run.id));
      } catch (problem) {
        setError(problem instanceof Error ? problem.message : String(problem));
        return;
      }
    }
    setShowReport(!showReport);
  }

  return (
    <>
      <div className="card">
        <h2>
          run #{run.id} <span className={`status ${run.status}`}>{run.status}</span>
        </h2>
        <dl className="facts">
          <div>
            <dt>target</dt>
            <dd>{run.target}</dd>
          </div>
          <div>
            <dt>agent</dt>
            <dd>{run.model}</dd>
          </div>
          <div>
            <dt>check plan</dt>
            <dd>{plan.source}</dd>
          </div>
          <div>
            <dt>requests used</dt>
            <dd>{run.request_count}</dd>
          </div>
          <div>
            <dt>started</dt>
            <dd>{run.started_at}</dd>
          </div>
          <div>
            <dt>finished</dt>
            <dd>{run.finished_at ?? "still running"}</dd>
          </div>
          {run.notes && (
            <div>
              <dt>notes</dt>
              <dd>{run.notes}</dd>
            </div>
          )}
        </dl>

        {run.status === "running" && <p className="hint">working on: {run.stage || "starting"}</p>}
        {run.error && <p className="error">{run.error}</p>}

        <h3>summary</h3>
        <p className="summary">{run.summary || "no summary yet"}</p>
        <p className="hint">
          {run.summary_source === "model"
            ? "written by the model. the results and findings below are recorded by the runner from the actual responses."
            : "written by the runner from the recorded results, not by the model."}
        </p>
      </div>

      <div className="card">
        <h3>planned checks</h3>
        {plan.checks.length === 0 ? (
          <p className="hint">no plan yet</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>check</th>
                <th>why the agent picked it</th>
              </tr>
            </thead>
            <tbody>
              {plan.checks.map((item) => (
                <tr key={item.id}>
                  <td>
                    <code>{item.id}</code>
                  </td>
                  <td>{item.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {plan.skipped.length > 0 && (
          <p className="hint">
            skipped: {plan.skipped.map((item) => `${item.id} (${item.reason})`).join(", ")}
          </p>
        )}
      </div>

      <div className="card">
        <h3>results</h3>
        {results.length === 0 ? (
          <p className="hint">no checks have run yet</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>check</th>
                <th>severity</th>
                <th>result</th>
                <th>detail</th>
              </tr>
            </thead>
            <tbody>
              {results.map((row) => (
                <tr key={row.id}>
                  <td>
                    <code>{row.check_id}</code>
                  </td>
                  <td>
                    <span className={`badge ${row.severity}`}>{row.severity}</span>
                  </td>
                  <td>
                    <span className={`result ${row.result}`}>{row.result}</span>
                  </td>
                  <td>{row.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h3>findings ({findings.length})</h3>
        {findings.length === 0 && <p className="hint">no confirmed findings in this run</p>}
        {findings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} runId={run.id} />
        ))}
      </div>

      <div className="card">
        <h3>report</h3>
        <p className="hint">the markdown file written for this run, ready to paste into a write up</p>
        <button type="button" onClick={toggleReport}>
          {showReport ? "hide report" : "show report"}
        </button>
        {error && <p className="error">{error}</p>}
        {showReport && <pre className="evidence">{report}</pre>}
      </div>
    </>
  );
}
