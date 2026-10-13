import { useEffect, useState } from "react";
import { getReport } from "../api";
import type { ObservedFacts, RunDetail as RunDetailData } from "../types";
import FindingCard from "./FindingCard";

const TABS = ["results", "plan", "findings", "report"] as const;
type Tab = (typeof TABS)[number];

function parseFacts(json: string | undefined): ObservedFacts | null {
  if (!json) {
    return null;
  }
  try {
    const parsed = JSON.parse(json);
    if (!parsed || typeof parsed !== "object" || Object.keys(parsed).length === 0) {
      return null;
    }
    return parsed as ObservedFacts;
  } catch {
    return null;
  }
}

function FactsCard({ facts }: { facts: ObservedFacts }) {
  const form = facts.login_form;
  const search = facts.search_endpoint;
  const untrusted = facts.untrusted ?? {};
  const rows: [string, string][] = [];
  if (facts.application_shape) {
    rows.push(["application shape", facts.application_shape]);
  }
  if (facts.login_shape) {
    rows.push(["login shape", facts.login_shape]);
  }
  rows.push([
    "login form",
    form && form.fields?.length
      ? `${form.action || "(no action)"} posting ${form.fields.join(", ")}${form.same_origin === false ? " (off host, not used)" : ""}`
      : "none found",
  ]);
  if (search?.path) {
    rows.push(["search endpoint", `${search.path} answered ${search.status}`]);
  }
  if (facts.unknown_path_status !== undefined) {
    rows.push([
      "unknown paths",
      facts.unknown_path_returns_app_shell ? "return the app page" : `answer ${facts.unknown_path_status}`,
    ]);
  }
  if (facts.root_status !== undefined) {
    rows.push(["root", `${facts.root_status} ${facts.root_content_type ?? ""}`.trim()]);
  }
  if (untrusted.title) {
    rows.push(["untrusted title (from the target)", untrusted.title]);
  }

  return (
    <section className="card">
      <header className="card-head">
        <div>
          <h3>what the runner observed</h3>
          <p className="card-sub">
            collected before planning. this is the only thing the model was shown about the target, so the
            model never reads the page itself.
          </p>
        </div>
      </header>
      <dl className="facts">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

type Props = {
  detail: RunDetailData;
};

export default function RunDetail({ detail }: Props) {
  const { run, plan, results, findings } = detail;
  const facts = parseFacts(run.profile_json);
  const rounds = plan.rounds ?? [];
  const [tab, setTab] = useState<Tab>("results");
  const [report, setReport] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    // a different run was picked, so the old tab and report text belong to the wrong run
    setTab("results");
    setReport("");
  }, [run.id]);

  useEffect(() => {
    if (tab !== "report") {
      return;
    }
    const load = () =>
      getReport(run.id)
        .then(setReport)
        .catch((problem: unknown) => setError(problem instanceof Error ? problem.message : String(problem)));
    load();
    if (run.status !== "running") {
      return;
    }
    // the report keeps changing while checks are still being written
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, [tab, run.id, run.status]);

  return (
    <>
      <section className="card">
        <header className="card-head">
          <div>
            <h2>
              run #{run.id} <span className={`status ${run.status}`}>{run.status}</span>
            </h2>
            <p className="card-sub">{run.target}</p>
          </div>
          <span className="chip">{run.request_count} requests</span>
        </header>

        <dl className="facts">
          <div>
            <dt>agent</dt>
            <dd>{run.model}</dd>
          </div>
          <div>
            <dt>check plan</dt>
            <dd>{plan.source}</dd>
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
          {!run.summary
            ? "the summary is written when the run finishes."
            : run.summary_source === "model"
              ? "written by the model. the results and findings below are recorded by the runner from the actual responses."
              : "written by the runner from the recorded results, not by the model."}
        </p>
      </section>

      {facts && <FactsCard facts={facts} />}

      <section className="card">
        <div className="pills">
          {TABS.map((name) => (
            <button
              key={name}
              type="button"
              className={name === tab ? "pill active" : "pill"}
              onClick={() => setTab(name)}
            >
              {name}
              {name === "results" && <span className="pill-count">{results.length}</span>}
              {name === "plan" && <span className="pill-count">{plan.checks.length}</span>}
              {name === "findings" && <span className="pill-count">{findings.length}</span>}
            </button>
          ))}
        </div>

        {tab === "results" &&
          (results.length === 0 ? (
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
          ))}

        {tab === "plan" &&
          (plan.checks.length === 0 ? (
            <p className="hint">no plan yet</p>
          ) : (
            <>
              {rounds.length > 1 && (
                <p className="hint">
                  planned over {rounds.length} rounds, each round seeing the results of the one before
                </p>
              )}
              <table>
                <thead>
                  <tr>
                    {rounds.length > 1 && <th>round</th>}
                    <th>check</th>
                    <th>why the agent picked it</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.checks.map((item) => (
                    <tr key={item.id}>
                      {rounds.length > 1 && <td>{item.round ?? 1}</td>}
                      <td>
                        <code>{item.id}</code>
                      </td>
                      <td>{item.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {rounds.some((entry) => entry.note) && (
                <p className="hint">
                  {rounds
                    .filter((entry) => entry.note)
                    .map((entry) => `round ${entry.round}: ${entry.note}`)
                    .join(" | ")}
                </p>
              )}
              {plan.skipped.length > 0 && (
                <p className="hint">
                  skipped: {plan.skipped.map((item) => `${item.id} (${item.reason})`).join(", ")}
                </p>
              )}
            </>
          ))}

        {tab === "findings" &&
          (findings.length === 0 ? (
            <p className="hint">no confirmed findings in this run</p>
          ) : (
            findings.map((finding) => <FindingCard key={finding.id} finding={finding} runId={run.id} />)
          ))}

        {tab === "report" && (
          <>
            <p className="hint">the markdown file written for this run, ready to paste into a write up</p>
            {error && <p className="error">{error}</p>}
            <pre className="evidence">{report || "loading the report"}</pre>
          </>
        )}
      </section>
    </>
  );
}
