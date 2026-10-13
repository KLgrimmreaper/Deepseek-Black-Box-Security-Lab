import { useEffect, useState } from "react";
import { getHealth, getRun, getRuns } from "./api";
import type { Health, Run, RunDetail as RunDetailData } from "./types";
import NewRunForm from "./components/NewRunForm";
import RunList from "./components/RunList";
import RunDetail from "./components/RunDetail";

const POLL_MS = 3000;

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<RunDetailData | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setError("the backend is not answering on /api, start it with uvicorn backend.app:app"));
    // the list is small and cheap, so polling it keeps the progress text current
    const loadRuns = () => getRuns().then((data) => setRuns(data.runs)).catch(() => undefined);
    loadRuns();
    const timer = setInterval(loadRuns, POLL_MS);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (selectedId === null) {
      setDetail(null);
      return;
    }
    let active = true;
    const load = () =>
      getRun(selectedId)
        .then((data) => {
          if (active) {
            setDetail(data);
            setError("");
          }
        })
        .catch((problem: unknown) => {
          if (active) {
            setError(problem instanceof Error ? problem.message : String(problem));
          }
        });
    load();
    const timer = setInterval(load, POLL_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [selectedId]);

  return (
    <div className="page">
      <header className="topbar">
        <div>
          <h1>deepseek black-box security lab</h1>
          <p className="hint">
            {health
              ? `${health.checks} checks in the catalogue, request budget ${health.max_requests_per_run} per run`
              : "loading backend settings"}
          </p>
        </div>
        {health && (
          <div className="tags">
            <span className="tag">targets: {health.allowed_targets.join(", ") || "none configured"}</span>
            <span className="tag">{health.mock_agent ? "mock agent" : `model: ${health.model}`}</span>
            <span className={health.has_api_key ? "tag ok" : "tag warn"}>
              {health.has_api_key ? "api key loaded" : "no api key"}
            </span>
          </div>
        )}
      </header>

      {error && <p className="error">{error}</p>}

      <div className="layout">
        <div className="column">
          <NewRunForm health={health} onStarted={setSelectedId} />
          <RunList runs={runs} selectedId={selectedId} onSelect={setSelectedId} />
        </div>
        <div className="column wide">
          {detail ? (
            <RunDetail detail={detail} />
          ) : (
            <div className="card">
              <h2>run detail</h2>
              <p className="hint">pick a run on the left, or start a new one.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
