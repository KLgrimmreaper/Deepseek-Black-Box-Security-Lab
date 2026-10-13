import { useEffect, useState } from "react";
import { getHealth, getRun, getRuns } from "./api";
import type { Health, Run, RunDetail as RunDetailData } from "./types";
import Catalogue from "./components/Catalogue";
import Dashboard from "./components/Dashboard";
import FindingsView from "./components/FindingsView";
import RunsView from "./components/RunsView";
import SettingsView from "./components/SettingsView";
import Sidebar from "./components/Sidebar";
import type { ViewId } from "./components/Sidebar";

const POLL_MS = 3000;

const TITLES: Record<ViewId, string> = {
  overview: "Overview",
  runs: "Runs",
  catalogue: "Check Catalogue",
  findings: "Findings",
  settings: "Settings",
};

function viewFromHash(): ViewId {
  const name = window.location.hash.replace("#", "");
  return name in TITLES ? (name as ViewId) : "overview";
}

export default function App() {
  const [view, setView] = useState<ViewId>(viewFromHash);
  const [health, setHealth] = useState<Health | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<RunDetailData | null>(null);
  const [error, setError] = useState("");

  function openView(next: ViewId) {
    // the hash keeps the view in the url, so a page can be linked to directly
    window.location.hash = next;
    setView(next);
  }

  useEffect(() => {
    const sync = () => setView(viewFromHash());
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setError("the backend is not answering on /api, start it with uvicorn backend.app:app"));
    // the run list is small, polling it keeps the sidebar counts and the progress text current
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

  const findingCount = runs.reduce((sum, run) => sum + (run.finding_count ?? 0), 0);

  return (
    <div className="shell">
      <Sidebar view={view} onSelect={openView} counts={{ runs: runs.length, findings: findingCount }} />

      <div className="main">
        <header className="topbar">
          <div className="crumb">
            <span>lab</span>
            <span className="crumb-sep">/</span>
            <strong>{TITLES[view]}</strong>
          </div>
          <div className="topbar-actions">
            {health && <span className="chip">{health.allowed_targets[0] ?? "no target configured"}</span>}
            {health && (
              <span className="chip">{health.mock_agent ? "mock agent" : `model ${health.model}`}</span>
            )}
            {runs.some((run) => run.status === "running") && <span className="chip live">run in progress</span>}
          </div>
        </header>

        <main className="content">
          {error && <p className="error">{error}</p>}

          {view === "overview" && <Dashboard health={health} onOpenRuns={() => openView("runs")} />}
          {view === "runs" && (
            <RunsView
              health={health}
              runs={runs}
              detail={detail}
              selectedId={selectedId}
              onSelect={setSelectedId}
            />
          )}
          {view === "catalogue" && <Catalogue />}
          {view === "findings" && <FindingsView />}
          {view === "settings" && <SettingsView health={health} />}
        </main>
      </div>
    </div>
  );
}
