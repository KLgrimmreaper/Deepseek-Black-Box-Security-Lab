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

function stateFromHash(): { view: ViewId; runId: number | null } {
  const raw = window.location.hash.replace("#", "");
  const [name, id] = raw.split("/");
  return {
    view: name in TITLES ? (name as ViewId) : "overview",
    runId: id && /^\d+$/.test(id) ? Number(id) : null,
  };
}

export default function App() {
  const initial = stateFromHash();
  const [view, setView] = useState<ViewId>(initial.view);
  const [health, setHealth] = useState<Health | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(initial.runId);
  const [detail, setDetail] = useState<RunDetailData | null>(null);
  const [error, setError] = useState("");

  function openView(next: ViewId) {
    // the hash keeps the view in the url, so a page can be linked to directly
    window.location.hash = next;
    setView(next);
  }

  function selectRun(runId: number) {
    // a single run is linkable too, which makes one worth sharing or screenshotting
    window.location.hash = `runs/${runId}`;
    setView("runs");
    setSelectedId(runId);
  }

  useEffect(() => {
    const sync = () => {
      const next = stateFromHash();
      setView(next.view);
      setSelectedId(next.runId);
    };
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
              onSelect={selectRun}
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
