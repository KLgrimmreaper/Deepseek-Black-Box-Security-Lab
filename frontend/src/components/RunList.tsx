import type { Run } from "../types";

type Props = {
  runs: Run[];
  selectedId: number | null;
  onSelect: (runId: number) => void;
};

export default function RunList({ runs, selectedId, onSelect }: Props) {
  return (
    <div className="card">
      <h2>runs</h2>
      {runs.length === 0 && <p className="hint">no runs yet</p>}
      <ul className="run-list">
        {runs.map((run) => (
          <li key={run.id}>
            <button
              type="button"
              className={run.id === selectedId ? "run active" : "run"}
              onClick={() => onSelect(run.id)}
            >
              <span className="run-head">
                <strong>#{run.id}</strong>
                <span className={`status ${run.status}`}>{run.status}</span>
              </span>
              <span className="run-target">{run.target}</span>
              <span className="run-meta">
                {run.finding_count ?? 0} finding(s), started {run.started_at}
              </span>
              {run.status === "running" && run.stage && <span className="run-meta">{run.stage}</span>}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
