import type { Health, Run, RunDetail as RunDetailData } from "../types";
import NewRunForm from "./NewRunForm";
import RunDetail from "./RunDetail";
import RunList from "./RunList";

type Props = {
  health: Health | null;
  runs: Run[];
  detail: RunDetailData | null;
  selectedId: number | null;
  onSelect: (runId: number) => void;
};

export default function RunsView({ health, runs, detail, selectedId, onSelect }: Props) {
  return (
    <div className="split">
      <div className="column">
        <NewRunForm health={health} onStarted={onSelect} />
        <RunList runs={runs} selectedId={selectedId} onSelect={onSelect} />
      </div>
      <div className="column">
        {detail ? (
          <RunDetail detail={detail} />
        ) : (
          <section className="card">
            <h3>run detail</h3>
            <p className="hint">pick a run on the left, or start a new one.</p>
          </section>
        )}
      </div>
    </div>
  );
}
