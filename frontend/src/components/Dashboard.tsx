import { useEffect, useState } from "react";
import { getStats } from "../api";
import { RESULT_COLOR, RESULT_ORDER, SEVERITY_COLOR, SEVERITY_ORDER } from "../theme";
import type { Health, Stats } from "../types";
import { AreaChart, BarList, Donut, StatCard } from "./charts";

type Props = {
  health: Health | null;
  onOpenRuns: () => void;
};

export default function Dashboard({ health, onOpenRuns }: Props) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const load = () =>
      getStats()
        .then((data) => {
          setStats(data);
          setError("");
        })
        .catch((problem: unknown) => setError(problem instanceof Error ? problem.message : String(problem)));
    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, []);

  const totals = stats?.totals;
  const toNumber = (label: string, counters: { label: string; value: number }[] | undefined) =>
    counters?.find((counter) => counter.label === label)?.value ?? 0;

  const severitySegments = SEVERITY_ORDER.map((severity) => ({
    label: severity,
    value: toNumber(severity, stats?.by_severity),
    color: SEVERITY_COLOR[severity],
  })).filter((segment) => segment.value > 0);

  const resultBars = RESULT_ORDER.map((result) => ({
    label: result,
    value: toNumber(result, stats?.by_result),
    color: RESULT_COLOR[result],
  }));
  const resultTotal = resultBars.reduce((sum, bar) => sum + bar.value, 0);

  return (
    <>
      {error && <p className="error">{error}</p>}

      <div className="grid four">
        <StatCard
          label="runs"
          value={totals?.runs ?? 0}
          hint={`${totals?.finished ?? 0} finished, ${totals?.failed ?? 0} failed`}
          accent="#4d7cfe"
        />
        <StatCard
          label="checks executed"
          value={totals?.checks_run ?? 0}
          hint={`${health?.checks ?? 0} in the catalogue`}
          accent="#22d3ee"
        />
        <StatCard
          label="findings"
          value={totals?.findings ?? 0}
          hint={totals?.findings ? "every one has an evidence file" : "nothing recorded yet"}
          accent="#f59e0b"
        />
        <StatCard
          label="requests sent"
          value={totals?.requests ?? 0}
          hint={`budget ${health?.max_requests_per_run ?? 0} per run`}
          accent="#34d399"
        />
      </div>

      <div className="grid two">
        <section className="card">
          <header className="card-head">
            <div>
              <h3>findings by severity</h3>
              <p className="card-sub">severities come from the check catalogue, not from the model</p>
            </div>
            <span className="chip">{totals?.findings ?? 0} total</span>
          </header>
          <div className="donut-wrap">
            <Donut segments={severitySegments} caption="findings" />
            <ul className="legend">
              {SEVERITY_ORDER.map((severity) => (
                <li key={severity}>
                  <span className="legend-dot" style={{ background: SEVERITY_COLOR[severity] }} />
                  <span className="legend-label">{severity}</span>
                  <strong>{toNumber(severity, stats?.by_severity)}</strong>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="card">
          <header className="card-head">
            <div>
              <h3>findings per run</h3>
              <p className="card-sub">one point per run, oldest on the left</p>
            </div>
            <span className="chip">last {stats?.trend.length ?? 0} run(s)</span>
          </header>
          <AreaChart points={stats?.trend ?? []} />
        </section>
      </div>

      <div className="grid two">
        <section className="card">
          <header className="card-head">
            <div>
              <h3>checks that failed most</h3>
              <p className="card-sub">counted over every run in this database</p>
            </div>
          </header>
          <BarList
            items={(stats?.top_failing_checks ?? []).map((item) => ({ ...item, color: "#ef4444" }))}
            emptyText="no failed checks yet"
          />
        </section>

        <section className="card">
          <header className="card-head">
            <div>
              <h3>result distribution</h3>
              <p className="card-sub">every check result across all runs</p>
            </div>
            <span className="chip">{resultTotal} results</span>
          </header>
          <BarList items={resultBars} emptyText="no checks have run yet" />
        </section>
      </div>

      {totals?.runs === 0 && (
        <section className="card">
          <h3>nothing to show yet</h3>
          <p className="hint">
            this dashboard only draws real runs. start one and the cards above fill in.
          </p>
          <button type="button" onClick={onOpenRuns}>
            go to runs
          </button>
        </section>
      )}
    </>
  );
}
