import { useState } from "react";
import type { FormEvent } from "react";
import { startRun } from "../api";
import type { Health } from "../types";

type Props = {
  health: Health | null;
  onStarted: (runId: number) => void;
};

export default function NewRunForm({ health, onStarted }: Props) {
  const [target, setTarget] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const { run_id } = await startRun(target, notes);
      setNotes("");
      onStarted(run_id);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : String(problem));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit}>
      <h2>new run</h2>
      <label htmlFor="target">target</label>
      <input
        id="target"
        value={target}
        onChange={(event) => setTarget(event.target.value)}
        placeholder={health?.allowed_targets[0] ?? "http://localhost:3000"}
        required
      />
      <p className="hint">
        the target has to match ALLOWED_TARGETS exactly: {health?.allowed_targets.join(", ") || "none configured"}
      </p>

      <label htmlFor="notes">notes</label>
      <input
        id="notes"
        value={notes}
        onChange={(event) => setNotes(event.target.value)}
        placeholder="optional, stored with the run"
      />

      {health && !health.has_api_key && !health.mock_agent && (
        <p className="warning">
          no DEEPSEEK_API_KEY is set, so this run will fail when the checks are planned. set the key in .env or start
          the backend with MOCK_AGENT=1.
        </p>
      )}
      {error && <p className="error">{error}</p>}

      <button type="submit" disabled={busy}>
        {busy ? "starting" : "start run"}
      </button>
    </form>
  );
}
