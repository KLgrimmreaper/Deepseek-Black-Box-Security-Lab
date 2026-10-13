import { useEffect, useState } from "react";
import { getChecks } from "../api";
import type { CatalogueEntry } from "../types";

export default function Catalogue() {
  const [checks, setChecks] = useState<CatalogueEntry[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    getChecks()
      .then((data) => setChecks(data.checks))
      .catch((problem: unknown) => setError(problem instanceof Error ? problem.message : String(problem)));
  }, []);

  return (
    <section className="card">
      <header className="card-head">
        <div>
          <h3>check catalogue</h3>
          <p className="card-sub">
            the model may only ask for ids from this list. unknown ids are dropped before anything runs, and the
            severity of each check is fixed here in code.
          </p>
        </div>
        <span className="chip">{checks.length} checks</span>
      </header>

      {error && <p className="error">{error}</p>}

      <table>
        <thead>
          <tr>
            <th>check</th>
            <th>category</th>
            <th>severity</th>
            <th>what it sends</th>
            <th>if it fails</th>
          </tr>
        </thead>
        <tbody>
          {checks.map((entry) => (
            <tr key={entry.id}>
              <td>
                <code>{entry.id}</code>
                <span className="cell-sub">{entry.name}</span>
              </td>
              <td>{entry.category}</td>
              <td>
                <span className={`badge ${entry.severity}`}>{entry.severity}</span>
              </td>
              <td>{entry.description}</td>
              <td>{entry.fix}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
