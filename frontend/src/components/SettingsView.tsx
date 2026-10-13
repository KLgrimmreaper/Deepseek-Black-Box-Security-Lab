import type { Health } from "../types";

type Props = {
  health: Health | null;
};

export default function SettingsView({ health }: Props) {
  return (
    <>
      <section className="card">
        <header className="card-head">
          <div>
            <h3>backend settings</h3>
            <p className="card-sub">read from .env when the backend started. restart uvicorn after changing a value.</p>
          </div>
          <span className={health?.has_api_key ? "chip ok" : "chip warn"}>
            {health?.has_api_key ? "api key loaded" : "no api key"}
          </span>
        </header>

        <dl className="facts">
          <div>
            <dt>allowed targets</dt>
            <dd>{health?.allowed_targets.join(", ") || "none configured"}</dd>
          </div>
          <div>
            <dt>model</dt>
            <dd>{health?.model}</dd>
          </div>
          <div>
            <dt>agent mode</dt>
            <dd>{health?.mock_agent ? "mock agent, no api calls" : "deepseek api"}</dd>
          </div>
          <div>
            <dt>request budget</dt>
            <dd>{health?.max_requests_per_run} per run</dd>
          </div>
          <div>
            <dt>checks in catalogue</dt>
            <dd>{health?.checks}</dd>
          </div>
        </dl>
      </section>

      <section className="card">
        <h3>changing these</h3>
        <p className="hint">
          everything here comes from <code>.env</code> in the project root. the api key is only ever read from the
          environment, and <code>.env</code> is gitignored.
        </p>
        <table>
          <thead>
            <tr>
              <th>key</th>
              <th>meaning</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                <code>ALLOWED_TARGETS</code>
              </td>
              <td>comma separated list of targets a run is allowed to touch. a run refuses anything else.</td>
            </tr>
            <tr>
              <td>
                <code>DEEPSEEK_API_KEY</code>
              </td>
              <td>needed for model planning and write ups. without it a run needs MOCK_AGENT=1 or --only.</td>
            </tr>
            <tr>
              <td>
                <code>DEEPSEEK_MODEL</code>
              </td>
              <td>model name sent to the api, deepseek-chat by default.</td>
            </tr>
            <tr>
              <td>
                <code>MOCK_AGENT</code>
              </td>
              <td>1 skips the api and uses the fallback plan, which is how the pipeline gets tested.</td>
            </tr>
            <tr>
              <td>
                <code>MAX_REQUESTS_PER_RUN</code>
              </td>
              <td>hard cap on requests for one run, counted in scope.py.</td>
            </tr>
            <tr>
              <td>
                <code>REQUEST_DELAY_MS</code>
              </td>
              <td>pause between requests so the target is not hammered.</td>
            </tr>
            <tr>
              <td>
                <code>LOGIN_PATH</code> and <code>SEARCH_PATH</code>
              </td>
              <td>the endpoints the authentication and reflected input checks use.</td>
            </tr>
            <tr>
              <td>
                <code>LAB_CREDENTIALS</code>
              </td>
              <td>email:password pairs for the weak credentials check. defaults to public juice shop demo logins.</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="card">
        <h3>where things are stored</h3>
        <dl className="facts">
          <div>
            <dt>database</dt>
            <dd>
              <code>data/lab.db</code>
            </dd>
          </div>
          <div>
            <dt>evidence</dt>
            <dd>
              <code>evidence/&lt;run id&gt;/&lt;check id&gt;.json</code>
            </dd>
          </div>
          <div>
            <dt>reports</dt>
            <dd>
              <code>reports/run_&lt;id&gt;.md</code>
            </dd>
          </div>
        </dl>
        <p className="hint">all three are gitignored, they are run output rather than source.</p>
      </section>
    </>
  );
}
