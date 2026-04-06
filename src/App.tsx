import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type ScannerStatus = {
  name: string;
  available: boolean;
};

type ScanTemplate = {
  id: string;
  name: string;
  description: string;
  nmap_flags: string;
  category: string;
};

type ScanJob = {
  id: string;
  target: string;
  profile_id: string;
  profile_name: string;
  nmap_flags: string;
  status: string;
  created_at: string;
  result_summary?: string | null;
  finished_at?: string | null;
};

type OperationSummary = {
  id: string;
  name: string;
  description: string;
  target_scope: string;
  created_at: string;
  updated_at: string;
  scan_count: number;
};

type Operation = {
  id: string;
  name: string;
  description: string;
  target_scope: string;
  created_at: string;
  updated_at: string;
  scan_jobs: ScanJob[];
};

type ScanPortResult = {
  port: number;
  protocol: string;
  state: string;
  service?: string | null;
};

type ScanHostResult = {
  address: string;
  hostname?: string | null;
  state: string;
  ports: ScanPortResult[];
};

type ScanSummary = {
  total_hosts: number;
  hosts_up: number;
  hosts_down: number;
  open_ports: number;
};

type ScanExecutionResult = {
  scan_id: string;
  operation_id: string;
  target: string;
  profile_name: string;
  command: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  summary: ScanSummary;
  hosts: ScanHostResult[];
  stdout: string;
  stderr: string;
};

type AppMode = "launcher" | "workspace";

type LauncherPanel = "none" | "create" | "open";

function App() {
  const [mode, setMode] = useState<AppMode>("launcher");
  const [launcherPanel, setLauncherPanel] = useState<LauncherPanel>("none");
  const [snapshotReady, setSnapshotReady] = useState(false);
  const [scanners, setScanners] = useState<ScannerStatus[]>([]);
  const [templates, setTemplates] = useState<ScanTemplate[]>([]);
  const [operations, setOperations] = useState<OperationSummary[]>([]);
  const [activeOperation, setActiveOperation] = useState<Operation | null>(null);
  const [scanResult, setScanResult] = useState<ScanExecutionResult | null>(null);
  const [scanTarget, setScanTarget] = useState("");
  const [scanTemplateId, setScanTemplateId] = useState("");
  const [customFlags, setCustomFlags] = useState("");
  const [newOperationName, setNewOperationName] = useState("");
  const [newOperationDescription, setNewOperationDescription] = useState("");
  const [newOperationScope, setNewOperationScope] = useState("192.168.1.0/24");
  const [isBusy, setIsBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refreshBootstrapData() {
    try {
      setError(null);
      const [scannerResult, templateResult, operationResult] = await Promise.all([
        invoke<ScannerStatus[]>("get_scanner_status"),
        invoke<ScanTemplate[]>("list_scan_templates"),
        invoke<OperationSummary[]>("list_operations"),
      ]);

      setScanners(scannerResult);
      setTemplates(templateResult);
      setOperations(operationResult);
      setSnapshotReady(true);

      if (!scanTemplateId && templateResult.length > 0) {
        setScanTemplateId(templateResult[0].id);
      }
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : String(requestError);
      setError(`Unable to initialize Topixa: ${message}`);
    }
  }

  useEffect(() => {
    refreshBootstrapData();
  }, []);

  const selectedTemplate = useMemo(
    () => templates.find((template) => template.id === scanTemplateId) ?? null,
    [templates, scanTemplateId],
  );

  const scanCommandPreview = useMemo(() => {
    if (!selectedTemplate) {
      return "nmap";
    }

    const flags = customFlags.trim() || selectedTemplate.nmap_flags;
    const target = scanTarget.trim() || activeOperation?.target_scope || "<target>";
    return `nmap ${flags} -oX - ${target}  (auto-retry with pkexec if root is required)`;
  }, [selectedTemplate, customFlags, scanTarget, activeOperation]);

  async function refreshOperations() {
    const operationResult = await invoke<OperationSummary[]>("list_operations");
    setOperations(operationResult);
  }

  async function openOperation(operationId: string) {
    try {
      setIsBusy(true);
      setError(null);
      const operation = await invoke<Operation>("get_operation", { operationId });
      setActiveOperation(operation);
      setScanTarget(operation.target_scope);
      setScanResult(null);
      setMode("workspace");
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : String(requestError);
      setError(`Unable to open operation: ${message}`);
    } finally {
      setIsBusy(false);
    }
  }

  async function createOperation() {
    if (!newOperationName.trim() || !newOperationScope.trim()) {
      setError("Operation name and target scope are required.");
      return;
    }

    try {
      setIsBusy(true);
      setError(null);

      const operation = await invoke<Operation>("create_operation", {
        input: {
          name: newOperationName.trim(),
          description: newOperationDescription.trim(),
          target_scope: newOperationScope.trim(),
        },
      });

      setActiveOperation(operation);
      setScanTarget(operation.target_scope);
      setScanResult(null);
      setNewOperationName("");
      setNewOperationDescription("");
      await refreshOperations();
      setMode("workspace");
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : String(requestError);
      setError(`Unable to create operation: ${message}`);
    } finally {
      setIsBusy(false);
    }
  }

  async function removeOperation(operationId: string) {
    try {
      setIsBusy(true);
      setError(null);
      await invoke("delete_operation", { operationId });
      await refreshOperations();
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : String(requestError);
      setError(`Unable to delete operation: ${message}`);
    } finally {
      setIsBusy(false);
    }
  }

  async function runScan() {
    if (!activeOperation) {
      setError("Open an operation before starting a scan.");
      return;
    }

    if (!scanTemplateId) {
      setError("Select a scan template.");
      return;
    }

    const target = scanTarget.trim() || activeOperation.target_scope.trim();
    if (!target) {
      setError("Enter a target subnet or host.");
      return;
    }

    try {
      setIsBusy(true);
      setError(null);

      const result = await invoke<ScanExecutionResult>("run_scan", {
        input: {
          operation_id: activeOperation.id,
          target,
          profile_id: scanTemplateId,
          custom_flags: customFlags.trim(),
        },
      });

      setScanResult(result);
      const refreshedOperation = await invoke<Operation>("get_operation", { operationId: activeOperation.id });
      setActiveOperation(refreshedOperation);
      await refreshOperations();
      setMode("workspace");
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : String(requestError);
      setError(`Scan failed: ${message}`);
    } finally {
      setIsBusy(false);
    }
  }

  function renderLauncher() {
    return (
      <section className="launcher-screen">
        <div className="banner-panel">
          <p className="banner-tag">Topixa Operations</p>
          <h2>Operation-Centric Network Mapping</h2>
          <p>Open a case or create a new one. Then run a live scan and inspect the result set.</p>
        </div>

        <div className="launcher-actions">
          <button className="start-tile" type="button" onClick={() => setLauncherPanel("create")}>
            <strong>Create operation</strong>
            <span>Start a fresh case.</span>
          </button>
          <button className="start-tile" type="button" onClick={() => setLauncherPanel("open")}>
            <strong>Open operation</strong>
            <span>Resume a saved case.</span>
          </button>
          <button className="start-tile" type="button" onClick={refreshBootstrapData}>
            <strong>Refresh list</strong>
            <span>Reload operations and scan templates.</span>
          </button>
        </div>

        <div className="launcher-grid">
          {launcherPanel === "create" ? (
            <section className="card create-card">
              <div className="list-header">
                <h3>Create Operation</h3>
                <button type="button" onClick={() => setLauncherPanel("none")}>
                  Close
                </button>
              </div>
              <label>
                <span>Operation Name</span>
                <input
                  value={newOperationName}
                  onChange={(event) => setNewOperationName(event.currentTarget.value)}
                  placeholder="Corporate Internal Sweep"
                />
              </label>
              <label>
                <span>Description</span>
                <textarea
                  value={newOperationDescription}
                  onChange={(event) => setNewOperationDescription(event.currentTarget.value)}
                  rows={3}
                  placeholder="Quarterly attack-surface baseline"
                />
              </label>
              <label>
                <span>Target Scope</span>
                <input
                  value={newOperationScope}
                  onChange={(event) => setNewOperationScope(event.currentTarget.value)}
                  placeholder="10.10.0.0/16"
                />
              </label>
              <button type="button" onClick={createOperation} disabled={isBusy}>
                Create And Open
              </button>
            </section>
          ) : null}

          {launcherPanel === "open" || launcherPanel === "none" ? (
            <section className="card list-card">
              <div className="list-header">
                <h3>Recent Operations</h3>
                <button type="button" onClick={refreshBootstrapData} disabled={isBusy}>
                  Refresh
                </button>
              </div>
              <div className="operation-list">
                {operations.length === 0 ? (
                  <div className="empty-inline">
                    <strong>No operations yet.</strong>
                    <p>Create one to get started.</p>
                  </div>
                ) : (
                  operations.map((operation) => (
                    <article className="operation-row" key={operation.id}>
                      <div>
                        <strong>{operation.name}</strong>
                        <p>{operation.target_scope}</p>
                        <p>{operation.scan_count} scans queued</p>
                      </div>
                      <div className="row-actions">
                        <button type="button" onClick={() => openOperation(operation.id)} disabled={isBusy}>
                          Open
                        </button>
                        <button
                          type="button"
                          className="danger"
                          onClick={() => removeOperation(operation.id)}
                          disabled={isBusy}
                        >
                          Delete
                        </button>
                      </div>
                    </article>
                  ))
                )}
              </div>
            </section>
          ) : null}
        </div>
      </section>
    );
  }

  function renderWorkspace() {
    if (!scanResult) {
      return (
        <section className="workspace-empty-shell">
          <div className="workspace-empty-card">
            <p className="banner-tag">Fresh operation</p>
            <h2>{activeOperation?.name ?? "Operation"}</h2>
            <p className="workspace-empty-copy">
              This case is ready. Choose a template, set a target, and run the first live scan.
            </p>

            <div className="scan-starter-card">
              <div className="scan-composer-compact">
                <label>
                  <span>Target</span>
                  <input
                    value={scanTarget}
                    onChange={(event) => setScanTarget(event.currentTarget.value)}
                    placeholder={activeOperation?.target_scope ?? "192.168.1.0/24"}
                  />
                </label>
                <label>
                  <span>Template</span>
                  <select
                    value={scanTemplateId}
                    onChange={(event) => setScanTemplateId(event.currentTarget.value)}
                  >
                    {templates.map((template) => (
                      <option value={template.id} key={template.id}>
                        {template.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Custom Flags</span>
                  <input
                    value={customFlags}
                    onChange={(event) => setCustomFlags(event.currentTarget.value)}
                    placeholder="Optional override"
                  />
                </label>
                <button type="button" className="primary" onClick={runScan} disabled={isBusy}>
                  Run First Scan
                </button>
              </div>
            </div>
          </div>
        </section>
      );
    }

    return (
      <section className="results-shell">
        <section className="ribbon-tabs" aria-label="Ribbon tabs">
          <button type="button" className="ribbon-tab active">
            Scan
          </button>
          <button type="button" className="ribbon-tab">
            Results
          </button>
          <button type="button" className="ribbon-tab">
            History
          </button>
        </section>

        <section className="ribbon-panel" aria-label="Ribbon actions">
          <div className="ribbon-group wide">
            <p className="ribbon-title">Scan Composer</p>
            <div className="scan-composer-grid">
              <label>
                <span>Target</span>
                <input
                  value={scanTarget}
                  onChange={(event) => setScanTarget(event.currentTarget.value)}
                  placeholder="192.168.1.0/24"
                />
              </label>
              <label>
                <span>Template</span>
                <select
                  value={scanTemplateId}
                  onChange={(event) => setScanTemplateId(event.currentTarget.value)}
                >
                  {templates.map((template) => (
                    <option value={template.id} key={template.id}>
                      {template.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <span>Custom Flags</span>
                <input
                  value={customFlags}
                  onChange={(event) => setCustomFlags(event.currentTarget.value)}
                  placeholder="Optional override"
                />
              </label>
              <button type="button" className="primary" onClick={runScan} disabled={isBusy}>
                Run Scan
              </button>
            </div>
          </div>
          <div className="ribbon-group">
            <p className="ribbon-title">Command Preview</p>
            <code>{scanCommandPreview}</code>
            <p className="template-hint">{selectedTemplate?.description ?? "Select a template"}</p>
          </div>
        </section>

        <section className="workspace-layout">
          <aside className="left-pane">
            <p className="pane-caption">Operation</p>
            <div className="operation-meta">
              <strong>{activeOperation?.name}</strong>
              <p>{activeOperation?.target_scope}</p>
              <p>{activeOperation?.description || "No description"}</p>
            </div>

            <p className="pane-caption">Scanner Availability</p>
            <ul className="scanner-list">
              {scanners.map((scanner) => (
                <li key={scanner.name} className={scanner.available ? "status-up" : "status-down"}>
                  <span>{scanner.name}</span>
                  <strong>{scanner.available ? "Detected" : "Missing"}</strong>
                </li>
              ))}
            </ul>

            <p className="pane-caption">Scan History</p>
            <div className="scan-history">
              {activeOperation?.scan_jobs.length ? (
                activeOperation.scan_jobs
                  .slice()
                  .reverse()
                  .map((job) => (
                    <article key={job.id} className="history-item">
                      <strong>{job.profile_name}</strong>
                      <p>{job.target}</p>
                      <p>{job.status}</p>
                      <p>{job.result_summary ?? "Pending result"}</p>
                    </article>
                  ))
              ) : (
                <div className="empty-inline">
                  <strong>No scan history.</strong>
                  <p>Run the first scan to populate this operation.</p>
                </div>
              )}
            </div>
          </aside>

          <section className="center-pane">
            <div className="toolstrip">
              <div>
                <p className="pane-caption">Live Results</p>
                <p className="toolbar-title">{scanResult.profile_name}</p>
              </div>
              <p>
                {scanResult.summary.total_hosts} hosts · {scanResult.summary.open_ports} open ports · {scanResult.duration_ms} ms
              </p>
            </div>

            <div className="result-summary-grid">
              <div className="metric-card">
                <span>Hosts Up</span>
                <strong>{scanResult.summary.hosts_up}</strong>
              </div>
              <div className="metric-card">
                <span>Hosts Down</span>
                <strong>{scanResult.summary.hosts_down}</strong>
              </div>
              <div className="metric-card">
                <span>Open Ports</span>
                <strong>{scanResult.summary.open_ports}</strong>
              </div>
              <div className="metric-card">
                <span>Duration</span>
                <strong>{scanResult.duration_ms} ms</strong>
              </div>
            </div>

            <div className="result-panels">
              <section className="card result-card">
                <div className="list-header">
                  <h3>Discovered Hosts</h3>
                  <span>{scanResult.hosts.length} entries</span>
                </div>
                <div className="table-wrap">
                  <table className="results-table">
                    <thead>
                      <tr>
                        <th>Address</th>
                        <th>Hostname</th>
                        <th>Status</th>
                        <th>Ports</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanResult.hosts.map((host) => (
                        <tr key={host.address}>
                          <td>{host.address}</td>
                          <td>{host.hostname ?? "-"}</td>
                          <td>{host.state}</td>
                          <td>{host.ports.length}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="card result-card">
                <div className="list-header">
                  <h3>Open Ports</h3>
                  <span>Parsed from XML output</span>
                </div>
                <div className="port-list">
                  {scanResult.hosts.flatMap((host) =>
                    host.ports.map((port) => (
                      <article key={`${host.address}-${port.protocol}-${port.port}`} className="port-row">
                        <div>
                          <strong>{host.address}</strong>
                          <p>{host.hostname ?? "Unknown hostname"}</p>
                        </div>
                        <div>
                          <strong>{port.port}/{port.protocol}</strong>
                          <p>{port.state}</p>
                        </div>
                        <div>
                          <strong>{port.service ?? "unknown"}</strong>
                          <p>service</p>
                        </div>
                      </article>
                    )),
                  )}
                </div>
              </section>
            </div>
          </section>

          <aside className="right-pane">
            <p className="pane-caption">Execution</p>
            <div className="operation-meta">
              <strong>Command</strong>
              <p>{scanResult.command}</p>
              <p>Started: {scanResult.started_at}</p>
              <p>Finished: {scanResult.finished_at}</p>
            </div>

            <p className="pane-caption">Scan Output</p>
            <div className="output-block">
              <strong>STDERR</strong>
              <pre>{scanResult.stderr || "No errors."}</pre>
            </div>
            <div className="output-block">
              <strong>STDOUT</strong>
              <pre>{scanResult.stdout || "No stdout."}</pre>
            </div>
          </aside>
        </section>
      </section>
    );
  }

  return (
    <main className="desktop-root">
      <header className="menubar">
        <div className="app-identity">
          <strong>Topixa</strong>
          <span>{mode === "workspace" ? activeOperation?.name ?? "Operation" : "Operation Launcher"}</span>
        </div>
        <nav className="menu-items" aria-label="Application menu">
          <button type="button" className="menu-btn" onClick={() => setMode("launcher")}>
            Operations
          </button>
          <button type="button" className="menu-btn" onClick={refreshBootstrapData}>
            Refresh
          </button>
        </nav>
      </header>

      {error ? <p className="error-banner">{error}</p> : null}

      {mode === "launcher" ? renderLauncher() : renderWorkspace()}

      <footer className="statusbar">
        <span>{snapshotReady ? "Ready" : "Loading scanner data..."}</span>
        <span>{activeOperation ? `Operation: ${activeOperation.name}` : "No operation opened"}</span>
      </footer>
    </main>
  );
}

export default App;
