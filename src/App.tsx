import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

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
  result_id?: string | null;
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
type RibbonMenu = "file" | "settings" | "help" | null;

function formatStamp(value?: string | null) {
  if (!value) {
    return "—";
  }

  const asNumber = Number(value);
  const millis = Number.isFinite(asNumber)
    ? (asNumber < 10_000_000_000 ? asNumber * 1000 : asNumber)
    : Date.parse(value);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleDateString();
}

function toTimestampMillis(value?: string | null) {
  if (!value) {
    return 0;
  }

  const asNumber = Number(value);
  if (Number.isFinite(asNumber)) {
    return asNumber < 10_000_000_000 ? asNumber * 1000 : asNumber;
  }

  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function jobTagClass(status: string) {
  switch (status) {
    case "completed":
      return "job-tag completed";
    case "running":
      return "job-tag running";
    case "failed":
      return "job-tag failed";
    case "queued":
      return "job-tag queued";
    default:
      return "job-tag";
  }
}

function hostTagClass(state: string) {
  switch (state) {
    case "open":
      return "tag open";
    case "closed":
      return "tag closed";
    case "filtered":
      return "tag filtered";
    default:
      return "tag";
  }
}

function Icon({ name }: { name: "panelOpen" | "panelClose" | "plus" | "close" | "chevronDown" }) {
  if (name === "panelOpen") {
    return (
      <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
        <rect x="3" y="4" width="18" height="16" rx="2" fill="none" stroke="currentColor" strokeWidth="1.7" />
        <line x1="9" y1="4" x2="9" y2="20" stroke="currentColor" strokeWidth="1.7" />
        <polyline points="14,9 17,12 14,15" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  if (name === "panelClose") {
    return (
      <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
        <rect x="3" y="4" width="18" height="16" rx="2" fill="none" stroke="currentColor" strokeWidth="1.7" />
        <line x1="9" y1="4" x2="9" y2="20" stroke="currentColor" strokeWidth="1.7" />
        <polyline points="18,9 15,12 18,15" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  if (name === "plus") {
    return (
      <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
        <line x1="12" y1="5" x2="12" y2="19" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
        <line x1="5" y1="12" x2="19" y2="12" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
      </svg>
    );
  }

  if (name === "chevronDown") {
    return (
      <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
        <polyline points="6,9 12,15 18,9" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
      <line x1="6" y1="6" x2="18" y2="18" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
      <line x1="18" y1="6" x2="6" y2="18" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
    </svg>
  );
}

function App() {
  const [mode, setMode] = useState<AppMode>("launcher");
  const [operations, setOperations] = useState<OperationSummary[]>([]);
  const [templates, setTemplates] = useState<ScanTemplate[]>([]);
  const [activeOperation, setActiveOperation] = useState<Operation | null>(null);
  const [activeScanJobId, setActiveScanJobId] = useState<string | null>(null);
  const [scanResultsByJobId, setScanResultsByJobId] = useState<Record<string, ScanExecutionResult>>({});
  const [scanLoadStateByJobId, setScanLoadStateByJobId] = useState<
    Record<string, "idle" | "loading" | "loaded" | "failed">
  >({});
  const [selectedHostAddress, setSelectedHostAddress] = useState<string | null>(null);
  const [scanTarget, setScanTarget] = useState("");
  const [scanTemplateId, setScanTemplateId] = useState("");
  const [customFlags, setCustomFlags] = useState("");
  const [newOperationName, setNewOperationName] = useState("");
  const [newOperationDescription, setNewOperationDescription] = useState("");
  const [newOperationScope, setNewOperationScope] = useState("192.168.1.0/24");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showScanConfigDialog, setShowScanConfigDialog] = useState(false);
  const [showHelpDialog, setShowHelpDialog] = useState(false);
  const [ribbonMenu, setRibbonMenu] = useState<RibbonMenu>(null);
  const [leftDrawerOpen, setLeftDrawerOpen] = useState(true);
  const [isBusy, setIsBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refreshBootstrapData() {
    try {
      setError(null);
      const [templateResult, operationResult] = await Promise.all([
        invoke<ScanTemplate[]>("list_scan_templates"),
        invoke<OperationSummary[]>("list_operations"),
      ]);

      setTemplates(templateResult);
      setOperations(operationResult);

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

  const targetSuggestions = useMemo(() => {
    const values = operations.map((operation) => operation.target_scope).filter(Boolean);
    return Array.from(new Set(values)).slice(0, 8);
  }, [operations]);

  const operationJobs = useMemo(() => {
    const jobs = activeOperation?.scan_jobs ?? [];
    return [...jobs].sort((a, b) => toTimestampMillis(a.created_at) - toTimestampMillis(b.created_at));
  }, [activeOperation]);

  const activeScanResult = activeScanJobId ? scanResultsByJobId[activeScanJobId] ?? null : null;
  const activeScanLoadState = activeScanJobId ? scanLoadStateByJobId[activeScanJobId] ?? "idle" : "idle";

  const selectedHost = useMemo(() => {
    if (!activeScanResult || !selectedHostAddress) {
      return null;
    }

    return activeScanResult.hosts.find((host) => host.address === selectedHostAddress) ?? null;
  }, [activeScanResult, selectedHostAddress]);

  const scanCommandPreview = useMemo(() => {
    if (!selectedTemplate) {
      return "nmap";
    }

    const flags = customFlags.trim() || selectedTemplate.nmap_flags;
    const target = scanTarget.trim() || activeOperation?.target_scope || "<target>";
    return `nmap ${flags} -oX - ${target}`;
  }, [selectedTemplate, customFlags, scanTarget, activeOperation]);

  const graphNodes = useMemo(() => {
    const hosts = activeScanResult?.hosts ?? [];
    const centerX = 360;
    const centerY = 215;
    const radius = hosts.length <= 1 ? 0 : Math.min(170, 110 + hosts.length * 12);

    return hosts.map((host, index) => {
      if (hosts.length === 1) {
        return {
          host,
          x: centerX,
          y: 105,
        };
      }

      const angle = (index / hosts.length) * Math.PI * 2 - Math.PI / 2;
      return {
        host,
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      };
    });
  }, [activeScanResult]);

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
      setScanResultsByJobId({});
      setScanLoadStateByJobId({});
      setSelectedHostAddress(null);
      setShowCreateDialog(false);
      setShowScanConfigDialog(false);
      setShowHelpDialog(false);
      setRibbonMenu(null);
      setLeftDrawerOpen(true);

      const completedJobs = [...operation.scan_jobs]
        .filter((job) => job.status === "completed")
        .sort((a, b) => toTimestampMillis(b.finished_at) - toTimestampMillis(a.finished_at));

      // Try jobs that explicitly reference persisted payloads first.
      completedJobs.sort((a, b) => {
        const aHas = a.result_id ? 1 : 0;
        const bHas = b.result_id ? 1 : 0;
        return bHas - aHas;
      });

      let initialScanJobId: string | null = operation.scan_jobs[0]?.id ?? null;
      const recoveredResults: Record<string, ScanExecutionResult> = {};
      const recoveredStates: Record<string, "idle" | "loading" | "loaded" | "failed"> = {};

      for (const job of completedJobs) {
        try {
          const result = await invoke<ScanExecutionResult>("get_scan_result", { job_id: job.id });
          recoveredResults[job.id] = result;
          recoveredStates[job.id] = "loaded";
          initialScanJobId = job.id;
          break;
        } catch {
          recoveredStates[job.id] = "failed";
          // Keep trying older completed scans.
        }
      }

      setScanResultsByJobId(recoveredResults);
      setScanLoadStateByJobId(recoveredStates);
      setActiveScanJobId(initialScanJobId);

      if (completedJobs.length > 0 && Object.keys(recoveredResults).length === 0) {
        setError("This operation has completed scans, but saved result payloads were not found. Run a new scan to regenerate graph data.");
      }

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
      setActiveScanJobId(null);
      setScanResultsByJobId({});
      setScanLoadStateByJobId({});
      setSelectedHostAddress(null);
      setNewOperationName("");
      setNewOperationDescription("");
      setShowCreateDialog(false);
      setShowScanConfigDialog(false);
      setShowHelpDialog(false);
      setRibbonMenu(null);
      setLeftDrawerOpen(true);
      await refreshOperations();
      setMode("workspace");
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : String(requestError);
      setError(`Unable to create operation: ${message}`);
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

      setScanResultsByJobId((current) => ({ ...current, [result.scan_id]: result }));
      setScanLoadStateByJobId((current) => ({ ...current, [result.scan_id]: "loaded" }));
      setActiveScanJobId(result.scan_id);
      setSelectedHostAddress(null);
      setShowScanConfigDialog(false);

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

  useEffect(() => {
    if (!activeOperation || !activeScanJobId) {
      return;
    }

    if (scanResultsByJobId[activeScanJobId]) {
      return;
    }

    const currentLoadState = scanLoadStateByJobId[activeScanJobId] ?? "idle";
    if (currentLoadState === "loading" || currentLoadState === "failed") {
      return;
    }

    const job = activeOperation.scan_jobs.find((entry) => entry.id === activeScanJobId);
    if (!job || job.status !== "completed") {
      return;
    }

    let cancelled = false;
    setScanLoadStateByJobId((current) => ({ ...current, [activeScanJobId]: "loading" }));

    invoke<ScanExecutionResult>("get_scan_result", { job_id: activeScanJobId })
      .then((result) => {
        if (cancelled) {
          return;
        }

        setScanLoadStateByJobId((current) => ({ ...current, [activeScanJobId]: "loaded" }));
        setScanResultsByJobId((current) => ({ ...current, [activeScanJobId]: result }));
      })
      .catch(() => {
        if (!cancelled) {
          setScanLoadStateByJobId((current) => ({ ...current, [activeScanJobId]: "failed" }));
          setError("Unable to load saved graph payload for this scan.");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [activeOperation, activeScanJobId, scanLoadStateByJobId, scanResultsByJobId]);

  useEffect(() => {
    if (!activeOperation || !activeScanJobId) {
      return;
    }

    if (activeScanLoadState !== "failed") {
      return;
    }

    const fallbackJobs = [...activeOperation.scan_jobs]
      .filter((job) => job.status === "completed" && job.id !== activeScanJobId)
      .sort((a, b) => toTimestampMillis(b.finished_at) - toTimestampMillis(a.finished_at));

    const loadedCandidate = fallbackJobs.find((job) => scanLoadStateByJobId[job.id] === "loaded" || !!scanResultsByJobId[job.id]);
    const retriableCandidate = fallbackJobs.find((job) => scanLoadStateByJobId[job.id] !== "failed");
    const nextCandidate = loadedCandidate ?? retriableCandidate;

    if (!nextCandidate) {
      return;
    }

    setActiveScanJobId(nextCandidate.id);
    setError("Selected scan had no saved payload. Switched to the next available completed scan.");
  }, [activeOperation, activeScanJobId, activeScanLoadState, scanLoadStateByJobId, scanResultsByJobId]);

  function renderLauncher() {
    return (
      <section className="launcher-view">
        <div className="launcher-frame">
          <div className="launcher-center">
            <div className="launcher-logo">
              <strong>TX</strong>
              <span>Topixa</span>
            </div>
            <button type="button" className="launcher-new-button" onClick={() => setShowCreateDialog(true)}>
              +
            </button>
            <div className="launcher-new-label">Create New Operation</div>
          </div>

          <aside className="launcher-recent">
            <h3>Recent Operations</h3>
            <div className="launcher-list">
              {operations.length === 0 ? (
                <div className="empty-state">No operations yet.</div>
              ) : (
                operations.map((operation) => (
                  <div className="recent-row" key={operation.id}>
                    <div>
                      <strong>{operation.name}</strong>
                      <div className="muted-line">{operation.target_scope}</div>
                      <div className="muted-line">{operation.scan_count} scans · updated {formatStamp(operation.updated_at)}</div>
                    </div>
                    <button type="button" className="secondary" onClick={() => openOperation(operation.id)} disabled={isBusy}>
                      Open
                    </button>
                  </div>
                ))
              )}
            </div>
          </aside>
        </div>
      </section>
    );
  }

  function renderGraph() {
    if (!activeScanResult) {
      return (
        <div className="graph-empty">
          <strong>No scan selected.</strong>
          <p>Open a completed scan tab to view the graph.</p>
        </div>
      );
    }

    const hosts = activeScanResult.hosts;

    if (hosts.length === 0) {
      return (
        <div className="graph-empty">
          <strong>No hosts discovered.</strong>
          <p>This scan did not return host nodes.</p>
        </div>
      );
    }

    return (
      <svg viewBox="0 0 720 430" className="host-graph" role="img" aria-label="Host graph visualization">
        <circle className="graph-center" cx="360" cy="215" r="34" />
        <text className="graph-center-label" x="360" y="212">
          {activeScanResult.target}
        </text>
        <text className="graph-center-sub" x="360" y="230">
          {activeScanResult.summary.hosts_up} up · {activeScanResult.summary.open_ports} open
        </text>

        {graphNodes.map(({ host, x, y }) => {
          const isSelected = selectedHostAddress === host.address;
          const openPorts = host.ports.filter((port) => port.state === "open").length;
          const hostLabel = host.hostname || host.address;

          return (
            <g
              key={host.address}
              className="host-node"
              onClick={() => setSelectedHostAddress(host.address)}
              role="button"
              tabIndex={0}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  setSelectedHostAddress(host.address);
                }
              }}
            >
              <line x1="360" y1="215" x2={x} y2={y} className="graph-link" />
              <circle className={isSelected ? "graph-host active" : "graph-host"} cx={x} cy={y} r="34" />
              <text className="graph-host-label" x={x} y={y - 2}>
                {hostLabel}
              </text>
              <text className="graph-host-sub" x={x} y={y + 13}>
                {openPorts} open ports
              </text>
            </g>
          );
        })}
      </svg>
    );
  }

  function renderWorkspace() {
    const workspaceClass = [
      "workspace-frame",
      leftDrawerOpen ? "drawer-open" : "drawer-collapsed",
      selectedHost ? "host-open" : "host-closed",
    ].join(" ");

    return (
      <section className="workspace-view">
        <header className="workspace-ribbon">
          <div className="ribbon-menu-row">
            <div className="ribbon-menu-wrap">
              <button type="button" className="ribbon-menu-btn" onClick={() => setRibbonMenu((m) => (m === "file" ? null : "file"))}>
                File <Icon name="chevronDown" />
              </button>
              {ribbonMenu === "file" ? (
                <div className="ribbon-submenu">
                  <button type="button" onClick={() => { setShowCreateDialog(true); setRibbonMenu(null); }}>New Operation</button>
                  <button type="button" onClick={() => { setMode("launcher"); setSelectedHostAddress(null); setRibbonMenu(null); }}>Open Operations</button>
                  <button type="button" onClick={() => { refreshBootstrapData(); setRibbonMenu(null); }}>Refresh Data</button>
                </div>
              ) : null}
            </div>

            <div className="ribbon-menu-wrap">
              <button type="button" className="ribbon-menu-btn" onClick={() => setRibbonMenu((m) => (m === "settings" ? null : "settings"))}>
                Settings <Icon name="chevronDown" />
              </button>
              {ribbonMenu === "settings" ? (
                <div className="ribbon-submenu">
                  <button type="button" onClick={() => { setShowScanConfigDialog(true); setRibbonMenu(null); }}>New Scan</button>
                  <button type="button" onClick={() => { setLeftDrawerOpen((v) => !v); setRibbonMenu(null); }}>
                    {leftDrawerOpen ? "Collapse Left Drawer" : "Expand Left Drawer"}
                  </button>
                  <button type="button" onClick={() => { setSelectedHostAddress(null); setRibbonMenu(null); }}>Clear Host Selection</button>
                </div>
              ) : null}
            </div>

            <div className="ribbon-menu-wrap">
              <button type="button" className="ribbon-menu-btn" onClick={() => setRibbonMenu((m) => (m === "help" ? null : "help"))}>
                Help <Icon name="chevronDown" />
              </button>
              {ribbonMenu === "help" ? (
                <div className="ribbon-submenu">
                  <button type="button" onClick={() => { setShowHelpDialog(true); setRibbonMenu(null); }}>About Topixa</button>
                  <button type="button" onClick={() => { setShowHelpDialog(true); setRibbonMenu(null); }}>Keyboard Shortcuts</button>
                </div>
              ) : null}
            </div>
          </div>

          <div className="ribbon-context">
            <strong>{activeOperation?.name || "Operation"}</strong>
            <span>{activeOperation?.target_scope || "No target scope"}</span>
          </div>
        </header>

        <div className={workspaceClass}>
          <aside className={leftDrawerOpen ? "drawer left-drawer" : "drawer left-drawer compact"}>
            <div className="left-drawer-toolbar">
              <button
                type="button"
                className="icon-btn"
                onClick={() => setLeftDrawerOpen((current) => !current)}
                aria-label={leftDrawerOpen ? "Collapse left drawer" : "Expand left drawer"}
              >
                <Icon name={leftDrawerOpen ? "panelClose" : "panelOpen"} />
              </button>
              <button
                type="button"
                className="icon-btn"
                onClick={() => setShowScanConfigDialog(true)}
                aria-label="Open scan configuration"
              >
                <Icon name="plus" />
              </button>
            </div>

            {leftDrawerOpen ? (
              <>
                <div className="drawer-title">Scans</div>
                <div className="scan-list">
                  {operationJobs.length === 0 ? (
                    <div className="empty-state">No scans yet.</div>
                  ) : (
                    operationJobs.map((job, index) => {
                      const label = `scan${index + 1}`;
                      const isActive = job.id === activeScanJobId;

                      return (
                        <button
                          key={job.id}
                          type="button"
                          className={isActive ? "scan-item active" : "scan-item"}
                          onClick={() => {
                            if (scanLoadStateByJobId[job.id] === "failed") {
                              setScanLoadStateByJobId((current) => ({ ...current, [job.id]: "idle" }));
                            }
                            setActiveScanJobId(job.id);
                            setSelectedHostAddress(null);
                          }}
                        >
                          <div className="scan-item-header">
                            <strong>{label}</strong>
                            <span className={jobTagClass(job.status)}>{job.status}</span>
                          </div>
                          <div className="scan-item-meta">{job.profile_name}</div>
                          <div className="scan-item-meta">{job.target}</div>
                          <div className="scan-item-meta">{formatStamp(job.created_at)}</div>
                        </button>
                      );
                    })
                  )}
                </div>
              </>
            ) : null}
          </aside>

          <section className="center-panel">
            <div className="center-subtitle">
              <span>Workspace · Graph View</span>
              <span>{activeOperation?.name || "Open an operation"}</span>
            </div>

            <div className="scan-tabs" aria-label="Scan tabs">
              {operationJobs.length === 0 ? (
                <div className="empty-state small">No chart tabs yet.</div>
              ) : (
                operationJobs.map((job, index) => {
                  const isActive = job.id === activeScanJobId;
                  return (
                    <button
                      key={job.id}
                      type="button"
                      className={isActive ? "scan-tab active" : "scan-tab"}
                      onClick={() => {
                        if (scanLoadStateByJobId[job.id] === "failed") {
                          setScanLoadStateByJobId((current) => ({ ...current, [job.id]: "idle" }));
                        }
                        setActiveScanJobId(job.id);
                        setSelectedHostAddress(null);
                      }}
                    >
                      scan{index + 1}
                    </button>
                  );
                })
              )}
            </div>

            <div className="graph-card">
              {activeScanJobId &&
              !activeScanResult &&
              operationJobs.some((job) => job.id === activeScanJobId && job.status === "completed") &&
              activeScanLoadState === "loading" ? (
                <div className="graph-empty">
                  <strong>Loading scan graph…</strong>
                  <p>Fetching the saved result for this scan.</p>
                </div>
              ) : activeScanJobId &&
                !activeScanResult &&
                operationJobs.some((job) => job.id === activeScanJobId && job.status === "completed") &&
                activeScanLoadState === "failed" ? (
                <div className="graph-empty">
                  <strong>Saved payload missing for this scan tab.</strong>
                  <p>This usually happens on legacy scans created before payload persistence. Select another tab or run a new scan.</p>
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => {
                      if (!activeScanJobId) {
                        return;
                      }
                      setScanLoadStateByJobId((current) => ({ ...current, [activeScanJobId]: "idle" }));
                    }}
                  >
                    Retry Load
                  </button>
                </div>
              ) : (
                renderGraph()
              )}
            </div>
          </section>

          <aside className={selectedHost ? "drawer right-drawer open" : "drawer right-drawer"}>
            {selectedHost ? (
              <>
                <div className="right-drawer-header">
                  <div className="drawer-title">Host Details</div>
                  <button
                    type="button"
                    className="icon-btn"
                    onClick={() => setSelectedHostAddress(null)}
                    aria-label="Close host details"
                  >
                    <Icon name="close" />
                  </button>
                </div>

                <div className="host-detail-card">
                  <div className="host-detail-summary">
                    <strong>{selectedHost.address}</strong>
                    <div>{selectedHost.hostname || "No hostname discovered"}</div>
                    <span className={hostTagClass(selectedHost.state)}>{selectedHost.state}</span>
                    <div className="muted-line">{selectedHost.ports.length} discovered ports</div>
                  </div>

                  <div className="host-port-list">
                    {selectedHost.ports.length === 0 ? (
                      <div className="empty-state">No ports discovered for this host.</div>
                    ) : (
                      selectedHost.ports.map((port) => (
                        <div className="host-port-item" key={`${selectedHost.address}-${port.protocol}-${port.port}`}>
                          <div>
                            <strong>
                              {port.port}/{port.protocol}
                            </strong>
                            <div className="muted-line">{port.service || "unknown service"}</div>
                          </div>
                          <span className={hostTagClass(port.state)}>{port.state}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </>
            ) : null}
          </aside>
        </div>

        {showScanConfigDialog ? (
          <div className="create-modal-overlay" role="dialog" aria-modal="true">
            <div className="create-modal scan-config-modal">
              <div className="scan-config-modal-header">
                <h3>Scan Configuration</h3>
                <button type="button" className="icon-btn" onClick={() => setShowScanConfigDialog(false)}>
                  <Icon name="close" />
                </button>
              </div>

              <label className="scan-target-field">
                <span>Enter hostname/subnet</span>
                <input
                  list="target-suggestions"
                  value={scanTarget}
                  onChange={(event) => setScanTarget(event.currentTarget.value)}
                  placeholder={activeOperation?.target_scope || "192.168.1.0/24"}
                />
                <datalist id="target-suggestions">
                  {targetSuggestions.map((target) => (
                    <option key={target} value={target} />
                  ))}
                </datalist>
              </label>

              <div className="scan-config-row">
                <label>
                  <span>Template</span>
                  <select value={scanTemplateId} onChange={(event) => setScanTemplateId(event.currentTarget.value)}>
                    {templates.map((template) => (
                      <option value={template.id} key={template.id}>
                        {template.name}
                      </option>
                    ))}
                  </select>
                </label>

                <label>
                  <span>Custom flags</span>
                  <input
                    value={customFlags}
                    onChange={(event) => setCustomFlags(event.currentTarget.value)}
                    placeholder="Optional override"
                  />
                </label>
              </div>

              <div className="command-preview">{scanCommandPreview}</div>

              <div className="modal-actions">
                <button type="button" className="secondary" onClick={() => setShowScanConfigDialog(false)}>
                  Cancel
                </button>
                <button type="button" className="primary" onClick={runScan} disabled={isBusy}>
                  Run Scan
                </button>
              </div>
            </div>
          </div>
        ) : null}
      </section>
    );
  }

  return (
    <main className="app-shell">
      {error ? (
        <div className="alert-banner" role="status" aria-live="polite">
          <span>{error}</span>
          <button
            type="button"
            className="alert-close-btn"
            onClick={() => setError(null)}
            aria-label="Dismiss alert"
          >
            <Icon name="close" />
          </button>
        </div>
      ) : null}
      {mode === "launcher" ? renderLauncher() : renderWorkspace()}

      {showCreateDialog ? (
        <div className="create-modal-overlay" role="dialog" aria-modal="true">
          <div className="create-modal">
            <h3>Create Operation</h3>

            <label>
              <span>Operation name</span>
              <input
                value={newOperationName}
                onChange={(event) => setNewOperationName(event.currentTarget.value)}
                placeholder="Internal Sweep"
              />
            </label>

            <label>
              <span>Description</span>
              <textarea
                value={newOperationDescription}
                onChange={(event) => setNewOperationDescription(event.currentTarget.value)}
                rows={3}
                placeholder="Quarterly baseline scan"
              />
            </label>

            <label>
              <span>Target scope</span>
              <input
                value={newOperationScope}
                onChange={(event) => setNewOperationScope(event.currentTarget.value)}
                placeholder="10.10.0.0/16"
              />
            </label>

            <div className="modal-actions">
              <button type="button" className="secondary" onClick={() => setShowCreateDialog(false)}>
                Cancel
              </button>
              <button type="button" className="primary" onClick={createOperation} disabled={isBusy}>
                Create Operation
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {showHelpDialog ? (
        <div className="create-modal-overlay" role="dialog" aria-modal="true">
          <div className="create-modal help-modal">
            <div className="scan-config-modal-header">
              <h3>Topixa Help</h3>
              <button type="button" className="icon-btn" onClick={() => setShowHelpDialog(false)}>
                <Icon name="close" />
              </button>
            </div>

            <div className="help-block">
              <h4>About</h4>
              <p>Topixa is an operation-centric network scanning workspace for organizing scans, graphing hosts, and inspecting service exposure.</p>
            </div>

            <div className="help-block">
              <h4>Keyboard Shortcuts</h4>
              <ul>
                <li><strong>Enter</strong> on a graph node opens host details.</li>
                <li><strong>Arrow / Tab navigation</strong> moves between scan tabs and controls.</li>
                <li><strong>Esc</strong> closes active modal dialogs.</li>
              </ul>
            </div>

            <div className="modal-actions">
              <button type="button" className="secondary" onClick={() => setShowHelpDialog(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </main>
  );
}

export default App;
