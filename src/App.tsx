import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type ScannerStatus = {
  name: string;
  available: boolean;
};

type HostNode = {
  id: string;
  ip: string;
  label: string;
  subnet: string;
  os_family: string;
  services: string[];
  risk_score: number;
  x: number;
  y: number;
};

type HostEdge = {
  source: string;
  target: string;
  relation: string;
};

type TopologySnapshot = {
  scan_id: string;
  generated_at: string;
  nodes: HostNode[];
  edges: HostEdge[];
};

const VIEWPORT_WIDTH = 980;
const VIEWPORT_HEIGHT = 620;

function App() {
  const [snapshot, setSnapshot] = useState<TopologySnapshot | null>(null);
  const [scanners, setScanners] = useState<ScannerStatus[]>([]);
  const [selectedService, setSelectedService] = useState<string>("all");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [activeRibbonTab, setActiveRibbonTab] = useState<"home" | "scan" | "view" | "intel">(
    "home",
  );
  const [error, setError] = useState<string | null>(null);

  async function loadMvpData() {
    setError(null);

    try {
      const [statusResult, snapshotResult] = await Promise.all([
        invoke<ScannerStatus[]>("get_scanner_status"),
        invoke<TopologySnapshot>("load_sample_topology"),
      ]);

      setScanners(statusResult);
      setSnapshot(snapshotResult);

      if (snapshotResult.nodes.length > 0) {
        setSelectedNodeId(snapshotResult.nodes[0].id);
      }
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : String(requestError);
      setError(`Unable to load Topixa data: ${message}`);
    }
  }

  useEffect(() => {
    loadMvpData();
  }, []);

  const visibleNodes = useMemo(() => {
    if (!snapshot) {
      return [];
    }

    if (selectedService === "all") {
      return snapshot.nodes;
    }

    return snapshot.nodes.filter((node) => node.services.includes(selectedService));
  }, [snapshot, selectedService]);

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);

  const visibleEdges = useMemo(() => {
    if (!snapshot) {
      return [];
    }

    return snapshot.edges.filter(
      (edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target),
    );
  }, [snapshot, visibleNodeIds]);

  const selectedNode = useMemo(
    () => visibleNodes.find((node) => node.id === selectedNodeId) ?? visibleNodes[0],
    [visibleNodes, selectedNodeId],
  );

  const serviceOptions = useMemo(() => {
    const services = new Set<string>();
    snapshot?.nodes.forEach((node) => {
      node.services.forEach((service) => services.add(service));
    });
    return ["all", ...Array.from(services.values()).sort()];
  }, [snapshot]);

  return (
    <main className="desktop-root">
      <header className="menubar">
        <div className="app-identity">
          <strong>Topixa</strong>
          <span>Network Intelligence</span>
        </div>
        <nav className="menu-items" aria-label="Application menu">
          <button type="button" className="menu-btn">File</button>
          <button type="button" className="menu-btn">Edit</button>
          <button type="button" className="menu-btn">Scan</button>
          <button type="button" className="menu-btn">View</button>
          <button type="button" className="menu-btn">Tools</button>
          <button type="button" className="menu-btn">Help</button>
        </nav>
      </header>

      <section className="ribbon-tabs" aria-label="Ribbon tabs">
        <button
          type="button"
          className={activeRibbonTab === "home" ? "ribbon-tab active" : "ribbon-tab"}
          onClick={() => setActiveRibbonTab("home")}
        >
          Home
        </button>
        <button
          type="button"
          className={activeRibbonTab === "scan" ? "ribbon-tab active" : "ribbon-tab"}
          onClick={() => setActiveRibbonTab("scan")}
        >
          Scan
        </button>
        <button
          type="button"
          className={activeRibbonTab === "view" ? "ribbon-tab active" : "ribbon-tab"}
          onClick={() => setActiveRibbonTab("view")}
        >
          View
        </button>
        <button
          type="button"
          className={activeRibbonTab === "intel" ? "ribbon-tab active" : "ribbon-tab"}
          onClick={() => setActiveRibbonTab("intel")}
        >
          Intelligence
        </button>
      </section>

      <section className="ribbon-panel" aria-label="Ribbon actions">
        <div className="ribbon-group">
          <p className="ribbon-title">Session</p>
          <div className="ribbon-actions">
            <button className="ribbon-action primary" type="button" onClick={loadMvpData}>
              Refresh Snapshot
            </button>
            <button className="ribbon-action" type="button">Open Scan</button>
            <button className="ribbon-action" type="button">Export JSON</button>
          </div>
        </div>
        <div className="ribbon-group">
          <p className="ribbon-title">Filter</p>
          <div className="ribbon-actions">
            {serviceOptions.slice(0, 5).map((option) => (
              <button
                key={`quick-${option}`}
                type="button"
                className={option === selectedService ? "ribbon-action active" : "ribbon-action"}
                onClick={() => setSelectedService(option)}
              >
                {option}
              </button>
            ))}
          </div>
        </div>
        <div className="ribbon-group compact">
          <p className="ribbon-title">Workspace</p>
          <div className="ribbon-actions">
            <button className="ribbon-action" type="button">Graph</button>
            <button className="ribbon-action" type="button">Table</button>
            <button className="ribbon-action" type="button">Timeline</button>
          </div>
        </div>
      </section>

      {error ? <p className="error-banner">{error}</p> : null}

      <section className="workspace-layout">
        <aside className="left-pane">
          <p className="pane-caption">Navigator</p>
          <ul className="module-list">
            <li className="module-item active">Topology</li>
            <li className="module-item">Assets</li>
            <li className="module-item">Services</li>
            <li className="module-item">Alerts</li>
            <li className="module-item">Timeline</li>
          </ul>

          <p className="pane-caption">Scanners</p>
          <ul className="scanner-list">
            {scanners.map((scanner) => (
              <li key={scanner.name} className={scanner.available ? "status-up" : "status-down"}>
                <span>{scanner.name}</span>
                <strong>{scanner.available ? "Detected" : "Missing"}</strong>
              </li>
            ))}
          </ul>

          <p className="pane-caption">Service Filter</p>
          <div className="service-filter-grid">
            {serviceOptions.map((option) => (
              <button
                key={option}
                type="button"
                className={option === selectedService ? "service-chip active" : "service-chip"}
                onClick={() => setSelectedService(option)}
              >
                {option}
              </button>
            ))}
          </div>
        </aside>

        <section className="center-pane">
          <div className="toolstrip">
            <div>
              <p className="pane-caption">Workspace</p>
              <p className="toolbar-title">Network Topology Graph</p>
            </div>
            <p>
              {visibleNodes.length} hosts · {visibleEdges.length} links · {snapshot?.scan_id ?? "no scan"}
            </p>
          </div>

          <div className="topology-canvas">
            <svg viewBox={`0 0 ${VIEWPORT_WIDTH} ${VIEWPORT_HEIGHT}`} className="edge-layer" role="img">
              <title>Network edges</title>
              {visibleEdges.map((edge) => {
                const sourceNode = visibleNodes.find((node) => node.id === edge.source);
                const targetNode = visibleNodes.find((node) => node.id === edge.target);
                if (!sourceNode || !targetNode) {
                  return null;
                }

                return (
                  <line
                    key={`${edge.source}-${edge.target}`}
                    x1={sourceNode.x}
                    y1={sourceNode.y}
                    x2={targetNode.x}
                    y2={targetNode.y}
                    className="network-edge"
                  />
                );
              })}
            </svg>

            {visibleNodes.map((node) => (
              <button
                key={node.id}
                type="button"
                className={selectedNode?.id === node.id ? "host-node selected" : "host-node"}
                style={{ left: `${node.x}px`, top: `${node.y}px` }}
                onClick={() => setSelectedNodeId(node.id)}
              >
                <span className="host-ip">{node.ip}</span>
                <span className="host-label">{node.label}</span>
              </button>
            ))}
          </div>
        </section>

        <aside className="right-pane">
          <p className="pane-caption">Inspector</p>
          <h2>Host Intelligence</h2>
          {selectedNode ? (
            <div className="intel-stack">
              <p>
                <strong>{selectedNode.label}</strong>
              </p>
              <p>Address: {selectedNode.ip}</p>
              <p>Subnet: {selectedNode.subnet}</p>
              <p>OS Family: {selectedNode.os_family}</p>
              <p>Risk Score: {selectedNode.risk_score}/100</p>
              <div>
                <h3>Observed Services</h3>
                <ul>
                  {selectedNode.services.map((service) => (
                    <li key={`${selectedNode.id}-${service}`}>{service}</li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <p>No host selected.</p>
          )}

          <h2>Roadmap Stub</h2>
          <ol>
            <li>Nmap XML ingest command</li>
            <li>Service enrichment pipeline</li>
            <li>Cytoscape.js-powered graph interactions</li>
          </ol>
        </aside>
      </section>

      <footer className="statusbar">
        <span>{snapshot ? `Generated at ${snapshot.generated_at}` : "Waiting for initial snapshot..."}</span>
        <span>{selectedNode ? `Selected: ${selectedNode.ip}` : "Selected: none"}</span>
      </footer>
    </main>
  );
}

export default App;
