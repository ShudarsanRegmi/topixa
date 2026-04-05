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
    <main className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Topixa</p>
          <h1>Network Intelligence Workbench</h1>
        </div>
        <button className="reload-btn" type="button" onClick={loadMvpData}>
          Reload Snapshot
        </button>
      </header>

      {error ? <p className="error-banner">{error}</p> : null}

      <section className="workspace-grid">
        <aside className="panel panel-left">
          <h2>Scanner Readiness</h2>
          <ul className="scanner-list">
            {scanners.map((scanner) => (
              <li key={scanner.name} className={scanner.available ? "status-up" : "status-down"}>
                <span>{scanner.name}</span>
                <strong>{scanner.available ? "Detected" : "Missing"}</strong>
              </li>
            ))}
          </ul>

          <h2>Service Filter</h2>
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

        <section className="panel panel-canvas">
          <div className="canvas-header">
            <h2>Topology View</h2>
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

        <aside className="panel panel-right">
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

      <footer className="statusline">
        {snapshot ? `Generated at ${snapshot.generated_at}` : "Waiting for initial snapshot..."}
      </footer>
    </main>
  );
}

export default App;
