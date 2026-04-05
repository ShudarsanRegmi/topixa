# Topixa

Topixa is a native desktop network intelligence workbench built with Tauri.
The long-term goal is to provide service-aware exploration and rich visual pivots on top of scanner output (Nmap, Masscan, RustScan, and more).

## Current MVP

- Native app shell with Tauri v2 + React + TypeScript
- Scanner readiness panel (detects scanner binaries available in your PATH)
- Service filter controls and interactive topology canvas
- Host intelligence side panel fed from Rust backend commands
- Sample graph payload to bootstrap frontend and interaction workflows

## Prerequisites

Linux desktop builds require system packages such as `webkit2gtk` and `librsvg2`.
See: https://tauri.app/guides/prerequisites/#linux

## Run

```bash
npm install
npm run tauri dev
```

If Linux prerequisites are missing, install them first and rerun `npm run tauri dev`.

## Next Build Steps

1. Add `ingest_nmap_xml` Rust command to parse Nmap XML into the graph model.
2. Persist snapshots in SQLite or graph storage and support historical diffs.
3. Add screenshot enrichment pipeline and attach previews to HTTP/HTTPS nodes.
4. Replace custom canvas renderer with Cytoscape.js for dense graph navigation.
