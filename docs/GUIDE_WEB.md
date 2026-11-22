# Web & Website Integration Guide — NextGen-Anything (`nga`)

## 1. Start the Local Web UI & REST API

```bash
nga ui --host 127.0.0.1 --port 8765

Optional API token protection (recommended on shared machines):
nga ui --host 127.0.0.1 --port 8765 --token YOUR_SECRET_TOKEN
Send X-NGA-Token: YOUR_SECRET_TOKEN or Authorization: Bearer YOUR_SECRET_TOKEN with API requests when a token is configured.
Available endpoints:
GET / — Interactive HTML5 + Vanilla JS dashboard.
GET /api/doctor — Host OS, Python runtime, and CLI tool report.
POST /api/inspect — Inspect local web, har, archive, or binary files ({"kind": "web", "target": "index.html"}).
POST /api/simulate — Run Python code inside the isolated sandbox simulation gate ({"code": "...", "label": "check"}).
POST /api/brief — Generate an architecture blueprint ({"label": "my_app", "kind": "web"}).
GET /api/ledger & POST /api/ledger — Read or record obligations in the coverage ledger.
2. Drop-In Website Widget
Include nga-widget.css and nga-widget.js, then mount #nga-widget:
<link rel="stylesheet" href="./nga/interfaces/web_embed/nga-widget.css" />
<div id="nga-widget" data-nga-endpoint="http://127.0.0.1:8765"></div>
<script src="./nga/interfaces/web_embed/nga-widget.js" defer></script>
3. ES Module SDK Client (sdk/js/nga-client.mjs)
import { NgaJsClient } from "./sdk/js/nga-client.mjs";

const client = new NgaJsClient("http://127.0.0.1:8765");
const doctorReport = await client.doctor();
console.log(doctorReport);
