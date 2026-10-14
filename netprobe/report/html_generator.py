import json
import time
from typing import List, Dict, Any
from netprobe.scenarios.base import TestResult


class HTMLReportGenerator:
    """Generates an offline, interactive, polished HTML report."""

    @staticmethod
    def generate(results: List[TestResult], summary: Dict[str, Any], output_path: str = "netprobe_report.html") -> str:
        results_json = json.dumps([r.to_dict() for r in results])
        gen_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetProbe Network Protocol Test Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-green: #4ade80;
            --accent-red: #f87171;
            --accent-yellow: #fbbf24;
            --accent-purple: #c084fc;
            --border-color: #475569;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }}
        body {{ background-color: var(--bg-primary); color: var(--text-main); padding: 24px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        
        /* Header */
        header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border-color); padding-bottom: 16px; margin-bottom: 24px; }}
        h1 {{ font-size: 26px; font-weight: 700; color: var(--accent-blue); display: flex; align-items: center; gap: 10px; }}
        .meta {{ font-size: 13px; color: var(--text-muted); text-align: right; }}

        /* KPI Cards */
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 28px; }}
        .card {{ background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 10px; padding: 18px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }}
        .card-label {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
        .card-value {{ font-size: 28px; font-weight: 700; }}
        .val-blue {{ color: var(--accent-blue); }}
        .val-green {{ color: var(--accent-green); }}
        .val-red {{ color: var(--accent-red); }}
        .val-yellow {{ color: var(--accent-yellow); }}
        .val-purple {{ color: var(--accent-purple); }}

        /* Controls */
        .controls {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; align-items: center; background: var(--bg-secondary); padding: 14px; border-radius: 8px; border: 1px solid var(--border-color); }}
        input[type="text"], select {{ background: var(--bg-primary); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 14px; border-radius: 6px; font-size: 14px; outline: none; }}
        input[type="text"]:focus, select:focus {{ border-color: var(--accent-blue); }}
        .search-box {{ flex: 1; min-width: 250px; }}

        /* Table */
        .table-container {{ overflow-x: auto; background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border-color); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2); }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 13.5px; }}
        th {{ background: #182234; padding: 12px 16px; font-weight: 600; color: var(--accent-blue); border-bottom: 1px solid var(--border-color); white-space: nowrap; }}
        td {{ padding: 12px 16px; border-bottom: 1px solid rgba(71, 85, 105, 0.4); vertical-align: middle; }}
        tr:hover {{ background-color: rgba(51, 65, 85, 0.4); }}
        
        /* Badges */
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .badge-tcp {{ background: rgba(56, 189, 248, 0.15); color: var(--accent-blue); border: 1px solid var(--accent-blue); }}
        .badge-tls {{ background: rgba(192, 132, 252, 0.15); color: var(--accent-purple); border: 1px solid var(--accent-purple); }}
        .badge-combo {{ background: rgba(251, 191, 36, 0.15); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
        
        .badge-success {{ background: rgba(74, 222, 128, 0.15); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .badge-rst {{ background: rgba(248, 113, 113, 0.15); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge-exhausted {{ background: rgba(251, 191, 36, 0.15); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
        .badge-timeout {{ background: rgba(148, 163, 184, 0.15); color: var(--text-muted); border: 1px solid var(--text-muted); }}

        .code-pill {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: var(--bg-primary); padding: 2px 6px; border-radius: 4px; font-size: 12px; border: 1px solid var(--border-color); }}
        .dir-tag {{ font-weight: 600; color: #38bdf8; }}
        .rtt-val {{ font-weight: 700; color: #38bdf8; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>NetProbe Protocol Test Report</h1>
                <p style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">Low-level TCP/TLS Bit & Byte Anomaly Evaluation Dashboard</p>
            </div>
            <div class="meta">
                <div>Generated: <strong>{gen_time}</strong></div>
                <div>Engine: <strong>NetProbe User-Space Stack</strong></div>
            </div>
        </header>

        <section class="kpi-grid">
            <div class="card">
                <div class="card-label">Total Test Scenarios</div>
                <div class="card-value val-blue">{summary.get("total", 0)}</div>
            </div>
            <div class="card">
                <div class="card-label">Response Received (Success)</div>
                <div class="card-value val-green">{summary.get("success", 0)}</div>
            </div>
            <div class="card">
                <div class="card-label">Rejected with RST</div>
                <div class="card-value val-red">{summary.get("rejected_rst", 0)}</div>
            </div>
            <div class="card">
                <div class="card-label">Retries Exhausted (Max 4)</div>
                <div class="card-value val-yellow">{summary.get("retry_exhausted", 0)}</div>
            </div>
            <div class="card">
                <div class="card-label">Avg Latency (RTT)</div>
                <div class="card-value val-purple">{summary.get("avg_rtt_ms", 0.0)} <span style="font-size: 16px;">ms</span></div>
            </div>
        </section>

        <div class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Search scenarios, field names, or values..." onkeyup="filterTable()">
            <select id="catFilter" onchange="filterTable()">
                <option value="ALL">All Categories</option>
                <option value="TCP">TCP Fields</option>
                <option value="TLS">TLS Records</option>
                <option value="COMBO">Combined TCP+TLS</option>
            </select>
            <select id="dirFilter" onchange="filterTable()">
                <option value="ALL">All Directions</option>
                <option value="Client -> Server">Client -> Server</option>
                <option value="Server -> Client">Server -> Client</option>
            </select>
            <select id="statusFilter" onchange="filterTable()">
                <option value="ALL">All Statuses</option>
                <option value="SUCCESS">SUCCESS</option>
                <option value="REJECTED_RST">REJECTED_RST</option>
                <option value="RETRY_EXHAUSTED">RETRY_EXHAUSTED</option>
            </select>
        </div>

        <div class="table-container">
            <table id="resultsTable">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Category</th>
                        <th>Scenario Name</th>
                        <th>Field Tested</th>
                        <th>Original Value</th>
                        <th>Mutated / Injected Value</th>
                        <th>Direction</th>
                        <th>Attempts</th>
                        <th>RTT (ms)</th>
                        <th>Peer Status</th>
                        <th>Response Details</th>
                    </tr>
                </thead>
                <tbody id="tableBody"></tbody>
            </table>
        </div>
    </div>

    <script>
        const rawData = {results_json};

        function renderRows(items) {{
            const tbody = document.getElementById("tableBody");
            tbody.innerHTML = "";

            items.forEach(r => {{
                let catClass = "badge-tcp";
                if (r.category === "TLS") catClass = "badge-tls";
                if (r.category === "COMBO") catClass = "badge-combo";

                let statusClass = "badge-success";
                if (r.response_status === "REJECTED_RST") statusClass = "badge-rst";
                else if (r.response_status === "RETRY_EXHAUSTED") statusClass = "badge-exhausted";
                else if (r.response_status !== "SUCCESS") statusClass = "badge-timeout";

                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td><strong>${{r.scenario_id}}</strong></td>
                    <td><span class="badge ${{catClass}}">${{r.category}}</span></td>
                    <td><strong>${{r.name}}</strong></td>
                    <td>${{r.field_tested}}</td>
                    <td><span class="code-pill">${{r.original_val}}</span></td>
                    <td><span class="code-pill" style="color: #fbbf24;">${{r.mutated_val}}</span></td>
                    <td><span class="dir-tag">${{r.direction}}</span></td>
                    <td style="text-align: center;"><strong>${{r.attempts_used}}</strong> / 4</td>
                    <td><span class="rtt-val">${{r.rtt_ms.toFixed(2)}} ms</span></td>
                    <td><span class="badge ${{statusClass}}">${{r.response_status}}</span></td>
                    <td style="color: var(--text-muted);">${{r.details}}</td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function filterTable() {{
            const query = document.getElementById("searchInput").value.toLowerCase();
            const cat = document.getElementById("catFilter").value;
            const dir = document.getElementById("dirFilter").value;
            const status = document.getElementById("statusFilter").value;

            const filtered = rawData.filter(r => {{
                const matchesSearch = r.name.toLowerCase().includes(query) ||
                                      r.field_tested.toLowerCase().includes(query) ||
                                      r.mutated_val.toLowerCase().includes(query) ||
                                      r.scenario_id.toLowerCase().includes(query);
                const matchesCat = (cat === "ALL" || r.category === cat);
                const matchesDir = (dir === "ALL" || r.direction === dir);
                const matchesStatus = (status === "ALL" || r.response_status === status);
                return matchesSearch && matchesCat && matchesDir && matchesStatus;
            }});

            renderRows(filtered);
        }}

        // Initial render
        renderRows(rawData);
    </script>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path
