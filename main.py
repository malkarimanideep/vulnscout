from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse
import sqlite3
import json
import uvicorn
from scanner import scan_host, inspect_endpoint_connections, terminate_process

app = FastAPI(title="VulnScout EDR Console", version="2.1.0")

def init_db():
    with sqlite3.connect("scans.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                target_pid INTEGER,
                details TEXT,
                performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

init_db()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VulnScout | Endpoint Threat Console</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-200 min-h-screen p-6 font-sans">
    <div class="max-w-7xl mx-auto space-y-6">
        <header class="flex justify-between items-center border-b border-slate-800 pb-4">
            <div>
                <h1 class="text-2xl font-bold text-white tracking-tight">VulnScout EDR Console</h1>
                <p class="text-xs text-slate-400">Host Telemetry & Real-Time Threat Containment</p>
            </div>
            <button onclick="pollTelemetry()" class="text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded border border-slate-700 transition">
                Refresh Telemetry
            </button>
        </header>

        <section class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <span class="text-xs font-mono text-slate-400">HOST RISK SCORE</span>
                <div id="riskScore" class="text-3xl font-mono font-bold text-emerald-400 mt-1">0</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <span class="text-xs font-mono text-slate-400">ACTIVE SOCKETS</span>
                <div id="activeSockets" class="text-3xl font-mono font-bold text-cyan-400 mt-1">0</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <span class="text-xs font-mono text-slate-400">CPU UTILIZATION</span>
                <div id="cpuLoad" class="text-3xl font-mono font-bold text-slate-200 mt-1">0%</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <span class="text-xs font-mono text-slate-400">RAM FOOTPRINT</span>
                <div id="ramLoad" class="text-3xl font-mono font-bold text-indigo-400 mt-1">0%</div>
            </div>
        </section>

        <div id="actionBanner" class="hidden p-3 rounded-lg text-xs font-mono"></div>

        <section class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
            <div class="px-5 py-3 border-b border-slate-800 font-mono text-xs text-slate-400 flex justify-between items-center">
                <span>ACTIVE LISTENING SOCKETS (PROCESS CORRELATION)</span>
                <span class="text-[10px] text-slate-500">Auto-polling every 5s</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left font-mono text-xs">
                    <thead>
                        <tr class="border-b border-slate-800 bg-slate-950/40 text-slate-500">
                            <th class="p-3">Port</th>
                            <th class="p-3">Bind IP</th>
                            <th class="p-3">Process</th>
                            <th class="p-3">PID</th>
                            <th class="p-3">Security State</th>
                            <th class="p-3 text-right">EDR Action</th>
                        </tr>
                    </thead>
                    <tbody id="socketsTable" class="divide-y divide-slate-800">
                        <tr><td colspan="6" class="p-4 text-center text-slate-500">Polling sockets...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>
    </div>

    <script>
        async function killProcess(pid) {
            if (!confirm(`Are you sure you want to terminate PID ${pid}?`)) return;
            try {
                const res = await fetch(`/api/kill?pid=${pid}`, { method: 'POST' });
                const result = await res.json();
                const banner = document.getElementById('actionBanner');
                banner.classList.remove('hidden');

                if (result.success) {
                    banner.className = "p-3 rounded-lg text-xs font-mono bg-emerald-950/60 border border-emerald-500/40 text-emerald-300";
                    banner.textContent = `[CONTAINMENT SUCCESS] ${result.message}`;
                } else {
                    banner.className = "p-3 rounded-lg text-xs font-mono bg-rose-950/60 border border-rose-500/40 text-rose-300";
                    banner.textContent = `[CONTAINMENT FAILED] ${result.error}`;
                }

                setTimeout(() => banner.classList.add('hidden'), 5000);
                pollTelemetry();
            } catch (err) {
                alert("Failed to communicate with agent.");
            }
        }

        async function pollTelemetry() {
            try {
                const res = await fetch('/api/telemetry');
                const data = await res.json();
                
                document.getElementById('riskScore').textContent = data.exposure_score;
                document.getElementById('activeSockets').textContent = data.listening_sockets.length;
                document.getElementById('cpuLoad').textContent = `${data.telemetry.cpu_usage_pct}%`;
                document.getElementById('ramLoad').textContent = `${data.telemetry.memory_usage_pct}%`;

                const tbody = document.getElementById('socketsTable');
                tbody.innerHTML = data.listening_sockets.map(s => `
                    <tr class="hover:bg-slate-800/40">
                        <td class="p-3 font-bold text-white">${s.port}</td>
                        <td class="p-3 text-slate-400">${s.bound_ip}</td>
                        <td class="p-3 text-slate-200 font-semibold">${s.process_name}</td>
                        <td class="p-3 text-slate-500">${s.pid}</td>
                        <td class="p-3">
                            ${s.threat ? '<span class="text-rose-400 font-bold">FLAGGED</span>' : '<span class="text-emerald-400">NORMAL</span>'}
                        </td>
                        <td class="p-3 text-right">
                            ${s.pid > 1 ? `
                                <button onclick="killProcess(${s.pid})" class="bg-rose-600/80 hover:bg-rose-600 text-white px-2.5 py-1 rounded text-[11px] font-sans font-medium transition">
                                    Terminate PID
                                </button>
                            ` : '<span class="text-slate-600">Protected</span>'}
                        </td>
                    </tr>
                `).join('');
            } catch (err) {
                console.error(err);
            }
        }
        pollTelemetry();
        setInterval(pollTelemetry, 5000);
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return DASHBOARD_HTML

@app.get("/api/telemetry")
def get_telemetry():
    return inspect_endpoint_connections()

@app.post("/api/kill")
def isolate_endpoint(pid: int):
    result = terminate_process(pid)
    with sqlite3.connect("scans.db") as conn:
        conn.execute(
            "INSERT INTO incident_actions (action, target_pid, details) VALUES (?, ?, ?)",
            ("TERMINATE_PROCESS", pid, json.dumps(result))
        )
    return result

@app.get("/reports")
def get_reports():
    with sqlite3.connect("scans.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, target, data, created_at FROM reports ORDER BY id DESC LIMIT 10")
        rows = cur.fetchall()
        return [{"id": r[0], "target": r[1], "data": json.loads(r[2]), "created_at": r[3]} for r in rows]

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
