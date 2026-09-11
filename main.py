from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
import sqlite3
import json
import uvicorn
import os
from scanner import collect_full_posture, contain_process
from report_generator import build_pdf_report

app = FastAPI(title="VulnScout Unified Posture & EDR Platform", version="4.0.0")

def init_db():
    with sqlite3.connect("scans.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

init_db()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VulnScout | Autonomous AppSec Posture & EDR</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
    </style>
</head>
<body class="bg-[#080c14] text-slate-200 min-h-screen flex flex-col selection:bg-indigo-500 selection:text-white">

    <!-- Top Navigation Bar -->
    <header class="border-b border-slate-800/80 bg-[#0d1322]/80 backdrop-blur sticky top-0 z-50">
        <div class="max-w-[1680px] mx-auto px-6 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="h-9 w-9 rounded-lg bg-gradient-to-tr from-indigo-500 via-sky-500 to-emerald-400 p-[1px] flex items-center justify-center shadow-lg shadow-indigo-500/10">
                    <div class="w-full h-full bg-[#080c14] rounded-lg flex items-center justify-center font-mono font-black text-white text-sm">
                        VS
                    </div>
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <span class="font-extrabold text-white text-base tracking-tight">VulnScout</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">Unified ASPM + EDR</span>
                    </div>
                    <p class="text-[11px] text-slate-400">Autonomous Exposure Management & Remediation Platform</p>
                </div>
            </div>

            <div class="flex items-center gap-3">
                <a href="/api/report/pdf" download class="flex items-center gap-2 text-xs font-mono bg-indigo-600 hover:bg-indigo-500 text-white px-3.5 py-1.5 rounded-lg shadow-md transition font-medium">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    Export Audit PDF
                </a>
                <button onclick="syncAll()" class="text-xs font-mono bg-slate-800/80 hover:bg-slate-700 text-slate-200 px-3.5 py-1.5 rounded-lg border border-slate-700 transition">
                    Sync Intelligence
                </button>
            </div>
        </div>
    </header>

    <!-- Main Content Container -->
    <main class="max-w-[1680px] mx-auto px-6 py-6 flex-1 w-full space-y-6">

        <!-- Top Posture Metric Cards -->
        <section class="grid grid-cols-1 md:grid-cols-4 gap-4">
            
            <div class="bg-[#0f172a]/70 border border-slate-800 p-5 rounded-2xl shadow-sm">
                <span class="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Host Attack Posture</span>
                <div class="flex items-baseline gap-2 mt-2">
                    <span id="riskScore" class="text-4xl font-extrabold font-mono text-white">0</span>
                    <span class="text-xs font-mono text-slate-500">/ 100</span>
                </div>
                <span id="riskVerdict" class="text-[11px] font-mono text-emerald-400 mt-1 block">CALCULATING POSTURE...</span>
            </div>

            <div class="bg-[#0f172a]/70 border border-rose-950/40 p-5 rounded-2xl shadow-sm">
                <span class="text-[11px] font-mono text-rose-400 uppercase tracking-wider">High EPSS Exploits (>40%)</span>
                <div id="epssCount" class="text-4xl font-extrabold font-mono text-rose-500 mt-2">0</div>
                <span class="text-[11px] font-mono text-slate-500 mt-1 block">Active Weaponized Threat Probability</span>
            </div>

            <div class="bg-[#0f172a]/70 border border-indigo-950/40 p-5 rounded-2xl shadow-sm">
                <span class="text-[11px] font-mono text-indigo-400 uppercase tracking-wider">SCA Package Backlog</span>
                <div id="sbomCount" class="text-4xl font-extrabold font-mono text-indigo-400 mt-2">0</div>
                <span class="text-[11px] font-mono text-slate-500 mt-1 block">Tracked Open Source Vulnerabilities</span>
            </div>

            <div class="bg-[#0f172a]/70 border border-slate-800 p-5 rounded-2xl shadow-sm">
                <span class="text-[11px] font-mono text-cyan-400 uppercase tracking-wider">Microservice & Daemons</span>
                <div id="surfaceCount" class="text-4xl font-extrabold font-mono text-cyan-400 mt-2">0</div>
                <span class="text-[11px] font-mono text-slate-500 mt-1 block">Listening Sockets + Containers</span>
            </div>
        </section>

        <!-- Dynamic Remediation Feedback Banner -->
        <div id="actionBanner" class="hidden p-4 rounded-xl text-xs font-mono border"></div>

        <!-- Pillar 1: Software Composition Analysis (SCA) & EPSS Exploits -->
        <section class="bg-[#0f172a]/70 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div class="px-6 py-4 border-b border-slate-800 bg-[#0d1322]/60 flex justify-between items-center">
                <div>
                    <h2 class="text-sm font-bold text-white uppercase tracking-wider">Software Composition Analysis (SCA) & EPSS Matrix</h2>
                    <p class="text-xs text-slate-400">Prioritizing real-world exploit likelihood over raw CVSS scores</p>
                </div>
                <span class="text-xs font-mono text-indigo-400 bg-indigo-950/50 px-2.5 py-1 rounded border border-indigo-500/20">Live OSV.dev Feed</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left font-mono text-xs">
                    <thead>
                        <tr class="border-b border-slate-800 text-slate-400 bg-slate-900/30 text-[11px] uppercase">
                            <th class="py-3 px-6">Vulnerability ID</th>
                            <th class="py-3 px-6">Affected Package</th>
                            <th class="py-3 px-6">Severity (CVSS)</th>
                            <th class="py-3 px-6">EPSS Probability</th>
                            <th class="py-3 px-6">Remediation SLA</th>
                            <th class="py-3 px-6 text-right">Lifecycle</th>
                        </tr>
                    </thead>
                    <tbody id="sbomTableBody" class="divide-y divide-slate-800/60">
                        <tr><td colspan="6" class="p-6 text-center text-slate-500">Syncing dependency graph...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Pillar 2: Container Security & Runtime Exposure -->
        <section class="bg-[#0f172a]/70 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div class="px-6 py-4 border-b border-slate-800 bg-[#0d1322]/60 flex justify-between items-center">
                <div>
                    <h2 class="text-sm font-bold text-white uppercase tracking-wider">Container Infrastructure & Microservice Posture</h2>
                    <p class="text-xs text-slate-400">Inspecting image layers, container ports, and root execution privileges</p>
                </div>
                <span class="text-xs font-mono text-slate-400">Docker Runtime Daemon</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left font-mono text-xs">
                    <thead>
                        <tr class="border-b border-slate-800 text-slate-400 bg-slate-900/30 text-[11px] uppercase">
                            <th class="py-3 px-6">Container ID</th>
                            <th class="py-3 px-6">Service Name</th>
                            <th class="py-3 px-6">Image Digest</th>
                            <th class="py-3 px-6">Bound Host Ports</th>
                            <th class="py-3 px-6">Privilege Boundary</th>
                            <th class="py-3 px-6 text-right">Status</th>
                        </tr>
                    </thead>
                    <tbody id="containerTableBody" class="divide-y divide-slate-800/60">
                        <tr><td colspan="6" class="p-6 text-center text-slate-500">Auditing container sockets...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Pillar 3: Endpoint Detection & Threat Hunting Matrix (With Freeze/Kill Containment) -->
        <section class="bg-[#0f172a]/70 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div class="px-6 py-4 border-b border-slate-800 bg-[#0d1322]/60 flex justify-between items-center">
                <div>
                    <h2 class="text-sm font-bold text-white uppercase tracking-wider">Host Attack Surface & MITRE ATT&CK Mapping</h2>
                    <p class="text-xs text-slate-400">Direct socket-to-process correlation with forensic freeze capabilities</p>
                </div>
                <span class="text-xs font-mono text-emerald-400">EDR Agent Active</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left font-mono text-xs">
                    <thead>
                        <tr class="border-b border-slate-800 text-slate-400 bg-slate-900/30 text-[11px] uppercase">
                            <th class="py-3 px-6">Port / Protocol</th>
                            <th class="py-3 px-6">Process Name</th>
                            <th class="py-3 px-6">PID</th>
                            <th class="py-3 px-6">MITRE Technique</th>
                            <th class="py-3 px-6 text-right">Containment Actions</th>
                        </tr>
                    </thead>
                    <tbody id="socketTableBody" class="divide-y divide-slate-800/60">
                        <tr><td colspan="5" class="p-6 text-center text-slate-500">Enumerating listening sockets...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>

    </main>

    <script>
        async function syncAll() {
            try {
                const res = await fetch('/api/posture');
                const data = await res.json();

                // Metric Cards
                document.getElementById('riskScore').textContent = data.exposure_score;
                document.getElementById('surfaceCount').textContent = data.sockets.length + data.containers.length;
                document.getElementById('sbomCount').textContent = data.sbom_vulns.length;

                let epssElevated = data.sbom_vulns.filter(v => v.epss_raw > 0.4).length;
                document.getElementById('epssCount').textContent = epssElevated;

                const verdict = document.getElementById('riskVerdict');
                if (data.exposure_score >= 50) {
                    verdict.textContent = "CRITICAL EXPOSURE DETECTED";
                    verdict.className = "text-[11px] font-mono text-rose-400 mt-1 block font-bold";
                } else {
                    verdict.textContent = "ACCEPTABLE POSTURE LEVEL";
                    verdict.className = "text-[11px] font-mono text-emerald-400 mt-1 block";
                }

                // Render SBOM Table
                document.getElementById('sbomTableBody').innerHTML = data.sbom_vulns.length ? data.sbom_vulns.map(v => `
                    <tr class="hover:bg-slate-800/20">
                        <td class="py-3 px-6 font-bold text-white">${v.cve_id}</td>
                        <td class="py-3 px-6 text-slate-300">${v.package}</td>
                        <td class="py-3 px-6">
                            <span class="px-2 py-0.5 rounded text-[10px] border ${v.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'} font-bold">
                                ${v.severity} (${v.cvss})
                            </span>
                        </td>
                        <td class="py-3 px-6 font-bold ${v.epss_raw > 0.4 ? 'text-rose-400' : 'text-slate-300'}">${v.epss}</td>
                        <td class="py-3 px-6 text-slate-400">${v.sla_deadline}</td>
                        <td class="py-3 px-6 text-right">
                            <span class="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Active</span>
                        </td>
                    </tr>
                `).join('') : '<tr><td colspan="6" class="p-6 text-center text-slate-500">No active package vulnerabilities detected.</td></tr>';

                // Render Containers Table
                document.getElementById('containerTableBody').innerHTML = data.containers.map(c => `
                    <tr class="hover:bg-slate-800/20">
                        <td class="py-3 px-6 font-bold text-slate-300">${c.id}</td>
                        <td class="py-3 px-6 font-semibold text-white">${c.name}</td>
                        <td class="py-3 px-6 text-slate-400">${c.image}</td>
                        <td class="py-3 px-6 text-cyan-400 font-mono">${c.ports}</td>
                        <td class="py-3 px-6">
                            <span class="px-2 py-0.5 rounded text-[10px] border ${c.root_risk === 'ROOT' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'} font-bold">
                                ${c.root_risk} PRIVILEGE
                            </span>
                        </td>
                        <td class="py-3 px-6 text-right text-slate-400">${c.status}</td>
                    </tr>
                `).join('');

                // Render Sockets / Processes Table
                document.getElementById('socketTableBody').innerHTML = data.sockets.map(s => `
                    <tr class="hover:bg-slate-800/20">
                        <td class="py-3 px-6 font-bold text-white">${s.port} / ${s.protocol}</td>
                        <td class="py-3 px-6 text-slate-200 font-semibold">${s.process_name}</td>
                        <td class="py-3 px-6 text-slate-400">${s.pid}</td>
                        <td class="py-3 px-6">
                            <span class="text-xs text-indigo-400 bg-indigo-950/40 px-2 py-0.5 rounded border border-indigo-500/20">
                                ${s.mitre.technique}: ${s.mitre.name}
                            </span>
                        </td>
                        <td class="py-3 px-6 text-right space-x-2">
                            ${s.pid > 1 ? `
                                <button onclick="remediate(${s.pid}, 'freeze')" class="bg-amber-600/80 hover:bg-amber-600 text-white px-2.5 py-1 rounded text-[11px] transition">
                                    Freeze (SIGSTOP)
                                </button>
                                <button onclick="remediate(${s.pid}, 'kill')" class="bg-rose-600/80 hover:bg-rose-600 text-white px-2.5 py-1 rounded text-[11px] transition">
                                    Kill (SIGTERM)
                                </button>
                            ` : '<span class="text-slate-600">Protected Kernel PID</span>'}
                        </td>
                    </tr>
                `).join('');

            } catch (err) {
                console.error("Telemetry failed:", err);
            }
        }

        async function remediate(pid, action) {
            const res = await fetch(`/api/contain?pid=${pid}&action=${action}`, { method: 'POST' });
            const result = await res.json();
            const banner = document.getElementById('actionBanner');
            banner.classList.remove('hidden');

            if (result.success) {
                banner.className = "p-3 rounded-xl text-xs font-mono bg-emerald-950/60 border border-emerald-500/40 text-emerald-300";
                banner.textContent = `[CONTAINMENT SUCCESS] ${result.message}`;
            } else {
                banner.className = "p-3 rounded-xl text-xs font-mono bg-rose-950/60 border border-rose-500/40 text-rose-300";
                banner.textContent = `[CONTAINMENT FAILED] ${result.error}`;
            }

            setTimeout(() => banner.classList.add('hidden'), 5000);
            syncAll();
        }

        syncAll();
        setInterval(syncAll, 8000);
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return DASHBOARD_HTML

@app.get("/api/posture")
def get_posture_feed():
    return collect_full_posture()

@app.post("/api/contain")
def execute_containment(pid: int, action: str = "kill"):
    result = contain_process(pid, action)
    with sqlite3.connect("scans.db") as conn:
        conn.execute(
            "INSERT INTO audit_logs (action, details) VALUES (?, ?)",
            (f"{action.upper()}_PID_{pid}", json.dumps(result))
        )
    return result

@app.get("/api/report/pdf")
def download_audit_report():
    data = collect_full_posture()
    filepath = "audit_report.pdf"
    build_pdf_report(data, filepath)
    return FileResponse(filepath, filename="VulnScout_Posture_Audit.pdf", media_type="application/pdf")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
