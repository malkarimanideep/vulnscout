from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
import sqlite3
import json
import uvicorn
import os
from scanner import collect_full_posture, contain_process
from report_generator import build_pdf_report

app = FastAPI(title="VulnScout Unified Posture & EDR Platform", version="5.0.0")

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
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <title>VulnScout | Enterprise Threat Exposure & EDR</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Space Grotesk', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                    colors: {
                        slate: {
                            950: '#070a12',
                            900: '#0b1120',
                            850: '#10172a',
                            800: '#1e293b'
                        }
                    }
                }
            }
        }
    </script>
    <style>
        /* Smooth radial aura accents */
        .glow-crimson { box-shadow: 0 0 35px -5px rgba(244, 63, 94, 0.15); }
        .glow-indigo { box-shadow: 0 0 35px -5px rgba(99, 102, 241, 0.2); }
        .glass-card {
            background: rgba(15, 23, 42, 0.65);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.06);
        }
        /* Progress Ring Animation */
        circle {
            transition: stroke-dashoffset 0.8s ease-in-out, stroke 0.5s ease;
        }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col font-sans antialiased selection:bg-indigo-500 selection:text-white">

    <!-- Top Navigation -->
    <header class="border-b border-white/5 bg-slate-900/70 backdrop-blur-xl sticky top-0 z-50">
        <div class="max-w-[1720px] mx-auto px-6 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="relative flex items-center justify-center">
                    <div class="h-9 w-9 rounded-xl bg-gradient-to-tr from-indigo-500 via-sky-500 to-rose-500 p-[1.5px] shadow-lg shadow-indigo-500/20">
                        <div class="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center font-mono font-black text-white text-xs">
                            VS
                        </div>
                    </div>
                    <span class="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                        <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                    </span>
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <span class="font-bold text-white text-base tracking-tight">VulnScout</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">Unified CTEM & Forensics</span>
                    </div>
                    <p class="text-[11px] text-slate-400">Continuous Exposure Management & Autonomous Containment</p>
                </div>
            </div>

            <!-- Action Buttons -->
            <div class="flex items-center gap-2.5">
                <button onclick="toggleMitreModal()" class="flex items-center gap-2 text-xs font-mono bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 px-3.5 py-1.5 rounded-lg border border-slate-700/60 transition">
                    <svg class="w-3.5 h-3.5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path></svg>
                    MITRE Matrix
                </button>
                <a href="/api/report/pdf" download class="flex items-center gap-2 text-xs font-mono bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white px-3.5 py-1.5 rounded-lg shadow-md transition font-medium">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    Audit PDF
                </a>
                <button onclick="syncAll()" class="flex items-center gap-1.5 text-xs font-mono bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 px-3.5 py-1.5 rounded-lg border border-slate-700/60 transition">
                    <span id="syncSpinner" class="inline-block">↻</span>
                    Sync
                </button>
            </div>
        </div>
    </header>

    <!-- Main View -->
    <main class="max-w-[1720px] mx-auto px-6 py-6 flex-1 w-full space-y-6">

        <!-- Top Posture & Metrics Cards -->
        <section class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <!-- Radial Exposure Dial Card -->
            <div class="glass-card rounded-2xl p-5 flex items-center justify-between relative overflow-hidden">
                <div>
                    <span class="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">Posture Exposure</span>
                    <div class="flex items-baseline gap-2 mt-1">
                        <span id="riskScore" class="text-3xl font-extrabold font-mono text-white">0</span>
                        <span class="text-xs font-mono text-slate-500">/ 100</span>
                    </div>
                    <span id="riskVerdict" class="text-[10px] font-mono text-emerald-400 mt-1 block font-semibold">ANALYZING...</span>
                </div>
                <div class="relative w-16 h-16 flex items-center justify-center">
                    <svg class="w-16 h-16 transform -rotate-90">
                        <circle cx="32" cy="32" r="26" stroke="currentColor" stroke-width="4" class="text-slate-800" fill="transparent"/>
                        <circle id="riskDial" cx="32" cy="32" r="26" stroke="currentColor" stroke-width="4" class="text-rose-500" fill="transparent" stroke-dasharray="163.36" stroke-dashoffset="163.36" stroke-linecap="round"/>
                    </svg>
                    <span class="absolute text-[10px] font-mono text-slate-300" id="dialPercent">0%</span>
                </div>
            </div>

            <!-- Weaponized Threat Card -->
            <div class="glass-card rounded-2xl p-5 border-l-2 border-l-rose-500">
                <div class="flex justify-between items-start">
                    <span class="text-[11px] font-mono text-rose-400 uppercase tracking-wider">Exploitable (EPSS >40%)</span>
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">Critical SLA</span>
                </div>
                <div id="epssCount" class="text-3xl font-extrabold font-mono text-white mt-1">0</div>
                <span class="text-[11px] text-slate-400 mt-1 block">Weaponized CVE vectors detected</span>
            </div>

            <!-- SCA Dependency Vulnerabilities -->
            <div class="glass-card rounded-2xl p-5 border-l-2 border-l-indigo-500">
                <div class="flex justify-between items-start">
                    <span class="text-[11px] font-mono text-indigo-400 uppercase tracking-wider">SCA Vulnerabilities</span>
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">OSV.dev Sync</span>
                </div>
                <div id="sbomCount" class="text-3xl font-extrabold font-mono text-white mt-1">0</div>
                <span class="text-[11px] text-slate-400 mt-1 block">Dependencies requiring remediation</span>
            </div>

            <!-- Microservices & Daemon Exposure -->
            <div class="glass-card rounded-2xl p-5 border-l-2 border-l-sky-500">
                <div class="flex justify-between items-start">
                    <span class="text-[11px] font-mono text-sky-400 uppercase tracking-wider">Attack Surface</span>
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">Runtime Daemons</span>
                </div>
                <div id="surfaceCount" class="text-3xl font-extrabold font-mono text-white mt-1">0</div>
                <span class="text-[11px] text-slate-400 mt-1 block">Listening ports & containers</span>
            </div>
        </section>

        <!-- Containment Notification Banner -->
        <div id="actionBanner" class="hidden p-3.5 rounded-xl text-xs font-mono border backdrop-blur-md transition-all"></div>

        <!-- Navigation Tabs -->
        <div class="flex items-center justify-between border-b border-white/5 pb-2">
            <div class="flex gap-2">
                <button onclick="switchTab('all')" id="tab-all" class="text-xs font-medium px-4 py-2 rounded-lg bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 transition">
                    Unified Command View
                </button>
                <button onclick="switchTab('sca')" id="tab-sca" class="text-xs font-medium px-4 py-2 rounded-lg bg-slate-900/60 text-slate-400 hover:text-white border border-white/5 transition">
                    SCA & Dependencies
                </button>
                <button onclick="switchTab('containers')" id="tab-containers" class="text-xs font-medium px-4 py-2 rounded-lg bg-slate-900/60 text-slate-400 hover:text-white border border-white/5 transition">
                    Containers & Daemons
                </button>
                <button onclick="switchTab('forensics')" id="tab-forensics" class="text-xs font-medium px-4 py-2 rounded-lg bg-slate-900/60 text-slate-400 hover:text-white border border-white/5 transition">
                    Process Forensics & EDR
                </button>
            </div>
            <div class="flex items-center gap-2">
                <span class="text-[11px] font-mono text-slate-500">Auto-refreshing:</span>
                <span class="text-[11px] font-mono text-emerald-400">8s</span>
            </div>
        </div>

        <!-- Section 1: SCA & Software Composition Analysis -->
        <section id="section-sca" class="glass-card rounded-2xl overflow-hidden shadow-2xl">
            <div class="px-6 py-4 border-b border-white/5 bg-slate-900/40 flex justify-between items-center">
                <div>
                    <h2 class="text-sm font-bold text-white uppercase tracking-wider">Software Composition Analysis & EPSS Threat Prioritization</h2>
                    <p class="text-xs text-slate-400">Continuous vulnerability ledger synchronized with Google / OpenSSF OSV</p>
                </div>
                <div class="flex gap-2">
                    <span class="text-[11px] font-mono px-2.5 py-1 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">PyPI Ecosystem</span>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left font-mono text-xs">
                    <thead>
                        <tr class="border-b border-white/5 text-slate-400 bg-slate-950/40 text-[11px] uppercase">
                            <th class="py-3.5 px-6">Advisory ID</th>
                            <th class="py-3.5 px-6">Package</th>
                            <th class="py-3.5 px-6">Severity (CVSS)</th>
                            <th class="py-3.5 px-6">EPSS Probability</th>
                            <th class="py-3.5 px-6">Remediation SLA</th>
                            <th class="py-3.5 px-6 text-right">Status</th>
                        </tr>
                    </thead>
                    <tbody id="sbomTableBody" class="divide-y divide-white/5">
                        <tr><td colspan="6" class="p-6 text-center text-slate-500">Syncing dependency graph...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Section 2: Containers & Microservice Posture -->
        <section id="section-containers" class="glass-card rounded-2xl overflow-hidden shadow-2xl">
            <div class="px-6 py-4 border-b border-white/5 bg-slate-900/40 flex justify-between items-center">
                <div>
                    <h2 class="text-sm font-bold text-white uppercase tracking-wider">Container Infrastructure & Microservice Posture</h2>
                    <p class="text-xs text-slate-400">Inspecting image layers, bound network interfaces, and root execution boundaries</p>
                </div>
                <span class="text-xs font-mono text-slate-400">Docker Runtime</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left font-mono text-xs">
                    <thead>
                        <tr class="border-b border-white/5 text-slate-400 bg-slate-950/40 text-[11px] uppercase">
                            <th class="py-3.5 px-6">Container ID</th>
                            <th class="py-3.5 px-6">Service Name</th>
                            <th class="py-3.5 px-6">Image Digest</th>
                            <th class="py-3.5 px-6">Bound Host Ports</th>
                            <th class="py-3.5 px-6">Privilege Boundary</th>
                            <th class="py-3.5 px-6 text-right">Status</th>
                        </tr>
                    </thead>
                    <tbody id="containerTableBody" class="divide-y divide-white/5">
                        <tr><td colspan="6" class="p-6 text-center text-slate-500">Auditing container sockets...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Section 3: Process Forensics & Binary Integrity -->
        <section id="section-forensics" class="glass-card rounded-2xl overflow-hidden shadow-2xl">
            <div class="px-6 py-4 border-b border-white/5 bg-slate-900/40 flex justify-between items-center">
                <div>
                    <h2 class="text-sm font-bold text-white uppercase tracking-wider">Endpoint Process Forensics & Binary Integrity</h2>
                    <p class="text-xs text-slate-400">Cryptographic SHA-256 binary validation, PPID trees, and MITRE classification</p>
                </div>
                <span class="text-xs font-mono text-emerald-400">Forensics Telemetry Active</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left font-mono text-xs">
                    <thead>
                        <tr class="border-b border-white/5 text-slate-400 bg-slate-950/40 text-[11px] uppercase">
                            <th class="py-3.5 px-6">Port / Protocol</th>
                            <th class="py-3.5 px-6">Process (PID / PPID)</th>
                            <th class="py-3.5 px-6">SHA-256 Binary Hash</th>
                            <th class="py-3.5 px-6">Integrity Status</th>
                            <th class="py-3.5 px-6">MITRE Classification</th>
                            <th class="py-3.5 px-6 text-right">EDR Action</th>
                        </tr>
                    </thead>
                    <tbody id="socketTableBody" class="divide-y divide-white/5">
                        <tr><td colspan="6" class="p-6 text-center text-slate-500">Enumerating process trees...</td></tr>
                    </tbody>
                </table>
            </div>
        </section>

    </main>

    <!-- MITRE ATT&CK Modal -->
    <div id="mitreModal" class="hidden fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-6">
        <div class="glass-card border border-white/10 rounded-2xl max-w-6xl w-full max-h-[85vh] flex flex-col overflow-hidden shadow-2xl">
            <div class="px-6 py-4 border-b border-white/10 flex justify-between items-center bg-slate-900/60">
                <div>
                    <h3 class="font-bold text-white text-base">MITRE ATT&CK Matrix (Observed Attack Surface)</h3>
                    <p class="text-xs text-slate-400">Active telemetry mapped across standard enterprise tactics</p>
                </div>
                <button onclick="toggleMitreModal()" class="text-slate-400 hover:text-white font-mono text-lg px-2">✕</button>
            </div>
            <div class="p-6 overflow-y-auto flex-1">
                <div id="mitreGrid" class="grid grid-cols-2 md:grid-cols-5 gap-3"></div>
            </div>
        </div>
    </div>

    <script>
        let cachedMitre = {};

        function toggleMitreModal() {
            document.getElementById('mitreModal').classList.toggle('hidden');
        }

        function switchTab(tab) {
            const sections = ['sca', 'containers', 'forensics'];
            const tabs = ['all', 'sca', 'containers', 'forensics'];
            
            tabs.forEach(t => {
                const btn = document.getElementById(`tab-${t}`);
                if (t === tab) {
                    btn.className = "text-xs font-medium px-4 py-2 rounded-lg bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 transition";
                } else {
                    btn.className = "text-xs font-medium px-4 py-2 rounded-lg bg-slate-900/60 text-slate-400 hover:text-white border border-white/5 transition";
                }
            });

            if (tab === 'all') {
                sections.forEach(s => document.getElementById(`section-${s}`).classList.remove('hidden'));
            } else {
                sections.forEach(s => {
                    const el = document.getElementById(`section-${s}`);
                    if (s === tab) el.classList.remove('hidden');
                    else el.classList.add('hidden');
                });
            }
        }

        async function syncAll() {
            const spinner = document.getElementById('syncSpinner');
            spinner.classList.add('animate-spin');

            try {
                const res = await fetch('/api/posture');
                const data = await res.json();
                cachedMitre = data.mitre_matrix;

                // Metric Calculations
                const score = data.exposure_score;
                document.getElementById('riskScore').textContent = score;
                document.getElementById('surfaceCount').textContent = data.sockets.length + data.containers.length;
                document.getElementById('sbomCount').textContent = data.sbom_vulns.length;

                let epssElevated = data.sbom_vulns.filter(v => v.epss_raw > 0.4).length;
                document.getElementById('epssCount').textContent = epssElevated;

                // Animated SVG Dial update
                const circle = document.getElementById('riskDial');
                const circumference = 2 * Math.PI * 26; // ~163.36
                const offset = circumference - (score / 100) * circumference;
                circle.style.strokeDashoffset = offset;
                document.getElementById('dialPercent').textContent = `${score}%`;

                const verdict = document.getElementById('riskVerdict');
                if (score >= 60) {
                    circle.setAttribute('class', 'text-rose-500');
                    verdict.textContent = "CRITICAL EXPOSURE";
                    verdict.className = "text-[10px] font-mono text-rose-400 mt-1 block font-bold";
                } else if (score >= 30) {
                    circle.setAttribute('class', 'text-amber-500');
                    verdict.textContent = "ELEVATED RISK";
                    verdict.className = "text-[10px] font-mono text-amber-400 mt-1 block font-bold";
                } else {
                    circle.setAttribute('class', 'text-emerald-500');
                    verdict.textContent = "ACCEPTABLE POSTURE";
                    verdict.className = "text-[10px] font-mono text-emerald-400 mt-1 block font-bold";
                }

                // Render SBOM Table
                document.getElementById('sbomTableBody').innerHTML = data.sbom_vulns.length ? data.sbom_vulns.map(v => `
                    <tr class="hover:bg-white/[0.02] transition">
                        <td class="py-3.5 px-6 font-bold text-white">${v.cve_id}</td>
                        <td class="py-3.5 px-6 text-slate-300 font-semibold">${v.package}</td>
                        <td class="py-3.5 px-6">
                            <span class="px-2.5 py-1 rounded-md text-[10px] border ${v.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'} font-bold">
                                ${v.severity} (${v.cvss})
                            </span>
                        </td>
                        <td class="py-3.5 px-6 font-bold ${v.epss_raw > 0.4 ? 'text-rose-400' : 'text-slate-300'}">${v.epss}</td>
                        <td class="py-3.5 px-6 text-slate-400">${v.sla_deadline}</td>
                        <td class="py-3.5 px-6 text-right">
                            <span class="text-[10px] px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">Active</span>
                        </td>
                    </tr>
                `).join('') : '<tr><td colspan="6" class="p-6 text-center text-slate-500">No active package vulnerabilities detected.</td></tr>';

                // Render Containers Table
                document.getElementById('containerTableBody').innerHTML = data.containers.map(c => `
                    <tr class="hover:bg-white/[0.02] transition">
                        <td class="py-3.5 px-6 font-bold text-slate-300">${c.id}</td>
                        <td class="py-3.5 px-6 font-semibold text-white">${c.name}</td>
                        <td class="py-3.5 px-6 text-slate-400">${c.image}</td>
                        <td class="py-3.5 px-6 text-sky-400 font-mono">${c.ports}</td>
                        <td class="py-3.5 px-6">
                            <span class="px-2.5 py-1 rounded-md text-[10px] border ${c.root_risk === 'ROOT' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'} font-bold">
                                ${c.root_risk} PRIVILEGE
                            </span>
                        </td>
                        <td class="py-3.5 px-6 text-right text-slate-400">${c.status}</td>
                    </tr>
                `).join('');

                // Render Sockets + Forensics
                document.getElementById('socketTableBody').innerHTML = data.sockets.map(s => `
                    <tr class="hover:bg-white/[0.02] transition">
                        <td class="py-3.5 px-6 font-bold text-white">${s.port} / ${s.protocol}</td>
                        <td class="py-3.5 px-6">
                            <div class="text-slate-200 font-semibold">${s.process_name}</div>
                            <div class="text-[10px] text-slate-500">PID: ${s.pid} | PPID: ${s.ppid}</div>
                        </td>
                        <td class="py-3.5 px-6 text-slate-400 font-mono text-[11px] truncate max-w-xs" title="${s.sha256}">
                            ${s.sha256.length > 20 ? s.sha256.substring(0, 16) + '...' : s.sha256}
                        </td>
                        <td class="py-3.5 px-6">
                            ${s.fileless_risk ? `
                                <span class="text-[10px] px-2.5 py-1 rounded-md bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold animate-pulse">
                                    FILELESS / UNLINKED
                                </span>
                            ` : `
                                <span class="text-[10px] px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                                    VERIFIED DISK
                                </span>
                            `}
                        </td>
                        <td class="py-3.5 px-6">
                            <span class="text-xs text-indigo-400 bg-indigo-950/40 px-2.5 py-1 rounded-md border border-indigo-500/20">
                                ${s.mitre.id}: ${s.mitre.name}
                            </span>
                        </td>
                        <td class="py-3.5 px-6 text-right space-x-2">
                            ${s.pid > 1 ? `
                                <button onclick="remediate(${s.pid}, 'freeze')" class="bg-amber-600/80 hover:bg-amber-600 text-white px-3 py-1 rounded-lg text-[11px] transition shadow-sm">
                                    Freeze
                                </button>
                                <button onclick="remediate(${s.pid}, 'kill')" class="bg-rose-600/80 hover:bg-rose-600 text-white px-3 py-1 rounded-lg text-[11px] transition shadow-sm">
                                    Kill
                                </button>
                            ` : '<span class="text-slate-600">Kernel PID</span>'}
                        </td>
                    </tr>
                `).join('');

                renderMitreGrid();

            } catch (err) {
                console.error("Telemetry error:", err);
            } finally {
                setTimeout(() => spinner.classList.remove('animate-spin'), 600);
            }
        }

        function renderMitreGrid() {
            const container = document.getElementById('mitreGrid');
            container.innerHTML = Object.entries(cachedMitre).map(([tactic, items]) => `
                <div class="bg-slate-900/60 border border-white/5 rounded-xl p-3 flex flex-col justify-between">
                    <div>
                        <div class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 border-b border-white/5 pb-1">
                            ${tactic}
                        </div>
                        <div class="space-y-1.5">
                            ${items.length ? items.map(i => `
                                <div class="bg-rose-950/40 border border-rose-500/30 rounded-lg p-2 text-[10px]">
                                    <div class="font-bold text-rose-300">${i.technique}</div>
                                    <div class="text-slate-300 truncate">${i.name}</div>
                                    <div class="text-slate-500 mt-0.5">Port ${i.port} (${i.process})</div>
                                </div>
                            `).join('') : '<div class="text-[10px] text-slate-600">No active techniques observed</div>'}
                        </div>
                    </div>
                </div>
            `).join('');
        }

        async function remediate(pid, action) {
            const res = await fetch(`/api/contain?pid=${pid}&action=${action}`, { method: 'POST' });
            const result = await res.json();
            const banner = document.getElementById('actionBanner');
            banner.classList.remove('hidden');

            if (result.success) {
                banner.className = "p-3.5 rounded-xl text-xs font-mono bg-emerald-950/70 border border-emerald-500/40 text-emerald-300 glow-indigo";
                banner.textContent = `[CONTAINMENT SUCCESS] ${result.message}`;
            } else {
                banner.className = "p-3.5 rounded-xl text-xs font-mono bg-rose-950/70 border border-rose-500/40 text-rose-300 glow-crimson";
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
