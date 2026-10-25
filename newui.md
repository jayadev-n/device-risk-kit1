# UI Modernization & Design Upgrade Guide

This guide provides the complete, copy-paste ready HTML, Tailwind CSS styling, and JavaScript code to transform your Device Fingerprinting dashboard into a modern cybersecurity command center.

---

## Highlights of the Design Upgrade

1. **Cybersecurity Glassmorphism:** Sleek, semi-transparent dark panels (`bg-slate-900/80 backdrop-blur-xl`) with subtle slate borders (`border-slate-800/80`).
2. **Dynamic Risk Score Gauge:** Pulsing risk level badges (**LOW**, **MEDIUM**, **HIGH**) with real-time color-coded accent glow effects (`emerald`, `amber`, `rose`).
3. **Interactive Telemetry Modals:** Upgraded inspection overlays with clear key-value diagnostic layouts for telemetry evidence.
4. **Enhanced JSON Viewer:** Styled syntax-highlighted code viewport with custom smooth scrollbars.
5. **Responsive Dashboard Grid:** Clean 3-column layout optimized for modern widescreen monitors.

---

## File to Replace: `templates/index.html`

Replace the entire contents of `templates/index.html` with this updated code:

```html
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Device Fingerprinting & Risk Engine</title>
    <!-- Tailwind CSS CDN -->
    <script src="[https://cdn.tailwindcss.com](https://cdn.tailwindcss.com)"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        slate: {
                            850: '#0f172a',
                            950: '#020617',
                        }
                    },
                    fontFamily: {
                        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
                    }
                }
            }
        }
    </script>
    <link href="[https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap](https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap)" rel="stylesheet">
    <style>
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
        }
        .code-font {
            font-family: 'JetBrains Mono', monospace;
        }
        /* Custom Smooth Scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: #020617;
        }
        ::-webkit-scrollbar-thumb {
            background: #1e293b;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #334155;
        }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen antialiased selection:bg-blue-500 selection:text-white">

    <!-- Top Navigation Header -->
    <header class="sticky top-0 z-40 bg-slate-900/80 backdrop-blur-xl border-b border-slate-800/80 px-6 py-4">
        <div class="max-w-[1700px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
            <div class="flex items-center space-x-3">
                <div class="p-2 bg-blue-600/10 border border-blue-500/30 rounded-xl text-blue-400">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                    </svg>
                </div>
                <div>
                    <h1 class="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                        Device Fingerprinting Engine
                        <span class="px-2 py-0.5 text-[10px] code-font font-semibold bg-blue-500/10 border border-blue-500/30 text-blue-400 rounded-full">v2.4 Enterprise</span>
                    </h1>
                    <p class="text-xs text-slate-400">Forensic-level Browser Telemetry & Threat Analysis</p>
                </div>
            </div>

            <!-- Simulation Controls -->
            <div class="flex flex-wrap items-center gap-2">
                <button onclick="analyzeBrowser()" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 active:scale-95 text-white font-medium text-xs rounded-xl transition shadow-lg shadow-blue-500/20 flex items-center space-x-2">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                    <span>Analyze My Browser</span>
                </button>
                <button onclick="simulateScenario('postman')" class="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-300 font-medium text-xs rounded-xl border border-slate-700/60 transition flex items-center space-x-2">
                    <span>🤖 Postman / Bot</span>
                </button>
                <button onclick="simulateScenario('outdated')" class="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-300 font-medium text-xs rounded-xl border border-slate-700/60 transition flex items-center space-x-2">
                    <span>📅 Chrome 70</span>
                </button>
                <button onclick="simulateScenario('curl')" class="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-300 font-medium text-xs rounded-xl border border-slate-700/60 transition flex items-center space-x-2">
                    <span>💻 cURL Request</span>
                </button>
            </div>
        </div>
    </header>

    <!-- Main Content Layout -->
    <main class="max-w-[1700px] mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">

        <!-- Left Column: Risk Gauge & Overview -->
        <section class="lg:col-span-3 space-y-6">
            <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 backdrop-blur-xl shadow-xl">
                <h2 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center justify-between">
                    <span>Risk Assessment</span>
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] code-font bg-slate-800 text-slate-400">Live</span>
                </h2>

                <!-- Score Display Badge -->
                <div id="risk-score-badge" class="p-6 rounded-2xl bg-emerald-950/30 border border-emerald-500/30 text-center transition-all duration-300">
                    <span id="risk-severity-text" class="text-2xl font-black tracking-widest text-emerald-400 block uppercase">LOW</span>
                    <span id="risk-action-text" class="text-[11px] code-font text-emerald-300/80 mt-1 block">ACTION: ALLOW</span>
                </div>

                <!-- Numerical Risk Score Meter -->
                <div class="mt-6 space-y-2">
                    <div class="flex justify-between text-xs text-slate-400 font-medium">
                        <span>Risk Score</span>
                        <span id="risk-score-num" class="code-font font-bold text-white text-base">0</span>
                    </div>
                    <div class="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden p-0.5 border border-slate-700/50">
                        <div id="risk-score-bar" class="h-full bg-emerald-500 rounded-full transition-all duration-500" style="width: 0%"></div>
                    </div>
                    <div class="flex justify-between text-[10px] code-font text-slate-500 pt-1">
                        <span>0 — Low</span>
                        <span>5 — Med</span>
                        <span>12+ — High</span>
                    </div>
                </div>

                <!-- Session Metadata Details -->
                <div class="mt-6 pt-6 border-t border-slate-800/80 space-y-3 text-xs">
                    <div class="flex justify-between items-center py-1">
                        <span class="text-slate-400">Device ID</span>
                        <span id="meta-device-id" class="code-font text-slate-200 font-semibold truncate max-w-[140px]">--</span>
                    </div>
                    <div class="flex justify-between items-center py-1">
                        <span class="text-slate-400">Browser</span>
                        <span id="meta-browser" class="code-font text-slate-200">--</span>
                    </div>
                    <div class="flex justify-between items-center py-1">
                        <span class="text-slate-400">Operating System</span>
                        <span id="meta-os" class="code-font text-slate-200">--</span>
                    </div>
                    <div class="flex justify-between items-center py-1">
                        <span class="text-slate-400">Bot Detected</span>
                        <span id="meta-bot" class="code-font text-emerald-400 font-bold">No</span>
                    </div>
                    <div class="flex justify-between items-center py-1">
                        <span class="text-slate-400">Evaluated At</span>
                        <span id="meta-time" class="code-font text-slate-400">--</span>
                    </div>
                </div>
            </div>
        </section>

        <!-- Middle Column: Rule Evaluation Feed -->
        <section class="lg:col-span-5 space-y-4">
            <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 backdrop-blur-xl shadow-xl flex flex-col h-[calc(100vh-140px)]">
                
                <!-- Rule Status Bar Headers -->
                <div class="flex items-center justify-between mb-4 pb-4 border-b border-slate-800/80">
                    <h2 class="text-xs font-bold text-slate-400 uppercase tracking-wider">Rule Evaluation Engine</h2>
                    <div class="flex items-center space-x-2 text-xs font-medium">
                        <span id="triggered-badge" class="px-2.5 py-1 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 code-font">0 TRIGGERED</span>
                        <span id="passed-badge" class="px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 code-font">0 PASSED</span>
                        <span id="pending-badge" class="px-2.5 py-1 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 code-font">0 PENDING</span>
                    </div>
                </div>

                <!-- Scrollable Rule Cards Container -->
                <div id="rule-evaluation-container" class="flex-1 overflow-y-auto pr-2 space-y-2.5">
                    <!-- Dynamic Rule Cards Populate Here -->
                    <div class="text-center py-12 text-slate-500 text-xs italic">
                        Click "Analyze My Browser" to execute heuristics inspection.
                    </div>
                </div>
            </div>
        </section>

        <!-- Right Column: Raw JSON Response Payload -->
        <section class="lg:col-span-4 space-y-4">
            <div class="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 backdrop-blur-xl shadow-xl flex flex-col h-[calc(100vh-140px)]">
                <div class="flex items-center justify-between mb-4 pb-4 border-b border-slate-800/80">
                    <h2 class="text-xs font-bold text-slate-400 uppercase tracking-wider">JSON Payload Output</h2>
                    <button onclick="copyJsonResponse()" class="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center space-x-1">
                        <span>Copy JSON</span>
                    </button>
                </div>
                <div class="flex-1 bg-slate-950 rounded-xl border border-slate-800/80 p-4 overflow-auto">
                    <pre id="json-response-viewer" class="code-font text-xs text-emerald-400 leading-relaxed">{\n  "status": "idle",\n  "message": "Awaiting browser analysis execution..."\n}</pre>
                </div>
            </div>
        </section>

    </main>

    <!-- Inspection Evidence Detail Modal Overlay -->
    <div id="rule-detail-modal" class="hidden fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
        <div class="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl relative animate-in fade-in zoom-in-95 duration-150">
            <div class="flex justify-between items-start mb-4">
                <div>
                    <div class="flex items-center space-x-2">
                        <span id="modal-rule-id" class="px-2 py-0.5 text-xs font-mono font-bold rounded"></span>
                        <h3 id="modal-rule-title" class="text-base font-bold text-white"></h3>
                    </div>
                    <p id="modal-rule-desc" class="text-xs text-slate-400 mt-2"></p>
                </div>
                <button onclick="closeRuleModal()" class="text-slate-400 hover:text-white text-2xl font-bold ml-2">&times;</button>
            </div>

            <!-- Evidence Breakdown Box -->
            <div class="bg-slate-950 p-4 rounded-xl border border-slate-800/80 mb-5">
                <h4 class="text-[11px] font-bold text-slate-400 mb-3 uppercase tracking-wider flex items-center space-x-1.5">
                    <svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    <span>Browser Telemetry Evidence</span>
                </h4>
                <div id="modal-rule-details" class="space-y-2">
                    <!-- Key-value detail rows render here -->
                </div>
            </div>

            <div class="flex justify-between items-center pt-2">
                <span id="modal-score-impact" class="text-xs font-mono"></span>
                <button onclick="closeRuleModal()" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 active:scale-95 text-white rounded-xl text-xs font-medium transition shadow-lg shadow-blue-500/20">
                    Close Inspection
                </button>
            </div>
        </div>
    </div>

    <!-- Frontend Application JavaScript -->
    <script>
        let currentAnalysisData = null;

        // Perform browser telemetry collection and submit to scoring API
        async function analyzeBrowser() {
            const payload = {
                canvas_hash: "canvas_340bcfbc",
                platform: navigator.platform || "Win32",
                screen_depth: window.screen.colorDepth || 24,
                screen_resolution: `${window.screen.width}x${window.screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Asia/Calcutta",
                cookies_enabled: navigator.cookieEnabled,
                webdriver: navigator.webdriver || false,
                mouse_event_count: 14,
                is_automated_context: false
            };

            try {
                const response = await fetch('/api/v1/score', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept-Language': navigator.language || 'en-US,en;q=0.9'
                    },
                    body: JSON.stringify(payload)
                });

                currentAnalysisData = await response.json();
                updateDashboardUI(currentAnalysisData);
            } catch (err) {
                console.error("Scoring API request failed:", err);
            }
        }

        // Update all UI panels with API results
        function updateDashboardUI(data) {
            // 1. Update JSON Viewer
            document.getElementById('json-response-viewer').innerText = JSON.stringify(data, null, 2);

            // 2. Update Risk Gauge
            const score = data.risk_score || 0;
            const severity = data.risk_severity || "LOW";
            const action = data.recommended_action || "ALLOW";

            document.getElementById('risk-score-num').innerText = score;
            document.getElementById('risk-severity-text').innerText = severity;
            document.getElementById('risk-action-text').innerText = `ACTION: ${action}`;

            const badgeEl = document.getElementById('risk-score-badge');
            const barEl = document.getElementById('risk-score-bar');

            if (severity === "HIGH") {
                badgeEl.className = "p-6 rounded-2xl bg-rose-950/40 border border-rose-500/50 text-center shadow-lg shadow-rose-950/50";
                document.getElementById('risk-severity-text').className = "text-2xl font-black tracking-widest text-rose-400 block uppercase";
                barEl.className = "h-full bg-rose-500 rounded-full transition-all duration-500";
            } else if (severity === "MEDIUM") {
                badgeEl.className = "p-6 rounded-2xl bg-amber-950/40 border border-amber-500/50 text-center shadow-lg shadow-amber-950/50";
                document.getElementById('risk-severity-text').className = "text-2xl font-black tracking-widest text-amber-400 block uppercase";
                barEl.className = "h-full bg-amber-500 rounded-full transition-all duration-500";
            } else {
                badgeEl.className = "p-6 rounded-2xl bg-emerald-950/40 border border-emerald-500/50 text-center shadow-lg shadow-emerald-950/50";
                document.getElementById('risk-severity-text').className = "text-2xl font-black tracking-widest text-emerald-400 block uppercase";
                barEl.className = "h-full bg-emerald-500 rounded-full transition-all duration-500";
            }

            const barPercentage = Math.min((score / 15) * 100, 100);
            barEl.style.width = `${barPercentage}%`;

            // 3. Update Session Metadata
            document.getElementById('meta-device-id').innerText = data.device_id || "--";
            document.getElementById('meta-browser').innerText = `${data.parsed_metadata?.browser?.family || 'Chrome'} ${data.parsed_metadata?.browser?.major || ''}`;
            document.getElementById('meta-os').innerText = data.parsed_metadata?.os?.family || 'Windows 10';
            document.getElementById('meta-bot').innerText = data.parsed_metadata?.is_bot ? 'Yes' : 'No';
            document.getElementById('meta-bot').className = data.parsed_metadata?.is_bot ? 'code-font text-rose-400 font-bold' : 'code-font text-emerald-400 font-bold';
            document.getElementById('meta-time').innerText = new Date(data.evaluated_at || Date.now()).toLocaleTimeString();

            // 4. Render Rule Evaluation Cards
            renderRules(data.evaluated_rules || []);
        }

        // Render dynamic rule cards
        function renderRules(evaluatedRules) {
            const container = document.getElementById('rule-evaluation-container');
            container.innerHTML = '';

            let triggeredCount = 0;
            let passedCount = 0;

            evaluatedRules.forEach(rule => {
                const isTriggered = rule.status === 'triggered';
                if (isTriggered) triggeredCount++; else passedCount++;

                const card = document.createElement('div');
                card.className = `p-3.5 rounded-xl border cursor-pointer transition-all duration-200 hover:scale-[1.01] ${
                    isTriggered 
                        ? 'bg-rose-950/20 border-rose-500/40 hover:border-rose-400 text-rose-200 shadow-lg shadow-rose-950/20' 
                        : 'bg-slate-900/40 border-slate-800/80 hover:border-slate-700 text-slate-300'
                }`;

                card.innerHTML = `
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-2">
                            <span class="px-2 py-0.5 text-[11px] font-mono font-bold rounded-md ${
                                isTriggered ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            }">${rule.id}</span>
                            <strong class="text-xs font-semibold text-white">${rule.name}</strong>
                        </div>
                        <span class="text-xs font-mono font-bold ${isTriggered ? 'text-rose-400' : 'text-slate-500'}">
                            ${isTriggered ? `+${rule.score_impact} pts` : '0 pts'}
                        </span>
                    </div>
                    <p class="text-[11px] text-slate-400 mt-1.5 leading-relaxed">${rule.description}</p>
                    <div class="flex items-center justify-between mt-2.5 pt-2 border-t border-slate-800/60">
                        <span class="text-[10px] text-blue-400 font-mono">🔍 Click to inspect evidence</span>
                        <span class="text-[10px] uppercase font-bold tracking-wider ${isTriggered ? 'text-rose-400' : 'text-emerald-400'}">
                            ${isTriggered ? 'Triggered' : 'Passed'}
                        </span>
                    </div>
                `;

                card.addEventListener('click', () => openRuleModal(rule));
                container.appendChild(card);
            });

            document.getElementById('triggered-badge').innerText = `${triggeredCount} TRIGGERED`;
            document.getElementById('passed-badge').innerText = `${passedCount} PASSED`;
            document.getElementById('pending-badge').innerText = `0 PENDING`;
        }

        // Open modal overlay with telemetry details
        function openRuleModal(rule) {
            const modal = document.getElementById('rule-detail-modal');
            const isTriggered = rule.status === 'triggered';

            const badgeEl = document.getElementById('modal-rule-id');
            badgeEl.innerText = rule.id;
            badgeEl.className = `px-2 py-0.5 text-xs font-mono font-bold rounded ${
                isTriggered ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
            }`;

            document.getElementById('modal-rule-title').innerText = rule.name;
            document.getElementById('modal-rule-desc').innerText = rule.description;
            
            document.getElementById('modal-score-impact').innerText = isTriggered 
                ? `Risk Contribution: +${rule.score_impact} pts` 
                : `Risk Contribution: 0 pts (Passed cleanly)`;
            document.getElementById('modal-score-impact').className = `text-xs font-mono ${isTriggered ? 'text-rose-400 font-bold' : 'text-slate-400'}`;

            const detailsContainer = document.getElementById('modal-rule-details');
            detailsContainer.innerHTML = '';

            const details = rule.details || {};
            if (Object.keys(details).length === 0) {
                detailsContainer.innerHTML = `<p class="text-xs text-slate-500 italic">No evidence recorded.</p>`;
            } else {
                Object.entries(details).forEach(([key, value]) => {
                    const row = document.createElement('div');
                    row.className = 'flex justify-between items-center py-1.5 border-b border-slate-800/80 text-xs';
                    row.innerHTML = `
                        <span class="text-slate-400 font-medium">${key}</span>
                        <span class="font-mono text-emerald-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 break-all max-w-[240px] text-right">
                            ${value}
                        </span>
                    `;
                    detailsContainer.appendChild(row);
                });
            }

            modal.classList.remove('hidden');
        }

        function closeRuleModal() {
            document.getElementById('rule-detail-modal').classList.add('hidden');
        }

        function copyJsonResponse() {
            if (currentAnalysisData) {
                navigator.clipboard.writeText(JSON.stringify(currentAnalysisData, null, 2));
                alert("JSON Response copied to clipboard!");
            }
        }

        // Auto-run analysis on initial load
        window.addEventListener('DOMContentLoaded', analyzeBrowser);
    </script>
</body>
</html>