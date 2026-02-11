// ═══════════════════════════════════════════════════════════
//  SkyShield – Frontend Controller
// ═══════════════════════════════════════════════════════════

const API = "http://localhost:8000";
let knownAlertIds = new Set();
let detectionInProgress = false;
let allDetectionResults = [];

// ── DOM refs ──
const $totalLogs     = document.getElementById("totalLogs");
const $threatsBlocked= document.getElementById("threatsBlocked");
const $suspicious    = document.getElementById("suspicious");
const $normalCount   = document.getElementById("normalCount");
const $alertCount    = document.getElementById("alertCount");
const $alertsList    = document.getElementById("alertsList");
const $noAlerts      = document.getElementById("noAlerts");
const $logsBody      = document.getElementById("logsBody");
const $detectBody    = document.getElementById("detectBody");
const $healthBar     = document.getElementById("healthBar");
const $healthLabel   = document.getElementById("healthLabel");
const $statAttacks   = document.getElementById("statAttacks");
const $statSuspicious= document.getElementById("statSuspicious");
const $statNormal    = document.getElementById("statNormal");
const $logForm       = document.getElementById("logForm");
const $logStatus     = document.getElementById("logStatus");
const $btnDetect     = document.getElementById("btnDetect");
const $btnClearAlerts= document.getElementById("btnClearAlerts");
const $btnClearLogs  = document.getElementById("btnClearLogs");
const $btnRefreshLogs= document.getElementById("btnRefreshLogs");
const $filterThreat  = document.getElementById("filterThreat");
const $filterIP      = document.getElementById("filterIP");
const $resultsCount  = document.getElementById("resultsCount");

// Modal elements
const $detailsModal   = document.getElementById("detailsModal");
const $modalTitle     = document.getElementById("modalTitle");
const $modalAlertsBody= document.getElementById("modalAlertsBody");
const $btnCloseModal  = document.getElementById("btnCloseModal");
const $modalTotal     = document.getElementById("modalTotal");
const $modalUniqueIPs = document.getElementById("modalUniqueIPs");
const $modalAvgScore  = document.getElementById("modalAvgScore");
const $cardAttacks    = document.getElementById("cardAttacks");
const $cardSuspicious = document.getElementById("cardSuspicious");

// ═══════════════════════════════════════════════════════════
//  FETCH HELPERS
// ═══════════════════════════════════════════════════════════

async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
//  STATS & METRICS
// ═══════════════════════════════════════════════════════════

async function refreshStats() {
  try {
    const [stats, logData] = await Promise.all([
      api("/stats"),
      api("/logs/count"),
    ]);

    animateValue($totalLogs, logData.count);
    animateValue($threatsBlocked, stats.blocked);
    animateValue($suspicious, stats.suspicious);
    animateValue($normalCount, stats.normal);
    animateValue($statAttacks, stats.attacks);
    animateValue($statSuspicious, stats.suspicious);
    animateValue($statNormal, stats.normal);

    // Health bar
    const h = stats.health_score;
    $healthBar.style.width = h + "%";
    $healthLabel.textContent = h + "% " + (h >= 80 ? "Optimal" : h >= 50 ? "Moderate" : "Critical");
    $healthLabel.className = h >= 80 ? "text-green-400" : h >= 50 ? "text-orange-400" : "text-red-400";

    setOnline(true);
  } catch (e) {
    console.error("Stats error:", e);
    setOnline(false);
  }
}

// ═══════════════════════════════════════════════════════════
//  ALERTS
// ═══════════════════════════════════════════════════════════

async function refreshAlerts() {
  try {
    const alerts = await api("/alerts");
    $alertCount.textContent = alerts.length;

    if (alerts.length === 0) {
      $noAlerts && ($noAlerts.style.display = "");
      return;
    }
    $noAlerts && ($noAlerts.style.display = "none");

    alerts.forEach(a => {
      if (knownAlertIds.has(a.log_id)) return;
      knownAlertIds.add(a.log_id);

      const isAttack = a.threat_label === "Attack";
      const isSusp   = a.threat_label === "Suspicious";

      const li = document.createElement("li");
      li.className = "p-4 flex items-start gap-4 hover:bg-white/5 transition animate-slideIn";

      li.innerHTML = `
        <div class="${isAttack ? 'bg-red-500/20 text-red-500' : isSusp ? 'bg-orange-500/20 text-orange-400' : 'bg-green-500/20 text-green-400'} p-2 rounded-lg">
          <i class="fa-solid ${isAttack ? 'fa-shield-virus' : isSusp ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i>
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex justify-between items-center">
            <span class="font-semibold text-sm ${isAttack ? 'text-red-400' : isSusp ? 'text-orange-400' : 'text-green-400'}">${a.threat_label}</span>
            <span class="text-xs text-slate-500 whitespace-nowrap ml-2">${formatTime(a.timestamp)}</span>
          </div>
          <p class="text-xs text-slate-400 mt-1">
            IP: <span class="text-slate-300">${a.source_ip || '—'}</span>
            &nbsp;|&nbsp; Score: <span class="font-mono ${isAttack ? 'text-red-400' : 'text-slate-300'}">${(a.threat_score ?? 0).toFixed(4)}</span>
          </p>
          <p class="text-xs mt-1">
            Action: <span class="italic ${isAttack ? 'text-red-400' : 'text-blue-400'}">${a.action_taken}</span>
          </p>
        </div>`;

      $alertsList.prepend(li);

      // Keep max 50 items in DOM
      while ($alertsList.children.length > 51) {
        $alertsList.removeChild($alertsList.lastChild);
      }
    });

    setOnline(true);
  } catch (e) {
    console.error("Alerts error:", e);
    setOnline(false);
  }
}

// ═══════════════════════════════════════════════════════════
//  LOGS TABLE
// ═══════════════════════════════════════════════════════════

async function refreshLogs() {
  try {
    const logs = await api("/logs");

    if (logs.length === 0) {
      $logsBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-slate-500">No logs yet</td></tr>`;
      return;
    }

    // Show latest 10
    const recent = logs.slice(-10).reverse();
    $logsBody.innerHTML = recent.map(l => {
      // Handle multiple possible field names
      const sourceIP = l.source_ip || l["Source IP"] || l["Src IP"] || "—";
      const bytesSent = l.bytes_sent || l["Total Fwd Packets"] || l["Fwd Packet Length Total"] || 0;
      const bytesRecv = l.bytes_received || l["Total Backward Packets"] || l["Bwd Packet Length Total"] || 0;
      const duration = l["Flow Duration"] || l.duration || l["flow_duration"] || 0;
      const packets = l["Total Fwd Packets"] || l.packets || l["total_fwd_packets"] || 0;
      
      return `
      <tr class="hover:bg-white/5 transition">
        <td class="px-5 py-3 font-mono text-blue-300">${sourceIP}</td>
        <td class="px-5 py-3">${Number(bytesSent).toLocaleString()}</td>
        <td class="px-5 py-3">${Number(bytesRecv).toLocaleString()}</td>
        <td class="px-5 py-3">${Number(duration).toLocaleString()}</td>
        <td class="px-5 py-3">${Number(packets).toLocaleString()}</td>
      </tr>`;
    }).join("");

  } catch (e) {
    console.error("Logs error:", e);
  }
}

// ═══════════════════════════════════════════════════════════
//  SUBMIT LOG
// ═══════════════════════════════════════════════════════════

$logForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  showLogStatus("Submitting…", "text-blue-400");

  const log = {
    source_ip:       document.getElementById("inputIP").value.trim(),
    bytes_sent:      Number(document.getElementById("inputBytesSent").value),
    bytes_received:  Number(document.getElementById("inputBytesRecv").value),
    "Flow Duration": Number(document.getElementById("inputDuration").value || 0),
    "Total Fwd Packets": Number(document.getElementById("inputPackets").value || 0),
  };

  try {
    await api("/logs", { method: "POST", body: JSON.stringify(log) });
    showLogStatus("✅ Log submitted!", "text-green-400");
    $logForm.reset();
    refreshLogs();
    refreshStats();
  } catch (err) {
    showLogStatus("❌ Failed: " + err.message, "text-red-400");
  }
});

// ═══════════════════════════════════════════════════════════
//  RUN DETECTION (with cancellation)
// ═══════════════════════════════════════════════════════════

$btnDetect.addEventListener("click", async () => {
  if (detectionInProgress) {
    // Cancel ongoing detection
    try {
      await api("/detect/cancel", { method: "POST" });
      $btnDetect.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Cancelling...`;
    } catch (err) {
      console.error("Cancel failed:", err);
    }
    return;
  }

  detectionInProgress = true;
  $btnDetect.innerHTML = `<i class="fa-solid fa-stop mr-1"></i> Stop Analysis`;
  $btnDetect.className = $btnDetect.className.replace("bg-blue-600", "bg-red-600");

  try {
    // Ask user for limit (optional)
    const logCount = await api("/logs/count");
    let limit = null;
    
    if (logCount.count > 10000) {
      const userLimit = prompt(`Found ${logCount.count.toLocaleString()} logs. Analyze how many? (Leave empty for all)`);
      if (userLimit) limit = parseInt(userLimit);
    }

    const response = await api("/detect", { 
      method: "POST",
      body: JSON.stringify({ limit: limit })
    });

    const results = response.analyzed_events || [];
    
    // Store results for filtering
    allDetectionResults = results;
    
    // Apply current filters and display
    applyFilters();
      
    // Show summary
    if (response.cancelled) {
      alert(`⚠️ Stopped! Analyzed ${response.analyzed_count.toLocaleString()} of ${response.total_logs.toLocaleString()} logs.`);
    } else {
      alert(`✅ Analyzed ${response.analyzed_count.toLocaleString()} logs!`);
    }

    await Promise.all([refreshAlerts(), refreshStats()]);

  } catch (err) {
    alert("Detection failed: " + err.message);
  } finally {
    detectionInProgress = false;
    $btnDetect.disabled = false;
    $btnDetect.innerHTML = `<i class="fa-solid fa-radar mr-1"></i> Run Detection`;
    $btnDetect.className = $btnDetect.className.replace("bg-red-600", "bg-blue-600");
  }
});

// ═══════════════════════════════════════════════════════════
//  FILTER DETECTION RESULTS
// ═══════════════════════════════════════════════════════════

function applyFilters() {
  let filtered = allDetectionResults;
  
  // Filter by threat level
  const threatFilter = $filterThreat.value;
  if (threatFilter !== "all") {
    filtered = filtered.filter(r => r.threat_label === threatFilter);
  }
  
  // Filter by IP
  const ipFilter = $filterIP.value.trim().toLowerCase();
  if (ipFilter) {
    filtered = filtered.filter(r => 
      (r.source_ip || "").toLowerCase().includes(ipFilter)
    );
  }
  
  // Update results count
  $resultsCount.textContent = filtered.length;
  
  // Render filtered results
  if (filtered.length === 0) {
    $detectBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-slate-500">${allDetectionResults.length === 0 ? 'No logs to analyze' : 'No results match your filters'}</td></tr>`;
  } else {
    $detectBody.innerHTML = filtered.map(r => {
      const color = r.threat_label === "Attack" ? "text-red-400"
                  : r.threat_label === "Suspicious" ? "text-orange-400"
                  : "text-green-400";
      return `
        <tr class="hover:bg-white/5 transition">
          <td class="px-5 py-3 font-mono text-blue-300">${r.source_ip}</td>
          <td class="px-5 py-3 font-semibold ${color}">${r.threat_label}</td>
          <td class="px-5 py-3 font-mono">${r.threat_score.toFixed(4)}</td>
          <td class="px-5 py-3 italic ${color}">${r.action_taken}</td>
          <td class="px-5 py-3 text-slate-400 text-xs">${formatTime(r.timestamp)}</td>
        </tr>`;
    }).join("");
  }
}

// Filter event listeners
$filterThreat.addEventListener("change", applyFilters);
$filterIP.addEventListener("input", applyFilters);

// ═══════════════════════════════════════════════════════════
//  CLEAR ALERTS
// ═══════════════════════════════════════════════════════════

$btnClearAlerts.addEventListener("click", async () => {
  try {
    await api("/alerts/clear", { method: "POST" });
    knownAlertIds.clear();
    $alertsList.innerHTML = `
      <li class="p-6 text-center text-slate-500 text-sm" id="noAlerts">
        <i class="fa-solid fa-shield-halved text-2xl mb-2 block"></i>
        No alerts yet — submit logs and run detection
      </li>`;
    $alertCount.textContent = "0";
    refreshStats();
  } catch (e) {
    console.error("Clear failed:", e);
  }
});

$btnClearLogs.addEventListener("click", async () => {
  const ok = confirm("Clear all logs and alerts? This cannot be undone.");
  if (!ok) return;

  try {
    await api("/logs/clear", { method: "POST", body: JSON.stringify({ clear_alerts: true }) });
    allDetectionResults = [];
    applyFilters();
    refreshLogs();
    refreshAlerts();
    refreshStats();
  } catch (e) {
    console.error("Clear logs failed:", e);
    alert("Failed to clear logs: " + e.message);
  }
});

$btnRefreshLogs.addEventListener("click", refreshLogs);

// ═══════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════

function animateValue(el, target) {
  const start = parseInt(el.textContent.replace(/[^0-9-]/g, "")) || 0;
  if (start === target) { el.textContent = target.toLocaleString(); return; }
  const duration = 400;
  let startTime = null;
  function step(ts) {
    if (!startTime) startTime = ts;
    const p = Math.min((ts - startTime) / duration, 1);
    el.textContent = Math.floor(p * (target - start) + start).toLocaleString();
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function formatTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function showLogStatus(msg, cls) {
  $logStatus.textContent = msg;
  $logStatus.className = `text-xs mt-2 text-center ${cls}`;
  $logStatus.classList.remove("hidden");
  setTimeout(() => $logStatus.classList.add("hidden"), 3000);
}

function setOnline(ok) {
  const dot  = document.getElementById("statusDot");
  const text = document.getElementById("statusText");
  const badge= document.getElementById("statusBadge");

  dot.className  = ok ? "status-dot bg-green-500" : "status-dot bg-red-500";
  text.textContent = ok ? "System Online" : "Backend Offline";
  badge.className  = ok ? "status-badge online" : "status-badge offline";
}

// ═══════════════════════════════════════════════════════════
//  DETAILS MODAL FOR ATTACKS & SUSPICIOUS
// ═══════════════════════════════════════════════════════════

async function showAlertDetails(threatType) {
  try {
    const allAlerts = await api("/alerts");
    const filtered = allAlerts.filter(a => a.threat_label === threatType);
    
    // Update modal title
    const icon = threatType === "Attack" ? "fa-shield-virus" : "fa-triangle-exclamation";
    const color = threatType === "Attack" ? "text-red-400" : "text-orange-400";
    $modalTitle.innerHTML = `<i class="fa-solid ${icon} ${color} mr-2"></i> ${threatType} Details`;
    
    // Calculate stats
    const total = filtered.length;
    const uniqueIPs = new Set(filtered.map(a => a.source_ip)).size;
    const avgScore = total > 0 ? (filtered.reduce((sum, a) => sum + (a.threat_score || 0), 0) / total) : 0;
    
    $modalTotal.textContent = total;
    $modalUniqueIPs.textContent = uniqueIPs;
    $modalAvgScore.textContent = avgScore.toFixed(4);
    
    // Populate table
    if (filtered.length === 0) {
      $modalAlertsBody.innerHTML = `<tr><td colspan="4" class="px-5 py-6 text-center text-slate-500">No ${threatType.toLowerCase()} alerts found</td></tr>`;
    } else {
      const rowColor = threatType === "Attack" ? "text-red-400" : "text-orange-400";
      $modalAlertsBody.innerHTML = filtered.map(a => `
        <tr class="hover:bg-white/5 transition">
          <td class="px-5 py-3 font-mono text-blue-300">${a.source_ip || '—'}</td>
          <td class="px-5 py-3 font-mono ${rowColor}">${(a.threat_score ?? 0).toFixed(4)}</td>
          <td class="px-5 py-3 text-sm italic ${rowColor}">${a.action_taken}</td>
          <td class="px-5 py-3 text-slate-400 text-xs">${formatTime(a.timestamp)}</td>
        </tr>`).join("");
    }
    
    // Show modal
    $detailsModal.classList.remove("hidden");
  } catch (err) {
    console.error("Failed to load alert details:", err);
    alert("Could not load alert details: " + err.message);
  }
}

// Modal event listeners
$btnCloseModal.addEventListener("click", () => {
  $detailsModal.classList.add("hidden");
});

$detailsModal.addEventListener("click", (e) => {
  if (e.target === $detailsModal) {
    $detailsModal.classList.add("hidden");
  }
});

// Close modal with Escape key
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$detailsModal.classList.contains("hidden")) {
    $detailsModal.classList.add("hidden");
  }
});

// Card click handlers
$cardAttacks.addEventListener("click", () => showAlertDetails("Attack"));
$cardSuspicious.addEventListener("click", () => showAlertDetails("Suspicious"));

// ═══════════════════════════════════════════════════════════
//  INIT – load everything on page open
// ═══════════════════════════════════════════════════════════

(async function init() {
  await Promise.all([refreshStats(), refreshAlerts(), refreshLogs()]);
})();

// Auto-refresh every 5 seconds
setInterval(() => {
  refreshStats();
  refreshAlerts();
}, 5000);