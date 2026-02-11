// ═══════════════════════════════════════════════════════════
//  SkyShield – Frontend Controller
// ═══════════════════════════════════════════════════════════

const API = "http://localhost:8000";
let knownAlertIds = new Set();

// ── DOM refs ──
const $totalLogs     = document.getElementById("totalLogs");
const $threatsBlocked= document.getElementById("threatsBlocked");
const $suspicious    = document.getElementById("suspicious");
const $normalCount   = document.getElementById("normalCount");
const $alertCount    = document.getElementById("alertCount");
const $alertsList    = document.getElementById("alertsList");
const $noAlerts      = document.getElementById("noAlerts");
const $logsBody      = document.getElementById("logsBody");
const $healthBar     = document.getElementById("healthBar");
const $healthLabel   = document.getElementById("healthLabel");
const $statAttacks   = document.getElementById("statAttacks");
const $statSuspicious= document.getElementById("statSuspicious");
const $statNormal    = document.getElementById("statNormal");

const $btnClearAlerts= document.getElementById("btnClearAlerts");
const $btnClearLogs  = document.getElementById("btnClearLogs");
const $btnRefreshLogs= document.getElementById("btnRefreshLogs");
const $btnDetect     = document.getElementById("btnDetect");

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

// Chart instances
let threatChart = null;
let timelineChart = null;

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
//  CHARTS INITIALIZATION
// ═══════════════════════════════════════════════════════════

function initCharts() {
  // Threat Distribution Donut Chart
  const ctxThreat = document.getElementById('threatChart');
  if (ctxThreat) {
    threatChart = new Chart(ctxThreat, {
      type: 'doughnut',
      data: {
        labels: ['Attack', 'Suspicious', 'Normal'],
        datasets: [{
          data: [0, 0, 0],
          backgroundColor: [
            'rgba(239, 68, 68, 0.8)',   // Red for Attack
            'rgba(251, 146, 60, 0.8)',  // Orange for Suspicious
            'rgba(34, 197, 94, 0.8)'    // Green for Normal
          ],
          borderColor: [
            'rgba(239, 68, 68, 1)',
            'rgba(251, 146, 60, 1)',
            'rgba(34, 197, 94, 1)'
          ],
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: 'rgba(203, 213, 225, 0.9)',
              padding: 15,
              font: { size: 12 }
            }
          },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            titleColor: 'rgba(203, 213, 225, 1)',
            bodyColor: 'rgba(203, 213, 225, 0.8)',
            borderColor: 'rgba(59, 130, 246, 0.5)',
            borderWidth: 1,
            padding: 12,
            displayColors: true
          }
        }
      }
    });
  }

  // Attack Timeline Line Chart
  const ctxTimeline = document.getElementById('timelineChart');
  if (ctxTimeline) {
    timelineChart = new Chart(ctxTimeline, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Attacks',
            data: [],
            borderColor: 'rgba(239, 68, 68, 1)',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
          },
          {
            label: 'Suspicious',
            data: [],
            borderColor: 'rgba(251, 146, 60, 1)',
            backgroundColor: 'rgba(251, 146, 60, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false
        },
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: 'rgba(203, 213, 225, 0.9)',
              padding: 15,
              font: { size: 12 },
              usePointStyle: true
            }
          },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            titleColor: 'rgba(203, 213, 225, 1)',
            bodyColor: 'rgba(203, 213, 225, 0.8)',
            borderColor: 'rgba(59, 130, 246, 0.5)',
            borderWidth: 1,
            padding: 12
          }
        },
        scales: {
          x: {
            ticks: { color: 'rgba(148, 163, 184, 0.8)', font: { size: 10 } },
            grid: { color: 'rgba(71, 85, 105, 0.3)' }
          },
          y: {
            beginAtZero: true,
            ticks: { 
              color: 'rgba(148, 163, 184, 0.8)',
              font: { size: 10 },
              stepSize: 1
            },
            grid: { color: 'rgba(71, 85, 105, 0.3)' }
          }
        }
      }
    });
  }
}

function updateCharts(alerts) {
  // Update Threat Distribution
  const attackCount = alerts.filter(a => a.threat_label === 'Attack').length;
  const suspiciousCount = alerts.filter(a => a.threat_label === 'Suspicious').length;
  const normalCount = alerts.filter(a => a.threat_label === 'Normal').length;

  if (threatChart) {
    threatChart.data.datasets[0].data = [attackCount, suspiciousCount, normalCount];
    threatChart.update('none');
  }

  // Update Timeline - group by time intervals (last 10 detection runs)
  if (timelineChart && alerts.length > 0) {
    // Sort alerts by timestamp
    const sortedAlerts = [...alerts].sort((a, b) => 
      new Date(a.timestamp) - new Date(b.timestamp)
    );

    // Group into 10 time buckets
    const bucketCount = Math.min(10, Math.ceil(alerts.length / 5));
    const bucketSize = Math.ceil(sortedAlerts.length / bucketCount);
    const timeLabels = [];
    const attackData = [];
    const suspData = [];

    for (let i = 0; i < bucketCount; i++) {
      const bucketAlerts = sortedAlerts.slice(i * bucketSize, (i + 1) * bucketSize);
      if (bucketAlerts.length === 0) continue;

      const attacks = bucketAlerts.filter(a => a.threat_label === 'Attack').length;
      const suspicious = bucketAlerts.filter(a => a.threat_label === 'Suspicious').length;
      
      const firstTime = new Date(bucketAlerts[0].timestamp);
      const timeLabel = firstTime.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
      
      timeLabels.push(timeLabel);
      attackData.push(attacks);
      suspData.push(suspicious);
    }

    timelineChart.data.labels = timeLabels;
    timelineChart.data.datasets[0].data = attackData;
    timelineChart.data.datasets[1].data = suspData;
    timelineChart.update('none');
  }
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

    // Update charts with alert data
    updateCharts(alerts);

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
      // Handle multiple possible field names (matched to actual Kaggle CICIDS column names)
      const sourceIP = l.source_ip || l["Source IP"] || l["Src IP"] || "—";
      const bytesSent = l["Total Length of Fwd Packet"] || l["Fwd Packet Length Total"] || l.bytes_sent || 0;
      const bytesRecv = l["Total Length of Bwd Packet"] || l["Bwd Packet Length Total"] || l.bytes_received || 0;
      const duration = l["Flow Duration"] || l.duration || 0;
      const packets = l["Total Fwd Packet"] || l["Total Fwd Packets"] || l.packets || 0;
      return `
        <tr class="hover:bg-white/5 transition">
          <td class="px-5 py-3 font-mono text-blue-300">${sourceIP}</td>
          <td class="px-5 py-3">${formatNumber(bytesSent)}</td>
          <td class="px-5 py-3">${formatNumber(bytesRecv)}</td>
          <td class="px-5 py-3">${formatNumber(duration)}</td>
          <td class="px-5 py-3">${formatNumber(packets)}</td>
        </tr>`;
    }).join("");

  } catch (e) {
    console.error("Logs error:", e);
  }
}


// ═══════════════════════════════════════════════════════════
//  RUN DETECTION BUTTON
// ═══════════════════════════════════════════════════════════

$btnDetect.addEventListener("click", async () => {
  $btnDetect.disabled = true;
  $btnDetect.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Analyzing...`;

  try {
    const logCount = await api("/logs/count");
    let limit = null;
    
    if (logCount.count > 10000) {
      const userLimit = prompt(`Found ${formatNumber(logCount.count)} logs. Analyze how many? (Leave empty for all)`);
      if (userLimit) limit = parseInt(userLimit);
    }

    const response = await api("/detect", { 
      method: "POST",
      body: JSON.stringify({ limit: limit })
    });

    if (response.cancelled) {
      alert(`⚠️ Stopped! Analyzed ${formatNumber(response.analyzed_count)} of ${formatNumber(response.total_logs)} logs.`);
    } else {
      alert(`✅ Analyzed ${formatNumber(response.analyzed_count)} logs!\n\nCheck the Alerts section for results.`);
    }

    await Promise.all([refreshAlerts(), refreshStats()]);

  } catch (err) {
    alert("Detection failed: " + err.message);
  } finally {
    $btnDetect.disabled = false;
    $btnDetect.innerHTML = `<i class="fa-solid fa-radar mr-1"></i> Run Detection`;
  }
});

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
        No alerts yet
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
function safeNumber(val) {
  const num = Number(val) || 0;
  return isNaN(num) ? 0 : num;
}

function formatNumber(val) {
  return safeNumber(val).toLocaleString();
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
//  ALERT DETAILS MODAL
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
        // Populate table with threat classification
    if (filtered.length === 0) {
      $modalAlertsBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-slate-500">No ${threatType.toLowerCase()} alerts found</td></tr>`;
    } else {
      $modalAlertsBody.innerHTML = filtered.map(a => {
        // Determine threat badge color
        let threatBadgeColor = "bg-slate-600 text-slate-200";
        let threatText = a.threat_label || "Unknown";
        if (a.threat_label === "Attack") {
          threatBadgeColor = "bg-red-500/30 text-red-300";
        } else if (a.threat_label === "Suspicious") {
          threatBadgeColor = "bg-orange-500/30 text-orange-300";
        } else if (a.threat_label === "Normal") {
          threatBadgeColor = "bg-green-500/30 text-green-300";
        }
        return `
        <tr class="hover:bg-white/5 transition">
          <td class="px-5 py-3 font-mono text-blue-300">${a.source_ip || '—'}</td>
          <td class="px-5 py-3 font-mono text-slate-300">${(a.threat_score ?? 0).toFixed(4)}</td>
          <td class="px-5 py-3"><span class="inline-block px-2 py-1 rounded text-xs font-semibold ${threatBadgeColor}">${threatText}</span></td>
          <td class="px-5 py-3 text-sm italic text-slate-400">${a.action_taken || '—'}</td>
          <td class="px-5 py-3 text-slate-400 text-xs">${formatTime(a.timestamp)}</td>
        </tr>`;
      }).join("");
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
  initCharts();
  refreshStats().catch(e => console.error("Stats init error:", e));
  refreshAlerts().catch(e => console.error("Alerts init error:", e));
  refreshLogs().catch(e => console.error("Logs init error:", e));
})();

// Auto-refresh every 5 seconds
setInterval(() => {
  refreshStats();
  refreshAlerts();
}, 5000);