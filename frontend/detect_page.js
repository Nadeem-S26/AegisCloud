const API = "http://localhost:8000";

const $btnDetect = document.getElementById("btnDetect");
const $filterThreat = document.getElementById("filterThreat");
const $filterIP = document.getElementById("filterIP");
const $resultsCount = document.getElementById("resultsCount");
const $detectBody = document.getElementById("detectBody");

let detectionInProgress = false;
let allDetectionResults = [];

async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function formatTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function applyFilters() {
  let filtered = allDetectionResults;

  const threatFilter = $filterThreat.value;
  if (threatFilter !== "all") {
    filtered = filtered.filter(r => r.threat_label === threatFilter);
  }

  const ipFilter = $filterIP.value.trim().toLowerCase();
  if (ipFilter) {
    filtered = filtered.filter(r => (r.source_ip || "").toLowerCase().includes(ipFilter));
  }

  $resultsCount.textContent = filtered.length;

  if (filtered.length === 0) {
    $detectBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-slate-500">${allDetectionResults.length === 0 ? "No logs to analyze" : "No results match your filters"}</td></tr>`;
    return;
  }

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

$filterThreat.addEventListener("change", applyFilters);
$filterIP.addEventListener("input", applyFilters);

$btnDetect.addEventListener("click", async () => {
  if (detectionInProgress) {
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

    allDetectionResults = response.analyzed_events || [];
    applyFilters();

    if (response.cancelled) {
      alert(`Stopped! Analyzed ${response.analyzed_count.toLocaleString()} of ${response.total_logs.toLocaleString()} logs.`);
    } else {
      alert(`Analyzed ${response.analyzed_count.toLocaleString()} logs!`);
    }
  } catch (err) {
    alert("Detection failed: " + err.message);
  } finally {
    detectionInProgress = false;
    $btnDetect.disabled = false;
    $btnDetect.innerHTML = `<i class="fa-solid fa-radar mr-1"></i> Run Detection`;
    $btnDetect.className = $btnDetect.className.replace("bg-red-600", "bg-blue-600");
  }
});
