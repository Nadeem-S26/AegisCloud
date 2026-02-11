const API = "http://localhost:8000";
function safeNumber(val) {
  const num = Number(val) || 0;
  return isNaN(num) ? 0 : num;
}

function formatNumber(val) {
  return safeNumber(val).toLocaleString();
}
const $logsBody = document.getElementById("logsBody");
const $logsCount = document.getElementById("logsCount");
const $btnRefreshLogs = document.getElementById("btnRefreshLogs");
const $btnClearLogs = document.getElementById("btnClearLogs");

async function api(path, opts = {}) {
  try {
    const url = `${API}${path}`;
    console.log("Fetching:", url);
    const res = await fetch(url, {
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    console.log("Response status:", res.status);
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  } catch (error) {
    console.error("API fetch failed:", error);
    throw error;
  }
}

async function refreshLogs() {
  try {
    const logs = await api("/logs");
    $logsCount.textContent = logs.length;

    if (logs.length === 0) {
      $logsBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-slate-500">No logs yet</td></tr>`;
      return;
    }

    const recent = logs.slice(-50).reverse();
    $logsBody.innerHTML = recent.map(l => {
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
    $logsBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-slate-500">Failed to load logs</td></tr>`;
  }
}

$btnRefreshLogs.addEventListener("click", refreshLogs);

$btnClearLogs.addEventListener("click", async () => {
  const ok = confirm("Clear all logs and alerts? This cannot be undone.");
  if (!ok) return;

  try {
    await api("/logs/clear", { method: "POST", body: JSON.stringify({ clear_alerts: true }) });
    refreshLogs();
  } catch (e) {
    console.error("Clear logs failed:", e);
    alert("Failed to clear logs: " + e.message);
  }
});

refreshLogs();
