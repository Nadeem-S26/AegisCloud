const API = "http://localhost:8000";

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
