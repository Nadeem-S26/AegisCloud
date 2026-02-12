// ═══════════════════════════════════════════════════════════
//  Sidebar Toggle – Universal Init
// ═══════════════════════════════════════════════════════════

(function initSidebarToggle() {
  const sidebar = document.getElementById("sidebar");
  const sidebarToggle = document.getElementById("sidebarToggle");
  const mainContent = document.querySelector(".main-content");

  if (!sidebar || !sidebarToggle) return;

  // Load sidebar state from localStorage
  const isCollapsed = localStorage.getItem("sidebarCollapsed") === "true";
  if (isCollapsed) {
    sidebar.classList.add("collapsed");
    if (mainContent) mainContent.classList.add("sidebar-collapsed");
  }

  // Toggle sidebar
  sidebarToggle.addEventListener("click", () => {
    sidebar.classList.toggle("collapsed");
    if (mainContent) mainContent.classList.toggle("sidebar-collapsed");
    const collapsed = sidebar.classList.contains("collapsed");
    localStorage.setItem("sidebarCollapsed", collapsed);
  });
})();
