(() => {
  "use strict";

  const invoke = (...args) => {
    try { return window.__TAURI__.core.invoke(...args); }
    catch { return Promise.reject(new Error("Tauri runtime not available")); }
  };

  let processes = [];
  let filteredProcesses = [];
  let activePids = new Set();
  let isLoading = true;
  let pollingInterval = null;
  let autoTunnelNames = [];
  let isTunnelStarted = false;
  let isEngineRunning = false;

  const $ = (sel) => document.querySelector(sel);
  const statusPill = $("#statusPill");
  const statusLabel = $("#statusLabel");
  const searchInput = $("#searchInput");
  const refreshBtn = $("#refreshBtn");
  const settingsBtn = $("#settingsBtn");
  const processTableBody = $("#processTableBody");
  const processCount = $("#processCount");
  const emptyState = $("#emptyState");
  const emptyStateText = $("#emptyStateText");
  const toastContainer = $("#toastContainer");
  const masterTunnelBtn = $("#masterTunnelBtn");
  const winMinimizeBtn = $("#winMinimizeBtn");
  const winCloseBtn = $("#winCloseBtn");

  const selectAllCheckbox = $("#selectAllCheckbox");
  const tunnelSelectedBtn = $("#tunnelSelectedBtn");
  const stopSelectedBtn = $("#stopSelectedBtn");
  const actionsBtn = $("#actionsBtn");
  const actionsDropdown = $("#actionsDropdown");
  const autoTunnelInput = $("#autoTunnelInput");
  const autoTunnelAddBtn = $("#autoTunnelAddBtn");
  const autoTunnelTags = $("#autoTunnelTags");
  const autoTunnelCount = $("#autoTunnelCount");

  const proxyModal = $("#proxyModal");
  const proxyModalBackdrop = $("#proxyModalBackdrop");
  const proxyModalClose = $("#proxyModalClose");
  const proxyEnabled = $("#proxyEnabled");
  const proxyEnabledLabel = $("#proxyEnabledLabel");
  const proxyHost = $("#proxyHost");
  const proxyPort = $("#proxyPort");
  const proxyUsername = $("#proxyUsername");
  const proxyPassword = $("#proxyPassword");
  const proxySave = $("#proxySave");
  const proxyCancel = $("#proxyCancel");
  const proxyTest = $("#proxyTest");
  const proxyTestStatus = $("#proxyTestStatus");

  const statConnectionsValue = document.getElementById("statConnectionsValue");

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    showSkeletonLoading();
    bindEvents();
    await fetchProcesses();
    await fetchAutoTunnelNames();
    startStatusPolling();
  }

  function bindEvents() {
    searchInput.addEventListener("input", applyFilter);
    refreshBtn.addEventListener("click", onRefresh);
    settingsBtn.addEventListener("click", openProxyModal);

    masterTunnelBtn.addEventListener("click", toggleMasterTunnel);
    winMinimizeBtn.addEventListener("click", () => {
      const { getCurrentWindow } = window.__TAURI__.window;
      getCurrentWindow().minimize();
    });
    winCloseBtn.addEventListener("click", () => {
      const { getCurrentWindow } = window.__TAURI__.window;
      getCurrentWindow().close();
    });

    selectAllCheckbox.addEventListener("change", toggleSelectAll);
    tunnelSelectedBtn.addEventListener("click", tunnelSelected);
    stopSelectedBtn.addEventListener("click", stopSelected);

    actionsBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      actionsDropdown.classList.toggle("dropdown--open");
    });
    document.addEventListener("click", () => {
      actionsDropdown.classList.remove("dropdown--open");
    });

    autoTunnelAddBtn.addEventListener("click", addAutoTunnelRule);
    autoTunnelInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") addAutoTunnelRule();
    });

    proxyModalBackdrop.addEventListener("click", closeProxyModal);
    proxyModalClose.addEventListener("click", closeProxyModal);
    proxyCancel.addEventListener("click", closeProxyModal);
    proxySave.addEventListener("click", saveProxyConfig);
    proxyTest.addEventListener("click", testProxyConnection);

    proxyEnabled.addEventListener("change", () => {
      proxyEnabledLabel.textContent = proxyEnabled.checked ? "On" : "Off";
    });


    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        searchInput.focus();
        searchInput.select();
      }
      if (e.key === "Escape") {
        actionsDropdown.classList.remove("dropdown--open");
        if (!proxyModal.hidden) closeProxyModal();
        else if (document.activeElement === searchInput) searchInput.blur();
      }
    });
  }

  async function fetchProcesses() {
    isLoading = true;
    showSkeletonLoading();
    try {
      const apps = await invoke("get_running_apps");
      processes = Array.isArray(apps) ? apps : [];
      processes.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    } catch (err) {
      processes = [];
      showToast(`Failed to load processes: ${err.message || err}`, "error");
    }
    isLoading = false;
    applyFilter();
  }

  function applyFilter() {
    const q = searchInput.value.trim().toLowerCase();
    filteredProcesses = q
      ? processes.filter((p) => {
        const name = (p.name || "").toLowerCase();
        return name.includes(q) || String(p.pid || "").includes(q);
      })
      : [...processes];
    renderProcessList();
  }

  function renderProcessList() {
    processTableBody.innerHTML = "";

    if (filteredProcesses.length === 0) {
      emptyState.hidden = false;
      emptyStateText.textContent = searchInput.value.trim() ? "No matching processes" : "No processes found";
      processCount.textContent = "0";
      return;
    }

    emptyState.hidden = true;
    processCount.textContent = `${filteredProcesses.length}`;

    selectAllCheckbox.checked = false;
    updateBatchButtons();

    const frag = document.createDocumentFragment();

    filteredProcesses.forEach((proc) => {
      const tr = document.createElement("tr");
      tr.className = "process-row";
      const isActive = activePids.has(proc.pid);
      if (isActive) tr.classList.add("process-row--active");

      const tdCheck = document.createElement("td");
      tdCheck.className = "col-check";
      const chk = document.createElement("input");
      chk.type = "checkbox";
      chk.className = "process-checkbox";
      chk.dataset.pid = proc.pid;
      chk.addEventListener("change", updateBatchButtons);
      tdCheck.appendChild(chk);

      const tdName = document.createElement("td");
      tdName.className = "process-name";
      tdName.title = proc.exe_path || "";
      if (proc.icon) {
        const imgSrc = proc.icon.startsWith("data:") ? proc.icon : `data:image/png;base64,${proc.icon}`;
        tdName.innerHTML = `<img class="process-name__img-icon" src="${imgSrc}" alt="" /><span class="process-name__text">${esc(proc.name || "Unknown")}</span>`;
      } else {
        tdName.innerHTML = `<span class="process-name__icon">${(proc.name || "?")[0].toUpperCase()}</span><span class="process-name__text">${esc(proc.name || "Unknown")}</span>`;
      }

      const tdPid = document.createElement("td");
      tdPid.className = "process-pid";
      tdPid.textContent = proc.pid;

      const tdAction = document.createElement("td");
      tdAction.className = "process-action";
      const btn = document.createElement("button");
      btn.className = "tunnel-btn";
      btn.type = "button";
      if (isActive) {
        btn.classList.add("tunnel-btn--stop");
        btn.textContent = "Stop";
        btn.addEventListener("click", () => stopTunnel(proc.pid, proc.name));
      } else {
        btn.classList.add("tunnel-btn--start");
        btn.textContent = "Tunnel";
        btn.addEventListener("click", () => startTunnel(proc.pid, proc.name));
      }
      tdAction.appendChild(btn);

      tr.appendChild(tdCheck);
      tr.appendChild(tdName);
      tr.appendChild(tdPid);
      tr.appendChild(tdAction);
      frag.appendChild(tr);
    });

    processTableBody.appendChild(frag);
  }

  function showSkeletonLoading() {
    processTableBody.innerHTML = "";
    emptyState.hidden = true;
    processCount.textContent = "…";
    const frag = document.createDocumentFragment();
    for (let i = 0; i < 8; i++) {
      const tr = document.createElement("tr");
      tr.className = "skeleton-row";
      tr.innerHTML = `<td></td><td><div class="skeleton skeleton--name"></div></td><td><div class="skeleton skeleton--pid"></div></td><td><div class="skeleton skeleton--btn"></div></td>`;
      frag.appendChild(tr);
    }
    processTableBody.appendChild(frag);
  }

  async function startTunnel(pid, name) {
    try {
      await invoke("start_tunnel", { pid });
      activePids.add(pid);
      updateStatusPill();
      renderProcessList();
      showToast(`Tunnel started: ${name || pid}`, "success");
    } catch (err) {
      showToast(`Failed: ${err.message || err}`, "error");
    }
  }

  async function stopTunnel(pid, name) {
    try {
      await invoke("stop_tunnel", { pid });
      activePids.delete(pid);
      updateStatusPill();
      renderProcessList();
      showToast(`Tunnel stopped: ${name || pid}`, "success");
    } catch (err) {
      showToast(`Failed: ${err.message || err}`, "error");
    }
  }



  async function toggleMasterTunnel() {
    try {
      const nextState = !isTunnelStarted;
      await invoke("set_global_tunnel_active", { active: nextState });
      isTunnelStarted = nextState;
      updateMasterTunnelBtnState();
      showToast(nextState ? "Tunnel started" : "Tunnel stopped", "success");
    } catch (err) {
      showToast(`Failed: ${err.message || err}`, "error");
    }
  }

  function updateMasterTunnelBtnState() {
    if (isTunnelStarted) {
      masterTunnelBtn.className = "btn btn--tunnel-toggle btn--tunnel-stop";
      masterTunnelBtn.textContent = "Stop Tunnel";
    } else {
      masterTunnelBtn.className = "btn btn--tunnel-toggle btn--tunnel-start";
      masterTunnelBtn.textContent = "Start Tunnel";
    }
  }

  function startStatusPolling() {
    if (pollingInterval) clearInterval(pollingInterval);
    pollingInterval = setInterval(pollStatus, 2000);
    pollStatus();
  }

  async function pollStatus() {
    try {
      const status = await invoke("get_tunnel_status");

      const serverTunnelStarted = !!(status && status.tunnel_started);
      const serverEngineRunning = !!(status && status.engine_running);
      const newPids = new Set(status && status.active_pids ? status.active_pids : []);

      let changed = newPids.size !== activePids.size || [...newPids].some((pid) => !activePids.has(pid));
      if (serverTunnelStarted !== isTunnelStarted || serverEngineRunning !== isEngineRunning) {
        isTunnelStarted = serverTunnelStarted;
        isEngineRunning = serverEngineRunning;
        updateMasterTunnelBtnState();
        changed = true;
      }

      if (changed) {
        activePids = newPids;
        updateStatusPill();
        renderProcessList();
      }
      if (statConnectionsValue && status) {
        statConnectionsValue.textContent = status.nat_entries || 0;
      }
    } catch {
      // ignore polling errors when service is down
    }
  }

  function updateStatusPill() {
    const n = activePids.size;
    if (!isTunnelStarted) {
      statusPill.classList.remove("status--active");
      statusLabel.textContent = "Stopped";
    } else if (isEngineRunning && n > 0) {
      statusPill.classList.add("status--active");
      statusLabel.textContent = n === 1 ? "1 tunnel" : `${n} tunnels`;
    } else {
      statusPill.classList.remove("status--active");
      statusLabel.textContent = "Idle";
    }
  }

  async function onRefresh() {
    refreshBtn.disabled = true;
    refreshBtn.classList.add("btn--spinning");
    await fetchProcesses();
    setTimeout(() => {
      refreshBtn.classList.remove("btn--spinning");
      refreshBtn.disabled = false;
    }, 400);
  }

  async function openProxyModal() {
    try {
      const c = await invoke("get_proxy_config");
      proxyEnabled.checked = c.enabled || false;
      proxyEnabledLabel.textContent = c.enabled ? "On" : "Off";
      proxyHost.value = c.host || "";
      proxyPort.value = c.port || 1080;
      proxyUsername.value = c.username || "";
      proxyPassword.value = c.password || "";
    } catch {
      proxyEnabled.checked = false;
      proxyEnabledLabel.textContent = "Off";
      proxyHost.value = "";
      proxyPort.value = 1080;
      proxyUsername.value = "";
      proxyPassword.value = "";
    }
    proxyModal.hidden = false;
    proxyTestStatus.textContent = "";
    proxyTestStatus.className = "modal__test-status";
  }

  function closeProxyModal() { proxyModal.hidden = true; }

  async function saveProxyConfig() {
    const config = {
      enabled: proxyEnabled.checked,
      host: proxyHost.value.trim(),
      port: parseInt(proxyPort.value, 10) || 1080,
      username: proxyUsername.value.trim() || null,
      password: proxyPassword.value || null,
    };
    try {
      await invoke("set_proxy_config", { config });
      closeProxyModal();
      showToast(config.enabled ? `Proxy: ${config.host}:${config.port}` : "Proxy disabled", "success");
    } catch (err) {
      showToast(`Save failed: ${err.message || err}`, "error");
    }
  }

  async function testProxyConnection() {
    const config = {
      enabled: true,
      host: proxyHost.value.trim(),
      port: parseInt(proxyPort.value, 10) || 1080,
      username: proxyUsername.value.trim() || null,
      password: proxyPassword.value || null,
    };
    if (!config.host) {
      proxyTestStatus.textContent = "Enter host first";
      proxyTestStatus.className = "modal__test-status modal__test-status--error";
      return;
    }
    proxyTest.disabled = true;
    proxyTestStatus.textContent = "Connecting…";
    proxyTestStatus.className = "modal__test-status modal__test-status--loading";
    try {
      const r = await invoke("test_proxy_connection", { config });
      if (r.ok) {
        proxyTestStatus.textContent = `OK (${r.latency_ms}ms)`;
        proxyTestStatus.className = "modal__test-status modal__test-status--success";
      } else {
        proxyTestStatus.textContent = r.error;
        proxyTestStatus.className = "modal__test-status modal__test-status--error";
      }
    } catch (err) {
      proxyTestStatus.textContent = err.message || err;
      proxyTestStatus.className = "modal__test-status modal__test-status--error";
    } finally {
      proxyTest.disabled = false;
    }
  }

  function toggleSelectAll() {
    const on = selectAllCheckbox.checked;
    processTableBody.querySelectorAll(".process-checkbox").forEach((c) => { c.checked = on; });
    updateBatchButtons();
  }

  function updateBatchButtons() {
    const n = processTableBody.querySelectorAll(".process-checkbox:checked").length;
    actionsBtn.disabled = n === 0;
    if (n === 0) actionsDropdown.classList.remove("dropdown--open");
  }

  async function tunnelSelected() {
    actionsDropdown.classList.remove("dropdown--open");
    const pids = Array.from(processTableBody.querySelectorAll(".process-checkbox:checked")).map((c) => parseInt(c.dataset.pid, 10));
    if (!pids.length) return;
    try {
      await invoke("start_tunnels", { pids });
      pids.forEach((p) => activePids.add(p));
      selectAllCheckbox.checked = false;
      updateStatusPill();
      renderProcessList();
      showToast(`${pids.length} tunnel(s) started`, "success");
    } catch (err) {
      showToast(`Batch failed: ${err.message || err}`, "error");
    }
  }

  async function stopSelected() {
    actionsDropdown.classList.remove("dropdown--open");
    const pids = Array.from(processTableBody.querySelectorAll(".process-checkbox:checked")).map((c) => parseInt(c.dataset.pid, 10));
    if (!pids.length) return;
    try {
      await invoke("stop_tunnels", { pids });
      pids.forEach((p) => activePids.delete(p));
      selectAllCheckbox.checked = false;
      updateStatusPill();
      renderProcessList();
      showToast(`${pids.length} tunnel(s) stopped`, "success");
    } catch (err) {
      showToast(`Batch failed: ${err.message || err}`, "error");
    }
  }

  async function fetchAutoTunnelNames() {
    try {
      const names = await invoke("get_auto_tunnel_names");
      autoTunnelNames = Array.isArray(names) ? names : [];
      renderAutoTunnelTags();
    } catch (err) {
      showToast(`Failed to load rules: ${err.message || err}`, "error");
    }
  }

  async function addAutoTunnelRule() {
    const name = autoTunnelInput.value.trim();
    if (!name) return;
    if (autoTunnelNames.some((t) => t.toLowerCase() === name.toLowerCase())) {
      showToast(`"${name}" already exists`, "error");
      return;
    }
    const updated = [...autoTunnelNames, name];
    try {
      await invoke("set_auto_tunnel_names", { names: updated });
      autoTunnelNames = updated;
      autoTunnelInput.value = "";
      renderAutoTunnelTags();
      showToast(`Rule added: ${name}`, "success");
    } catch (err) {
      showToast(`Failed: ${err.message || err}`, "error");
    }
  }

  async function removeAutoTunnelRule(name) {
    const updated = autoTunnelNames.filter((t) => t !== name);
    try {
      await invoke("set_auto_tunnel_names", { names: updated });
      autoTunnelNames = updated;
      renderAutoTunnelTags();
      showToast(`Rule removed: ${name}`, "success");
    } catch (err) {
      showToast(`Failed: ${err.message || err}`, "error");
    }
  }

  function renderAutoTunnelTags() {
    autoTunnelTags.innerHTML = "";
    autoTunnelCount.textContent = autoTunnelNames.length;
    if (autoTunnelNames.length === 0) {
      autoTunnelTags.innerHTML = `<span style="color:var(--text-3);font-size:11px;">No rules. Add one above.</span>`;
      return;
    }
    autoTunnelNames.forEach((name) => {
      const tag = document.createElement("span");
      tag.className = "tag";
      tag.textContent = name + " ";
      const x = document.createElement("button");
      x.className = "tag__close";
      x.type = "button";
      x.innerHTML = "&times;";
      x.addEventListener("click", () => removeAutoTunnelRule(name));
      tag.appendChild(x);
      autoTunnelTags.appendChild(tag);
    });
  }

  function showToast(message, type = "error") {
    const toast = document.createElement("div");
    toast.className = `toast toast--${type}`;
    const iconSvg = type === "error"
      ? `<svg class="toast__icon" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.2"/><path d="M8 5v3.5M8 11v.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`
      : `<svg class="toast__icon" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.2"/><path d="M5.5 8l2 2 3-3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
    toast.innerHTML = `${iconSvg}<span class="toast__message">${esc(message)}</span>`;
    toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.classList.add("toast--exiting");
      toast.addEventListener("animationend", () => toast.remove(), { once: true });
    }, 3500);
  }

  function esc(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }
})();
