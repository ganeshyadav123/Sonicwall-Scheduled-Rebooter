/* ============================================
   SonicWall Firewall Reboot Scheduler
   Application Logic — Per-Firewall Scheduling
   ============================================ */

const API_BASE = (window.location.protocol.startsWith('http'))
  ? (window.location.port === '5000' ? `${window.location.origin}/api` : `${window.location.protocol}//${window.location.hostname}:5000/api`)
  : 'http://localhost:5000/api';

// Safe Event Binder Helper
function on(element, event, callback) {
  if (element) {
    element.addEventListener(event, callback);
  } else {
    console.warn(`Element for event "${event}" is missing or null.`);
  }
}

// ─── State ──────────────────────────────────
const state = {
  firewalls: [],
  selectedIds: new Set(),
  sites: [],
  activeSite: 'all',
  searchQuery: '',
  currentStep: 0,
  isRunning: false,
  results: {},
  sseSource: null,
  // Per-firewall schedule: { _id: { mode: 'at'|'now', date: '2026-01-01', time: '03:00' } }
  schedules: {},
  // Uptime results: { _id: { status, message } }
  uptimeResults: {},
  timezoneResults: {},
  uptimeSse: null,
  isUptimeRunning: false,
  // Schedule check/cancel results: { _id: { status, message, hasSchedule } }
  scheduleCheckResults: {},
  scheduleSse: null,
  isScheduleRunning: false,
  isTimezoneRunning: false,
  timezoneSse: null,
  // ID mappings for SSE to avoid cross-feature overlap collisions
  uptimeIdMap: {},
  timezoneIdMap: {},
  scheduleIdMap: {},
  rebootIdMap: {},
};

// ─── DOM References ─────────────────────────
const dom = {};
document.addEventListener('DOMContentLoaded', () => {
  // Cache Detection
  if (!document.getElementById('encrypt-success-area')) {
    const warning = document.createElement('div');
    warning.id = 'cache-warning-banner';
    warning.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#ef4444;color:#fff;text-align:center;padding:12px;z-index:99999;font-weight:bold;font-size:16px;box-shadow:0 4px 12px rgba(0,0,0,0.3);';
    warning.innerHTML = '⚠️ Your browser is running a cached version of the app. Please press Ctrl+F5 (Cmd+Shift+R) or clear your browser cache to load the latest features!';
    document.body.prepend(warning);
  }

  // Header
  dom.backendDot = document.getElementById('backend-dot');
  dom.backendText = document.getElementById('backend-status-text');
  // Stepper
  dom.stepperItems = document.querySelectorAll('.stepper-item');
  dom.connectors = [document.getElementById('connector-0-1'), document.getElementById('connector-1-2'), document.getElementById('connector-2-3')];
  // Panels
  dom.panels = [document.getElementById('step-upload'), document.getElementById('step-select'), document.getElementById('step-schedule'), document.getElementById('step-execute')];
  // Step 1
  dom.uploadZone = document.getElementById('upload-drop-zone');
  dom.fileInput = document.getElementById('csv-file-input');
  dom.btnBrowse = document.getElementById('btn-browse-files');
  dom.fileLoadedInfo = document.getElementById('file-loaded-info');
  dom.loadedFileName = document.getElementById('loaded-file-name');
  dom.loadedFwCount = document.getElementById('loaded-fw-count');
  dom.btnDownloadSample = document.getElementById('btn-download-sample');
  dom.btnStep1Next = document.getElementById('btn-step1-next');
  // Step 2
  dom.siteFilterBar = document.getElementById('site-filter-bar');
  dom.searchInput = document.getElementById('search-firewall-input');
  dom.btnGetUptime = document.getElementById('btn-get-uptime');
  dom.btnGetTimezone = document.getElementById('btn-get-timezone');
  dom.btnExportUptime = document.getElementById('btn-export-uptime');
  dom.btnCheckSchedules = document.getElementById('btn-check-schedules');
  dom.btnCancelSchedules = document.getElementById('btn-cancel-schedules');
  dom.btnSelectAll = document.getElementById('opt-select-all');
  dom.btnDeselectAll = document.getElementById('opt-deselect-all');
  dom.btnSelectFiltered = document.getElementById('opt-select-filtered');
  dom.selectedCountDisplay = document.getElementById('selected-count-display');
  dom.totalFwCount = document.getElementById('total-fw-count');
  dom.firewallTableBody = document.getElementById('firewall-table-body');
  dom.headerSelectAllCb = document.getElementById('header-select-all-cb');
  dom.firewallEmptyState = document.getElementById('firewall-empty-state');
  dom.firewallTableScroll = document.getElementById('firewall-table-scroll');
  dom.btnStep2Back = document.getElementById('btn-step2-back');
  dom.btnStep2Next = document.getElementById('btn-step2-next');
  // Step 3
  dom.pillSchedule = document.getElementById('pill-schedule');
  dom.pillNow = document.getElementById('pill-now');
  dom.quickDateInput = document.getElementById('quick-date-input');
  dom.quickTimeInput = document.getElementById('quick-time-input');
  dom.quickInterval = document.getElementById('quick-interval-input');
  dom.btnApplyAll = document.getElementById('btn-apply-all');
  
  dom.scheduleTableBody = document.getElementById('schedule-table-body');
  dom.summaryFwCount = document.getElementById('summary-fw-count');
  dom.summaryScheduledCount = document.getElementById('summary-scheduled-count');
  dom.summaryNowCount = document.getElementById('summary-now-count');
  dom.btnStep3Back = document.getElementById('btn-step3-back');
  dom.btnStep3Execute = document.getElementById('btn-step3-execute');
  // Step 4
  dom.statTotal = document.getElementById('stat-total');
  dom.statCompleted = document.getElementById('stat-completed');
  dom.statSuccess = document.getElementById('stat-success');
  dom.statFailed = document.getElementById('stat-failed');
  dom.progressLabel = document.getElementById('progress-status-label');
  dom.progressPercent = document.getElementById('progress-percent-text');
  dom.progressFill = document.getElementById('progress-fill-bar');
  dom.resultsTableBody = document.getElementById('results-table-body');
  dom.btnCancelExecution = document.getElementById('btn-cancel-execution');
  dom.btnExportResults = document.getElementById('btn-export-results');
  dom.btnStartOver = document.getElementById('btn-start-over');
  // Modal
  dom.confirmModal = document.getElementById('confirm-modal');
  dom.modalFwCount = document.getElementById('modal-fw-count');
  dom.btnModalCancel = document.getElementById('btn-modal-cancel');
  dom.btnModalConfirm = document.getElementById('btn-modal-confirm');
  // Toast
  dom.toastContainer = document.getElementById('toast-container');

  // Settings DOM references
  dom.settingsModal = document.getElementById('settings-modal');
  dom.btnSettingsToggle = document.getElementById('btn-settings-toggle');
  dom.btnSettingsSave = document.getElementById('btn-settings-save');
  dom.btnSettingsCancel = document.getElementById('btn-settings-cancel');
  dom.btnSettingsTest = document.getElementById('btn-settings-test');
  
  dom.settingSmtpServer = document.getElementById('setting-smtp-server');
  dom.settingSmtpPort = document.getElementById('setting-smtp-port');
  dom.settingSmtpUsername = document.getElementById('setting-smtp-username');
  dom.settingSmtpPassword = document.getElementById('setting-smtp-password');
  dom.settingRecipientEmail = document.getElementById('setting-recipient-email');
  dom.settingEnableEmails = document.getElementById('setting-enable-emails');
  dom.settingEnableMonitoring = document.getElementById('setting-enable-monitoring');
  dom.settingMonitoringTimeout = document.getElementById('setting-monitoring-timeout');
  dom.timeoutConfigWrapper = document.getElementById('timeout-config-wrapper');

  checkBackendStatus();
  setDefaultQuickDatetime();
  bindEvents();
});

function bindEvents() {
  // Upload
  on(dom.uploadZone, 'click', (e) => { if (!e.target.closest('button')) dom.fileInput.click(); });
  on(dom.btnBrowse, 'click', (e) => { e.stopPropagation(); dom.fileInput.click(); });
  on(dom.fileInput, 'change', handleFileSelect);
  on(dom.uploadZone, 'dragover', (e) => { e.preventDefault(); dom.uploadZone.classList.add('drag-over'); });
  on(dom.uploadZone, 'dragleave', () => dom.uploadZone.classList.remove('drag-over'));
  on(dom.uploadZone, 'drop', handleFileDrop);
  on(dom.btnDownloadSample, 'click', downloadSampleCSV);
  // Step nav
  on(dom.btnStep1Next, 'click', () => goToStep(1));
  on(dom.btnStep2Back, 'click', () => goToStep(0));
  on(dom.btnStep2Next, 'click', () => goToStep(2));
  on(dom.btnStep3Back, 'click', () => goToStep(1));
  on(dom.btnStep3Execute, 'click', showConfirmModal);
  if (dom.stepperItems) {
    dom.stepperItems.forEach((item) => {
      on(item, 'click', () => { const s = parseInt(item.dataset.step, 10); if (s < state.currentStep) goToStep(s); });
    });
  }
  // Selection
  on(dom.btnSelectAll, 'click', (e) => { e.preventDefault(); selectAll(); });
  on(dom.btnDeselectAll, 'click', (e) => { e.preventDefault(); deselectAll(); });
  on(dom.btnSelectFiltered, 'click', (e) => { e.preventDefault(); selectFiltered(); });
  
  // Selection Options Dropdown Toggle
  const selectToggle = document.getElementById('btn-select-options');
  const selectMenu = document.getElementById('select-options-menu');
  if (selectToggle && selectMenu) {
    on(selectToggle, 'click', (e) => {
      e.stopPropagation();
      selectMenu.classList.toggle('show');
    });
    on(document, 'click', () => {
      selectMenu.classList.remove('show');
    });
  }
  on(dom.headerSelectAllCb, 'change', () => { if (dom.headerSelectAllCb.checked) selectFiltered(); else deselectAll(); });
  // Search
  on(dom.searchInput, 'input', debounce((e) => { state.searchQuery = e.target.value.trim().toLowerCase(); renderFirewallTable(); }, 200));
  // Uptime
  on(dom.btnGetUptime, 'click', getUptime);
  on(dom.btnGetTimezone, 'click', getTimezone);
  on(dom.btnExportUptime, 'click', exportUptimeResults);
  // Schedules check & cancel
  on(dom.btnCheckSchedules, 'click', checkSchedules);
  on(dom.btnCancelSchedules, 'click', () => cancelSchedules(true));
  // Quick apply
  on(dom.pillSchedule, 'click', () => setQuickMode('at'));
  on(dom.pillNow, 'click', () => setQuickMode('now'));
  if (dom.quickDateInput) on(dom.quickDateInput, 'change', (e) => e.target.blur());
  if (dom.quickTimeInput) on(dom.quickTimeInput, 'change', (e) => e.target.blur());
  on(dom.btnApplyAll, 'click', applyScheduleToAll);
  // Modal
  on(dom.btnModalCancel, 'click', hideConfirmModal);
  on(dom.btnModalConfirm, 'click', executeReboot);
  on(dom.confirmModal, 'click', (e) => { if (e.target === dom.confirmModal) hideConfirmModal(); });
  // Execute actions
  on(dom.btnCancelExecution, 'click', cancelExecution);
  on(dom.btnExportResults, 'click', exportResults);
  on(dom.btnStartOver, 'click', startOver);

  // Clear Data Button
  const btnClearMem = document.getElementById('btn-clear-memory');
  on(btnClearMem, 'click', clearAllData);

  // Decrypt Modal Bindings
  const decryptModal = document.getElementById('decrypt-modal');
  const btnDecryptConfirm = document.getElementById('btn-decrypt-confirm');
  const btnDecryptCancel = document.getElementById('btn-decrypt-cancel');
  const decryptPassInp = document.getElementById('decrypt-passphrase-input');

  if (decryptModal) {
    decryptModal.addEventListener('click', (e) => {
      if (e.target === decryptModal) decryptModal.classList.remove('visible');
    });
  }

  if (btnDecryptCancel) btnDecryptCancel.addEventListener('click', () => decryptModal.classList.remove('visible'));
  if (btnDecryptConfirm) {
    btnDecryptConfirm.addEventListener('click', async () => {
      const pass = decryptPassInp.value.trim();
      if (!pass) { showToast('Please enter passphrase', 'warning'); return; }

      const origText = btnDecryptConfirm.textContent;
      btnDecryptConfirm.disabled = true;
      const startTime = performance.now();
      const timerInterval = setInterval(() => {
        const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
        btnDecryptConfirm.textContent = `Decrypting... (${elapsed}s)`;
      }, 100);

      try {
        const decryptedCSV = await cryptoDecrypt(pendingEncryptedContent, pass);
        const totalSecs = ((performance.now() - startTime) / 1000).toFixed(2);

        // Parse decrypted CSV string
        Papa.parse(decryptedCSV, {
          header: true, skipEmptyLines: true, transformHeader: (h) => h.trim(),
          complete: (results) => {
            clearInterval(timerInterval);
            btnDecryptConfirm.disabled = false;
            btnDecryptConfirm.textContent = origText;

            const required = ['Name', 'IP', 'Port', 'Username', 'Password', 'Site'];
            const headers = results.meta.fields || [];
            const missing = required.filter((c) => !headers.some((h) => h.toLowerCase() === c.toLowerCase()));
            if (missing.length > 0) { showToast(`Missing columns: ${missing.join(', ')}`, 'error'); return; }
            const firewalls = [];
            results.data.forEach((row, idx) => {
              const fw = {};
              required.forEach((c) => {
                const h = headers.find((hh) => hh.toLowerCase() === c.toLowerCase());
                fw[c] = (row[h] || '').trim();
              });
              if (fw.IP && fw.Name) { fw._id = idx; firewalls.push(fw); }
            });
            state.firewalls = firewalls;
            state.sites = [...new Set(state.firewalls.map((fw) => fw.Site).filter(Boolean))].sort();
            state.selectedIds.clear();
            state.activeSite = 'all';
            state.searchQuery = '';
            state.schedules = {};
            state.uptimeResults = {};
            dom.loadedFileName.textContent = pendingEncryptedFileName;
            dom.loadedFwCount.textContent = state.firewalls.length;
            dom.fileLoadedInfo.classList.remove('hidden');
            dom.btnStep1Next.disabled = false;
            decryptModal.classList.remove('visible');
            showToast(`Unlocked ${state.firewalls.length} firewalls in ${totalSecs}s!`, 'success');
            setTimeout(() => goToStep(1), 600);
          }
        });
      } catch (err) {
        clearInterval(timerInterval);
        btnDecryptConfirm.disabled = false;
        btnDecryptConfirm.textContent = origText;
        showToast('Decryption failed! Incorrect passphrase or corrupted payload.', 'error');
      }
    });
  }

  // Encrypt Modal Bindings
  const openEncryptorLink = document.getElementById('btn-open-encryptor');
  const btnExportEncryptedStep2 = document.getElementById('btn-export-encrypted-step2');
  const encryptModal = document.getElementById('encrypt-modal');
  const btnEncryptConfirm = document.getElementById('btn-encrypt-confirm');
  const btnEncryptCancel = document.getElementById('btn-encrypt-cancel');
  const btnEncryptDone = document.getElementById('btn-encrypt-done');
  const encryptFileInput = document.getElementById('encrypt-file-input');
  const encryptFileWrapper = document.getElementById('encrypt-file-wrapper');
  const encryptSubtitle = document.getElementById('encrypt-modal-subtitle');
  const encryptPass1 = document.getElementById('encrypt-pass1-input');
  const encryptPass2 = document.getElementById('encrypt-pass2-input');
  const encryptFormArea = document.getElementById('encrypt-form-area');
  const encryptSuccessArea = document.getElementById('encrypt-success-area');
  const encryptDownloadLink = document.getElementById('encrypt-download-link');
  const encryptDownloadFilename = document.getElementById('encrypt-download-filename');
  const encryptSuccessInfo = document.getElementById('encrypt-success-info');

  // Track the current blob URL so we can revoke it when modal closes
  let _encryptBlobUrl = null;

  function _resetEncryptModal() {
    if (_encryptBlobUrl) { window.URL.revokeObjectURL(_encryptBlobUrl); _encryptBlobUrl = null; }
    if (encryptFileInput) encryptFileInput.value = '';
    if (encryptPass1) encryptPass1.value = '';
    if (encryptPass2) encryptPass2.value = '';
    if (encryptFormArea) encryptFormArea.style.display = 'block';
    if (encryptSuccessArea) encryptSuccessArea.style.display = 'none';
    if (btnEncryptConfirm) { btnEncryptConfirm.disabled = false; btnEncryptConfirm.textContent = '🔒 Encrypt & Save .enc'; }
  }

  function _closeEncryptModal() {
    _resetEncryptModal();
    if (encryptModal) encryptModal.classList.remove('visible');
  }

  const openEncryptModal = (e, fromStep2 = false) => {
    if (e) e.preventDefault();
    _resetEncryptModal();

    if (fromStep2 || (state.firewalls && state.firewalls.length > 0)) {
      if (encryptFileWrapper) encryptFileWrapper.style.display = 'none';
      if (encryptSubtitle) encryptSubtitle.innerHTML = `Encrypting <strong>${state.firewalls.length} loaded firewall${state.firewalls.length !== 1 ? 's' : ''}</strong> into an AES-256-GCM <code>.enc</code> file.`;
    } else {
      if (encryptFileWrapper) encryptFileWrapper.style.display = 'block';
      if (encryptSubtitle) encryptSubtitle.innerHTML = `Convert raw CSV export to AES-256-GCM encrypted <code>.enc</code> file.`;
    }

    if (encryptModal) encryptModal.classList.add('visible');
    // Focus first passphrase field
    setTimeout(() => { if (encryptPass1) encryptPass1.focus(); }, 150);
  };

  if (encryptModal) {
    encryptModal.addEventListener('click', (e) => {
      if (e.target === encryptModal) _closeEncryptModal();
    });
  }

  if (openEncryptorLink) openEncryptorLink.addEventListener('click', (e) => { e.preventDefault(); handleNativeEncrypt(false); });
  if (btnExportEncryptedStep2) btnExportEncryptedStep2.addEventListener('click', (e) => { e.preventDefault(); handleNativeEncrypt(true); });

  if (btnEncryptConfirm) {
    btnEncryptConfirm.addEventListener('click', async () => {
      const file = encryptFileInput ? encryptFileInput.files[0] : null;
      const p1 = encryptPass1 ? encryptPass1.value.trim() : '';
      const p2 = encryptPass2 ? encryptPass2.value.trim() : '';

      // --- Validation ---
      if (!p1 || p1.length < 12) {
        encryptPass1.style.borderColor = 'var(--color-error)';
        setTimeout(() => { encryptPass1.style.borderColor = ''; }, 2000);
        showToast('Passphrase must be at least 12 characters (uppercase, lowercase, digit, special char)!', 'error');
        encryptPass1.focus();
        return;
      }
      if (p1 !== p2) {
        encryptPass2.style.borderColor = 'var(--color-error)';
        setTimeout(() => { encryptPass2.style.borderColor = ''; }, 2000);
        showToast('Passphrases do not match!', 'error');
        encryptPass2.focus();
        return;
      }

      // --- Build CSV text ---
      let csvText = '';
      let defaultFileName = 'firewalls_inventory.csv';

      if (file) {
        defaultFileName = file.name;
        try {
          csvText = await new Promise((resolve, reject) => {
            const r = new FileReader();
            r.onload = (ev) => resolve(ev.target.result);
            r.onerror = (err) => reject(err);
            r.readAsText(file);
          });
        } catch (e) {
          showToast('Could not read the selected file!', 'error');
          return;
        }
      } else if (state.firewalls && state.firewalls.length > 0) {
        const rows = [['Name', 'IP', 'Port', 'Username', 'Password', 'Site']];
        state.firewalls.forEach((fw) => {
          rows.push([fw.Name, fw.IP, fw.Port, fw.Username, fw.Password, fw.Site]);
        });
        csvText = rows.map((r) => r.map((c) => `"${String(c || '').replace(/"/g, '""')}"`).join(',')).join('\n');
      } else {
        showToast('No CSV loaded and no file selected. Upload a CSV first!', 'error');
        return;
      }

      if (!csvText.trim()) {
        showToast('CSV content is empty!', 'error');
        return;
      }

      // --- Encrypt ---
      const origBtnText = btnEncryptConfirm.textContent;
      btnEncryptConfirm.disabled = true;
      const startTime = performance.now();
      const timerInterval = setInterval(() => {
        const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
        btnEncryptConfirm.textContent = `Encrypting… (${elapsed}s)`;
      }, 100);

      try {
        const res = await fetch(`${API_BASE}/export-enc`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ csv_text: csvText, passphrase: p1, filename: defaultFileName })
        });

        if (!res.ok) {
          let errMsg = `Server error ${res.status}`;
          try { const j = await res.json(); errMsg = j.error || errMsg; } catch(_) {}
          throw new Error(errMsg);
        }

        const blob = await res.blob();
        const totalSecs = ((performance.now() - startTime) / 1000).toFixed(2);
        clearInterval(timerInterval);
        btnEncryptConfirm.disabled = false;
        btnEncryptConfirm.textContent = origBtnText;

        // Build persistent download URL
        const outFilename = defaultFileName.replace(/\.csv$/i, '') + '_encrypted.enc';
        _encryptBlobUrl = window.URL.createObjectURL(blob);

        // Wire up the visible download link
        if (encryptDownloadLink) {
          encryptDownloadLink.href = _encryptBlobUrl;
          encryptDownloadLink.download = outFilename;
          if (encryptDownloadFilename) encryptDownloadFilename.textContent = outFilename;
        }
        if (encryptSuccessInfo) {
          encryptSuccessInfo.textContent = `${outFilename} encrypted in ${totalSecs}s — AES-256-GCM, PBKDF2-SHA256, 600,000 iterations, 256-bit salt.`;
        }

        // Switch modal view to success area
        if (encryptFormArea) encryptFormArea.style.display = 'none';
        if (encryptSuccessArea) encryptSuccessArea.style.display = 'block';

        // Trigger auto-download (may be blocked by browser — visible link is the fallback)
        const triggerA = document.createElement('a');
        triggerA.style.display = 'none';
        triggerA.href = _encryptBlobUrl;
        triggerA.download = outFilename;
        document.body.appendChild(triggerA);
        triggerA.click();
        document.body.removeChild(triggerA);

        showToast(`✅ Encrypted in ${totalSecs}s — click the green button in the popup to save!`, 'success');

      } catch (err) {
        clearInterval(timerInterval);
        btnEncryptConfirm.disabled = false;
        btnEncryptConfirm.textContent = origBtnText;
        console.error('Encryption error:', err);
        showToast(`❌ Encryption failed: ${err.message}`, 'error');
      }
    });
  }

  // Quick Interval change cascades schedules
  on(dom.quickInterval, 'change', () => {
    autoSpaceSchedules(0);
    renderScheduleTable();
    updateScheduleSummary();
  });

  // Settings Modal Bindings
  on(dom.btnSettingsToggle, 'click', showSettingsModal);
  on(dom.btnSettingsSave, 'click', saveSettings);
  on(dom.btnSettingsCancel, 'click', hideSettingsModal);
  on(dom.btnSettingsTest, 'click', testSettings);
  if (dom.settingEnableMonitoring) {
    on(dom.settingEnableMonitoring, 'change', () => {
      if (dom.timeoutConfigWrapper) {
        dom.timeoutConfigWrapper.style.display = dom.settingEnableMonitoring.checked ? 'block' : 'none';
      }
    });
  }
}

// ─── Backend Status ─────────────────────────
async function checkBackendStatus() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      if (dom.backendDot) dom.backendDot.className = 'status-dot online';
      if (dom.backendText) dom.backendText.textContent = 'Backend Online';
    }
    else throw new Error();
  } catch {
    if (dom.backendDot) dom.backendDot.className = 'status-dot offline';
    if (dom.backendText) dom.backendText.textContent = 'Backend Offline';
  }
}

// ─── Step Navigation ────────────────────────
function goToStep(n) {
  if (n > state.currentStep) {
    if (n >= 1 && state.firewalls.length === 0) { showToast('Upload a CSV first.', 'warning'); return; }
    if (n >= 2 && state.selectedIds.size === 0) { showToast('Select at least one firewall.', 'warning'); return; }
  }
  state.currentStep = n;
  dom.panels.forEach((p, i) => p.classList.toggle('active', i === n));
  dom.stepperItems.forEach((item, i) => { item.classList.remove('active', 'completed'); if (i < n) item.classList.add('completed'); else if (i === n) item.classList.add('active'); });
  dom.connectors.forEach((c, i) => c.classList.toggle('completed', i < n));
  if (n === 1) { renderSiteFilter(); renderFirewallTable(); updateSelectedCount(); }
  if (n === 2) { autoSpaceSchedules(0); renderScheduleTable(); updateScheduleSummary(); }
  if (n === 3) { prepareExecutionView(); }
}

// ─── AES-256 Backend PyCA Cryptography API ───────
async function cryptoEncrypt(csvText, passphrase) {
  const res = await fetch(`${API_BASE}/encrypt-csv`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ csv_text: csvText, passphrase: passphrase })
  });
  const data = await res.json();
  if (!res.ok || !data.ok) throw new Error(data.error || 'Encryption failed');
  return data.json_str;
}

async function cryptoDecrypt(encStr, passphrase) {
  const res = await fetch(`${API_BASE}/decrypt-csv`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enc_str: encStr, passphrase: passphrase })
  });
  const data = await res.json();
  if (!res.ok || !data.ok) throw new Error(data.error || 'Decryption failed');
  return data.csv_text;
}

// Global reference for pending encrypted file
let pendingEncryptedContent = null;
let pendingEncryptedFileName = '';

// --- Native Dialog Fallbacks (100% Reliable, z-index immune) ---
const PASS_RULES = 'Minimum 12 chars, must include: uppercase, lowercase, digit, special char (!@#$%^&*)';
function _checkPassStrength(p) {
  if (!p || p.trim().length < 12) return 'Passphrase must be at least 12 characters long!';
  if (!/[A-Z]/.test(p)) return 'Passphrase must contain at least one uppercase letter!';
  if (!/[a-z]/.test(p)) return 'Passphrase must contain at least one lowercase letter!';
  if (!/[0-9]/.test(p)) return 'Passphrase must contain at least one digit!';
  if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]/.test(p)) return 'Passphrase must contain at least one special character!';
  return '';
}
async function handleNativeEncrypt(fromStep2) {
  let csvText = '';
  let defaultFileName = 'firewalls_inventory.csv';

  if (!fromStep2) {
    // Step 1: Open file picker natively
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.csv';
    fileInput.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const p1 = prompt(`🔒 Set Master Passphrase to encrypt CSV\n\n${PASS_RULES}:`);
      if (p1 === null) return;
      const p1Err = _checkPassStrength(p1);
      if (p1Err) {
        alert(`⚠️ ${p1Err}`);
        return;
      }
      const p2 = prompt("🔒 Confirm Master Passphrase:");
      if (p2 === null) return;
      if (p1.trim() !== p2.trim()) {
        alert("⚠️ Passphrases do not match!");
        return;
      }

      try {
        const text = await new Promise((resolve, reject) => {
          const r = new FileReader();
          r.onload = (ev) => resolve(ev.target.result);
          r.onerror = (err) => reject(err);
          r.readAsText(file);
        });
        await triggerEncryptionRequest(text, p1.trim(), file.name);
      } catch (err) {
        alert("❌ Error reading file: " + err.message);
      }
    };
    fileInput.click();
    return;
  }

  // Step 2: Encrypt loaded firewalls from memory
  if (state.firewalls && state.firewalls.length > 0) {
    const p1 = prompt(`🔒 Set Master Passphrase to encrypt ${state.firewalls.length} firewalls\n\n${PASS_RULES}:`);
    if (p1 === null) return;
    const p1Err2 = _checkPassStrength(p1);
    if (p1Err2) {
      alert(`⚠️ ${p1Err2}`);
      return;
    }
    const p2 = prompt("🔒 Confirm Master Passphrase:");
    if (p2 === null) return;
    if (p1.trim() !== p2.trim()) {
      alert("⚠️ Passphrases do not match!");
      return;
    }

    const rows = [['Name', 'IP', 'Port', 'Username', 'Password', 'Site']];
    state.firewalls.forEach((fw) => {
      rows.push([fw.Name, fw.IP, fw.Port, fw.Username, fw.Password, fw.Site]);
    });
    csvText = rows.map((r) => r.map((c) => `"${String(c || '').replace(/"/g, '""')}"`).join(',')).join('\n');
    await triggerEncryptionRequest(csvText, p1.trim(), defaultFileName);
  } else {
    alert("⚠️ No firewalls loaded in memory to encrypt! Please upload a CSV first.");
  }
}

async function triggerEncryptionRequest(csvText, passphrase, filename) {
  try {
    const res = await fetch(`${API_BASE}/export-enc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csv_text: csvText, passphrase: passphrase, filename: filename })
    });

    if (!res.ok) {
      let errMsg = `Server error ${res.status}`;
      try { const j = await res.json(); errMsg = j.error || errMsg; } catch(_) {}
      throw new Error(errMsg);
    }

    const blob = await res.blob();
    const outFilename = filename.replace(/\.csv$/i, '') + '_encrypted.enc';
    const downloadUrl = window.URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = downloadUrl;
    a.download = outFilename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(downloadUrl);

    showToast(`✅ AES-256-GCM Encrypted (600K PBKDF2) and downloaded!`, 'success');
    alert(`✅ AES-256-GCM Encrypted successfully!\n600,000 PBKDF2 iterations, 256-bit salt\nSaved as ${outFilename}`);
  } catch (err) {
    alert(`❌ Encryption failed: ${err.message}`);
  }
}

function handleNativeDecrypt(pendingContent, pendingName) {
  const pass = prompt(`🔒 Enter Master Passphrase to unlock "${pendingName}":`);
  if (pass === null) return;
  if (!pass.trim()) {
    alert("⚠️ Passphrase is required!");
    return;
  }

  (async () => {
    try {
      const decryptedCSV = await cryptoDecrypt(pendingContent, pass.trim());
      Papa.parse(decryptedCSV, {
        header: true, skipEmptyLines: true, transformHeader: (h) => h.trim(),
        complete: (results) => {
          const required = ['Name', 'IP', 'Port', 'Username', 'Password', 'Site'];
          const headers = results.meta.fields || [];
          const missing = required.filter((c) => !headers.some((h) => h.toLowerCase() === c.toLowerCase()));
          if (missing.length > 0) {
            alert(`❌ Missing columns in decrypted CSV: ${missing.join(', ')}`);
            return;
          }
          const firewalls = [];
          results.data.forEach((row, idx) => {
            const fw = {};
            required.forEach((c) => {
              const h = headers.find((hh) => hh.toLowerCase() === c.toLowerCase());
              fw[c] = (row[h] || '').trim();
            });
            if (fw.IP && fw.Name) { fw._id = idx; firewalls.push(fw); }
          });

          state.firewalls = firewalls;
          state.sites = [...new Set(state.firewalls.map((fw) => fw.Site).filter(Boolean))].sort();
          state.selectedIds.clear();
          state.activeSite = 'all';
          state.searchQuery = '';
          state.schedules = {};
          state.uptimeResults = {};

          dom.loadedFileName.textContent = pendingName;
          dom.loadedFwCount.textContent = state.firewalls.length;
          dom.fileLoadedInfo.classList.remove('hidden');
          dom.btnStep1Next.disabled = false;

          showToast(`✅ Decrypted ${state.firewalls.length} firewalls successfully!`, 'success');
          alert(`✅ Unlocked ${state.firewalls.length} firewalls successfully!`);
          goToStep(1);
        }
      });
    } catch (err) {
      alert("❌ Decryption failed! Incorrect passphrase or corrupted payload.");
    }
  })();
}

// ─── CSV Upload & Encryption ────────────────
function handleFileSelect(e) {
  const f = e.target.files[0];
  if (f) processUploadedFile(f);
}
function handleFileDrop(e) {
  e.preventDefault();
  dom.uploadZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) processUploadedFile(f);
  else showToast('Please drop a CSV or .enc file.', 'error');
}

function processUploadedFile(file) {
  if (file.name.toLowerCase().endsWith('.enc')) {
    const reader = new FileReader();
    reader.onload = (e) => {
      handleNativeDecrypt(e.target.result, file.name);
    };
    reader.readAsText(file);
  } else {
    parseCSVFile(file);
  }
}

function parseCSVFile(file) {
  Papa.parse(file, {
    header: true, skipEmptyLines: true, transformHeader: (h) => h.trim(),
    complete: (results) => {
      const required = ['Name', 'IP', 'Port', 'Username', 'Password', 'Site'];
      const headers = results.meta.fields || [];
      const missing = required.filter((c) => !headers.some((h) => h.toLowerCase() === c.toLowerCase()));
      if (missing.length > 0) { showToast(`Missing columns: ${missing.join(', ')}`, 'error'); return; }

      const seenIPs = new Set();
      const firewalls = [];
      results.data.forEach((row, idx) => {
        const fw = {};
        required.forEach((c) => {
          const h = headers.find((hh) => hh.toLowerCase() === c.toLowerCase());
          fw[c] = (row[h] || '').trim();
        });
        if (fw.IP && fw.Name) {
          if (!seenIPs.has(fw.IP)) {
            seenIPs.add(fw.IP);
            fw._id = idx;
            firewalls.push(fw);
          }
        }
      });
      state.firewalls = firewalls;

      state.sites = [...new Set(state.firewalls.map((fw) => fw.Site).filter(Boolean))].sort();
      state.selectedIds.clear();
      state.activeSite = 'all';
      state.searchQuery = '';
      state.schedules = {};
      state.uptimeResults = {};

      dom.loadedFileName.textContent = file.name;
      dom.loadedFwCount.textContent = state.firewalls.length;
      dom.fileLoadedInfo.classList.remove('hidden');
      dom.btnStep1Next.disabled = false;
      if (dom.fileInput) dom.fileInput.value = '';
      showToast(`Loaded ${state.firewalls.length} firewalls from ${file.name}`, 'success');
      setTimeout(() => goToStep(1), 600);
    },
    error: (err) => {
      if (dom.fileInput) dom.fileInput.value = '';
      showToast(`CSV error: ${err.message}`, 'error');
    },
  });
}

function downloadSampleCSV(e) {
  e.preventDefault();
  const csv = `Name,IP,Port,Username,Password,Site\nFW-HQ-01,10.0.1.1,22,admin,P@ssw0rd,Headquarters\nFW-HQ-02,10.0.1.2,22,admin,P@ssw0rd,Headquarters\nFW-BR-01,10.0.2.1,22,admin,P@ssw0rd,Branch Office\nFW-DC-01,10.0.3.1,22,admin,P@ssw0rd,Data Center`;
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'firewall_sample.csv'; a.click();
}

// ─── Firewall Selection (Step 2) ────────────
function getFilteredFirewalls() {
  return state.firewalls.filter((fw) => {
    const ms = state.activeSite === 'all' || fw.Site === state.activeSite;
    const mq = !state.searchQuery || fw.Name.toLowerCase().includes(state.searchQuery) || fw.IP.includes(state.searchQuery);
    return ms && mq;
  });
}

function renderSiteFilter() {
  const label = dom.siteFilterBar.querySelector('.site-filter-label');
  dom.siteFilterBar.innerHTML = '';
  dom.siteFilterBar.appendChild(label);
  const makeBtn = (text, count, site) => {
    const b = document.createElement('button');
    b.className = `site-btn ${state.activeSite === site ? 'active' : ''}`;
    b.innerHTML = `${esc(text)} <span class="site-count">${count}</span>`;
    b.addEventListener('click', () => { state.activeSite = site; renderSiteFilter(); renderFirewallTable(); });
    return b;
  };
  dom.siteFilterBar.appendChild(makeBtn('All Sites', state.firewalls.length, 'all'));
  state.sites.forEach((s) => dom.siteFilterBar.appendChild(makeBtn(s, state.firewalls.filter((fw) => fw.Site === s).length, s)));
}

function renderFirewallTable() {
  const filtered = getFilteredFirewalls();
  dom.firewallTableBody.innerHTML = '';
  dom.firewallEmptyState.classList.toggle('hidden', filtered.length > 0);
  dom.firewallTableScroll.classList.toggle('hidden', filtered.length === 0);

  let hasAnyActiveSchedules = false;

  filtered.forEach((fw, idx) => {
    const sel = state.selectedIds.has(fw._id);
    const ut = state.uptimeResults[fw._id];
    const utHtml = ut
      ? `<span class="uptime-badge ${ut.status}">${esc(ut.uptime || ut.message)}</span>`
      : '<span class="uptime-na">—</span>';

    const tz = state.timezoneResults[fw._id];
    const timeHtml = tz
      ? `<span class="uptime-badge ${tz.status}">${esc(tz.fwTime || tz.message)}</span>`
      : '<span class="uptime-na">—</span>';

    // Reboot Schedule cell
    const sc = state.scheduleCheckResults[fw._id];
    let schedHtml = '<span class="uptime-na">—</span>';
    if (sc) {
      if (['checking', 'fetching', 'cancelling'].includes(sc.status)) {
        schedHtml = `<span class="schedule-badge loading">${esc(sc.status === 'cancelling' ? 'Cancelling…' : 'Checking…')}</span>`;
      } else if (sc.status === 'success') {
        if (sc.hasSchedule) {
          hasAnyActiveSchedules = true;
          schedHtml = `<div class="sched-cell-wrap"><div class="sched-badge-wrap"><span class="schedule-badge active-glow">Scheduled</span><span class="sched-time-text">${esc(sc.message)}</span></div><button class="btn btn-danger btn-xs btn-cancel-row" data-fw-id="${fw._id}" title="Cancel reboot schedule">Cancel</button></div>`;
        } else {
          schedHtml = '<span class="schedule-badge none">None</span>';
        }
      } else if (sc.status === 'failed') {
        schedHtml = `<span class="schedule-badge failed" title="${esc(sc.message)}">Failed</span>`;
      } else if (sc.status === 'cancelled') {
        schedHtml = '<span class="schedule-badge none">Cancelled</span>';
      }
    }

    const tr = document.createElement('tr');
    tr.id = `fw-row-${fw._id}`;
    if (sel) tr.classList.add('selected');
    tr.style.animationDelay = `${idx * 0.02}s`;
    tr.innerHTML = `
      <td><label class="custom-checkbox"><input type="checkbox" data-fw-id="${fw._id}" ${sel ? 'checked' : ''}><span class="checkmark"><svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 6l3 3 5-5"/></svg></span></label></td>
      <td class="fw-name">${esc(fw.Name)}</td>
      <td class="fw-ip">${esc(fw.IP)}</td>
      <td>${esc(fw.Port)}</td>
      <td>${esc(fw.Username)}</td>
      <td class="fw-site">${esc(fw.Site)}</td>
      <td class="fw-uptime">${utHtml}</td>
      <td class="fw-time">${timeHtml}</td>
      <td class="fw-schedule">${schedHtml}</td>`;
    
    tr.querySelector('input[type="checkbox"]').addEventListener('change', () => toggleFirewall(fw._id));
    const cancelBtn = tr.querySelector('.btn-cancel-row');
    if (cancelBtn) cancelBtn.addEventListener('click', (e) => { e.stopPropagation(); cancelSchedules(false, fw._id); });
    
    dom.firewallTableBody.appendChild(tr);
  });

  // Make the toolbar "Cancel Reboots" button glow only if at least one selected firewall has an active schedule
  const selectedList = getSelectedFirewalls();
  const selectedHasSchedule = selectedList.some((fw) => {
    const sc = state.scheduleCheckResults[fw._id];
    return sc && sc.status === 'success' && sc.hasSchedule;
  });
  dom.btnCancelSchedules.classList.toggle('glow', selectedHasSchedule);

  updateHeaderCheckbox();
}

function toggleFirewall(id) { state.selectedIds.has(id) ? state.selectedIds.delete(id) : state.selectedIds.add(id); updateSelectedCount(); renderFirewallTable(); }
function selectAll() { state.firewalls.forEach((fw) => state.selectedIds.add(fw._id)); renderFirewallTable(); updateSelectedCount(); }
function deselectAll() { state.selectedIds.clear(); renderFirewallTable(); updateSelectedCount(); }
function selectFiltered() { getFilteredFirewalls().forEach((fw) => state.selectedIds.add(fw._id)); renderFirewallTable(); updateSelectedCount(); }
function updateHeaderCheckbox() { const f = getFilteredFirewalls(); dom.headerSelectAllCb.checked = f.length > 0 && f.every((fw) => state.selectedIds.has(fw._id)); }
function updateSelectedCount() {
  const count = state.selectedIds.size;
  dom.selectedCountDisplay.innerHTML = `<strong>${count}</strong> of <span>${state.firewalls.length}</span> selected`;
  dom.btnStep2Next.disabled = (count === 0);
  dom.btnGetUptime.disabled = (count === 0);
  dom.btnGetTimezone.disabled = (count === 0);
  dom.btnCheckSchedules.disabled = (count === 0);
  dom.btnCancelSchedules.disabled = (count === 0);
}

// ─── Uptime Check ───────────────────────────
function updateUptimeCell(fwId) {
  const tr = document.getElementById(`fw-row-${fwId}`);
  if (!tr) return;
  
  const ut = state.uptimeResults[fwId];
  const utHtml = ut
    ? `<span class="uptime-badge ${ut.status}">${esc(ut.uptime || ut.message)}</span>`
    : '<span class="uptime-na">—</span>';

  const tz = state.timezoneResults[fwId];
  const timeHtml = tz
    ? `<span class="uptime-badge ${tz.status}">${esc(tz.fwTime || tz.message)}</span>`
    : '<span class="uptime-na">—</span>';

  const cell = tr.querySelector('.fw-uptime');
  if (cell) cell.innerHTML = utHtml;

  const cellTime = tr.querySelector('.fw-time');
  if (cellTime) cellTime.innerHTML = timeHtml;
}

function updateScheduleCell(fwId) {
  const tr = document.getElementById(`fw-row-${fwId}`);
  if (!tr) return;
  const sc = state.scheduleCheckResults[fwId];
  let schedHtml = '<span class="uptime-na">—</span>';
  if (sc) {
    if (['checking', 'fetching', 'cancelling'].includes(sc.status)) {
      schedHtml = `<span class="schedule-badge loading">${esc(sc.status === 'cancelling' ? 'Cancelling…' : 'Checking…')}</span>`;
    } else if (sc.status === 'success') {
      if (sc.hasSchedule) {
        schedHtml = `<div class="sched-cell-wrap"><div class="sched-badge-wrap"><span class="schedule-badge active-glow">Scheduled</span><span class="sched-time-text">${esc(sc.message)}</span></div><button class="btn btn-danger btn-xs btn-cancel-row" data-fw-id="${fwId}" title="Cancel reboot schedule">Cancel</button></div>`;
      } else {
        schedHtml = '<span class="schedule-badge none">None</span>';
      }
    } else if (sc.status === 'failed') {
      schedHtml = `<span class="schedule-badge failed" title="${esc(sc.message)}">Failed</span>`;
    } else if (sc.status === 'cancelled') {
      schedHtml = '<span class="schedule-badge none">Cancelled</span>';
    }
  }
  const cell = tr.querySelector('.fw-schedule');
  if (cell) {
    cell.innerHTML = schedHtml;
    const cancelBtn = cell.querySelector('.btn-cancel-row');
    if (cancelBtn) cancelBtn.addEventListener('click', (e) => { e.stopPropagation(); cancelSchedules(false, fwId); });
  }

  // Handle toolbar glowing Cancel button
  const selectedList = getSelectedFirewalls();
  const selectedHasSchedule = selectedList.some((fw) => {
    const scResult = state.scheduleCheckResults[fw._id];
    return scResult && scResult.status === 'success' && scResult.hasSchedule;
  });
  dom.btnCancelSchedules.classList.toggle('glow', selectedHasSchedule);
  dom.btnCancelSchedules.disabled = !selectedHasSchedule;
}

async function getUptime() {
  if (state.selectedIds.size === 0) { showToast('Select firewalls first.', 'warning'); return; }
  if (state.isUptimeRunning) { showToast('Uptime check already running.', 'warning'); return; }

  const selected = getSelectedFirewalls();
  state.uptimeIdMap = {};
  const payload = selected.map((fw) => {
    const bid = `ut-${fw._id}`;
    state.uptimeIdMap[bid] = fw._id;
    return { id: bid, name: fw.Name, ip: fw.IP, port: parseInt(fw.Port, 10), username: fw.Username, password: fw.Password, site: fw.Site };
  });

  // Mark selected as loading
  selected.forEach((fw) => {
    state.uptimeResults[fw._id] = { status: 'loading', message: 'Checking…' };
    updateUptimeCell(fw._id);
  });

  try {
    const res = await fetch(`${API_BASE}/get-uptime`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ firewalls: payload, batchSize: 10 }) });
    if (!res.ok) throw new Error('Server error');
    state.isUptimeRunning = true;
    showToast('Uptime check started…', 'info');
    connectUptimeSSE();
  } catch (err) { showToast(`Uptime failed: ${err.message}`, 'error'); }
}

async function getTimezone() {
  if (state.selectedIds.size === 0) { showToast('Select firewalls first.', 'warning'); return; }
  if (state.isTimezoneRunning) { showToast('Timezone check already running.', 'warning'); return; }

  const selected = getSelectedFirewalls();
  state.timezoneIdMap = {};
  const payload = selected.map((fw) => {
    const bid = `tz-${fw._id}`;
    state.timezoneIdMap[bid] = fw._id;
    return { id: bid, name: fw.Name, ip: fw.IP, port: parseInt(fw.Port, 10), username: fw.Username, password: fw.Password, site: fw.Site };
  });

  // Mark selected as loading in timezone results only
  selected.forEach((fw) => {
    state.timezoneResults[fw._id] = { status: 'loading', message: 'Checking…' };
    updateUptimeCell(fw._id);
  });

  try {
    const res = await fetch(`${API_BASE}/get-timezone`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ firewalls: payload, batchSize: 10 }) });
    if (!res.ok) throw new Error('Server error');
    state.isTimezoneRunning = true;
    showToast('Timezone check started…', 'info');
    connectTimezoneSSE();
  } catch (err) { showToast(`Timezone check failed: ${err.message}`, 'error'); }
}

function connectTimezoneSSE() {
  if (state.timezoneSse) state.timezoneSse.close();
  state.timezoneSse = new EventSource(`${API_BASE}/timezone-status`);
  state.timezoneSse.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if ((data.id === '-1' || data.id === -1) && data.status === 'complete') {
        state.isTimezoneRunning = false;
        state.timezoneSse.close();
        state.timezoneSse = null;
        showToast('Timezone check complete.', 'success');
        return;
      }
      const localId = state.timezoneIdMap[data.id];
      if (localId !== undefined) {
        state.timezoneResults[localId] = {
          status: data.status,
          message: data.message || '',
          fwTime: data.fw_time || ''
        };
        updateUptimeCell(localId);
      }
    } catch {}
  };
  state.timezoneSse.onerror = () => { state.isTimezoneRunning = false; if (state.timezoneSse) { state.timezoneSse.close(); state.timezoneSse = null; } };
}

function connectUptimeSSE() {
  if (state.uptimeSse) state.uptimeSse.close();
  state.uptimeSse = new EventSource(`${API_BASE}/uptime-status`);
  state.uptimeSse.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if ((data.id === '-1' || data.id === -1) && data.status === 'complete') {
        state.isUptimeRunning = false;
        state.uptimeSse.close();
        state.uptimeSse = null;
        dom.btnExportUptime.classList.remove('hidden');
        showToast('Uptime check complete.', 'success');
        return;
      }
      const localId = state.uptimeIdMap[data.id];
      if (localId !== undefined) {
        state.uptimeResults[localId] = {
          status: data.status,
          message: data.message || '',
          uptime: data.uptime || ''
        };
        updateUptimeCell(localId);
      }
    } catch {}
  };
  state.uptimeSse.onerror = () => { state.isUptimeRunning = false; if (state.uptimeSse) { state.uptimeSse.close(); state.uptimeSse = null; } };
}

function exportUptimeResults() {
  const rows = [['Name', 'IP', 'Site', 'Uptime Status', 'Uptime', 'Timezone Status', 'Firewall Time (Timezone)']];
  state.firewalls.forEach((fw) => {
    const ut = state.uptimeResults[fw._id] || {};
    const tz = state.timezoneResults[fw._id] || {};
    
    const uptimeStatus = ut.status ? ut.status : 'Not checked';
    const uptimeVal = (ut.status === 'success' && ut.uptime) ? ut.uptime : (ut.status ? ut.message : 'Not checked');
    
    const tzStatus = tz.status ? tz.status : 'Not checked';
    const tzVal = (tz.status === 'success' && tz.fwTime) ? tz.fwTime : (tz.status ? tz.message : 'Not checked');
    
    rows.push([
      fw.Name,
      fw.IP,
      fw.Site,
      uptimeStatus,
      uptimeVal,
      tzStatus,
      tzVal
    ]);
  });
  downloadCSV(rows, `uptime_results_${new Date().toISOString().slice(0, 10)}.csv`);
  showToast('Uptime results exported.', 'success');
}

// ─── Schedule status Check & Cancel ─────────
async function checkSchedules() {
  if (state.selectedIds.size === 0) { showToast('Select firewalls first.', 'warning'); return; }
  if (state.isScheduleRunning) { showToast('A schedule check/cancel is already running.', 'warning'); return; }

  const selected = getSelectedFirewalls();
  state.scheduleIdMap = {};
  const payload = selected.map((fw) => {
    const bid = `sc-${fw._id}`;
    state.scheduleIdMap[bid] = fw._id;
    return { id: bid, name: fw.Name, ip: fw.IP, port: parseInt(fw.Port, 10), username: fw.Username, password: fw.Password, site: fw.Site };
  });

  // Mark selected as checking
  selected.forEach((fw) => {
    state.scheduleCheckResults[fw._id] = { status: 'checking', message: 'Checking…', hasSchedule: false };
    updateScheduleCell(fw._id);
  });

  try {
    const res = await fetch(`${API_BASE}/check-schedule`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ firewalls: payload, batchSize: 10 }) });
    if (!res.ok) throw new Error('Server error');
    state.isScheduleRunning = true;
    showToast('Checking reboot schedules…', 'info');
    connectScheduleSSE('check');
  } catch (err) { showToast(`Schedule check failed: ${err.message}`, 'error'); }
}

async function cancelSchedules(selectedOnly = true, targetFwId = null) {
  if (state.isScheduleRunning) { showToast('A schedule check/cancel is already running.', 'warning'); return; }

  let targetFirewalls = [];
  if (targetFwId !== null) {
    const fw = state.firewalls.find((f) => f._id === targetFwId);
    if (fw) targetFirewalls = [fw];
  } else {
    const baseList = selectedOnly ? getSelectedFirewalls() : state.firewalls;
    
    // Check if we have checked schedule status yet
    const hasCheckedAny = baseList.some((fw) => state.scheduleCheckResults[fw._id] !== undefined);
    if (!hasCheckedAny) {
      showToast('Please check reboot schedules first to verify active reboots.', 'warning');
      return;
    }

    // Only cancel schedules for firewalls that are verified to have a schedule!
    targetFirewalls = baseList.filter((fw) => {
      const sc = state.scheduleCheckResults[fw._id];
      return sc && sc.status === 'success' && sc.hasSchedule;
    });
  }

  if (targetFirewalls.length === 0) { 
    showToast('No active scheduled reboots found to cancel.', 'warning'); 
    return; 
  }

  state.scheduleIdMap = {};
  const payload = targetFirewalls.map((fw) => {
    const bid = `sc-${fw._id}`;
    state.scheduleIdMap[bid] = fw._id;
    return { id: bid, name: fw.Name, ip: fw.IP, port: parseInt(fw.Port, 10), username: fw.Username, password: fw.Password, site: fw.Site };
  });

  // Mark target firewalls as cancelling
  targetFirewalls.forEach((fw) => {
    state.scheduleCheckResults[fw._id] = { status: 'cancelling', message: 'Cancelling…', hasSchedule: true };
    updateScheduleCell(fw._id);
  });

  try {
    const res = await fetch(`${API_BASE}/cancel-schedule`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ firewalls: payload, batchSize: 10 }) });
    if (!res.ok) throw new Error('Server error');
    state.isScheduleRunning = true;
    showToast('Sending reboot cancel commands…', 'info');
    connectScheduleSSE('cancel');
  } catch (err) { showToast(`Cancel failed: ${err.message}`, 'error'); }
}

function connectScheduleSSE(actionType) {
  if (state.scheduleSse) state.scheduleSse.close();
  state.scheduleSse = new EventSource(`${API_BASE}/schedule-status`);
  state.scheduleSse.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if ((data.id === '-1' || data.id === -1) && data.status === 'complete') {
        state.isScheduleRunning = false;
        state.scheduleSse.close();
        state.scheduleSse = null;
        showToast(actionType === 'check' ? 'Schedule check complete.' : 'Reboot schedule cancelled.', 'success');
        return;
      }
      const localId = state.scheduleIdMap[data.id];
      if (localId !== undefined) {
        state.scheduleCheckResults[localId] = {
          status: data.status,
          message: data.message || '',
          hasSchedule: !!data.hasSchedule
        };
        updateScheduleCell(localId);
      }
    } catch {}
  };
  state.scheduleSse.onerror = () => {
    state.isScheduleRunning = false;
    if (state.scheduleSse) {
      state.scheduleSse.close();
      state.scheduleSse = null;
    }
  };
}

// ─── Schedule (Step 3) — Per-Firewall ───────
function setDefaultQuickDatetime() {
  const d = new Date(); d.setDate(d.getDate() + 1); d.setHours(3, 0, 0, 0);
  dom.quickDateInput.value = fmtDate(d);
  dom.quickTimeInput.value = '03:00';
}

function setQuickMode(mode) {
  dom.pillSchedule.classList.toggle('active', mode === 'at');
  dom.pillNow.classList.toggle('active', mode === 'now');
  dom.pillSchedule.querySelector('input').checked = mode === 'at';
  dom.pillNow.querySelector('input').checked = mode === 'now';
  dom.quickDateInput.disabled = mode === 'now';
  dom.quickTimeInput.disabled = mode === 'now';
}

function autoSpaceSchedules(startIndex = 0) {
  const selected = getSelectedFirewalls();
  if (selected.length === 0) return;

  const gapMinutes = parseInt(dom.quickInterval.value || '5', 10);
  let currentBase = null;

  selected.forEach((fw, idx) => {
    if (idx < startIndex) {
      const sched = getSchedule(fw._id);
      if (sched.mode === 'at' && sched.date && sched.time) {
        currentBase = new Date(`${sched.date}T${sched.time}`);
      }
      return;
    }

    if (idx === startIndex) {
      const sched = getSchedule(fw._id);
      const dVal = sched.date || dom.quickDateInput.value;
      const tVal = sched.time || dom.quickTimeInput.value || '03:00';
      state.schedules[fw._id] = { mode: sched.mode, date: dVal, time: tVal };
      if (sched.mode === 'at' && dVal && tVal) {
        currentBase = new Date(`${dVal}T${tVal}`);
      }
      return;
    }

    const sched = getSchedule(fw._id);
    if (sched.mode === 'now') {
      state.schedules[fw._id] = { mode: 'now', date: '', time: '' };
      return;
    }

    if (currentBase && !isNaN(currentBase.getTime())) {
      currentBase = new Date(currentBase.getTime() + gapMinutes * 60 * 1000);
      const fDate = fmtDate(currentBase);
      const fTime = fmtTime(currentBase);
      state.schedules[fw._id] = { mode: 'at', date: fDate, time: fTime };
    } else {
      const dVal = dom.quickDateInput.value;
      const tVal = dom.quickTimeInput.value || '03:00';
      state.schedules[fw._id] = { mode: 'at', date: dVal, time: tVal };
      currentBase = new Date(`${dVal}T${tVal}`);
    }
  });
}

function fmtTime(date) {
  const h = String(date.getHours()).padStart(2, '0');
  const m = String(date.getMinutes()).padStart(2, '0');
  return `${h}:${m}`;
}

function applyScheduleToAll() {
  const mode = dom.pillNow.querySelector('input').checked ? 'now' : 'at';
  const date = dom.quickDateInput.value;
  const time = dom.quickTimeInput.value;
  const selected = getSelectedFirewalls();
  if (selected.length === 0) return;

  state.schedules[selected[0]._id] = { mode, date, time };

  selected.forEach((fw, idx) => {
    if (idx > 0) {
      state.schedules[fw._id] = { mode, date: mode === 'now' ? '' : date, time: mode === 'now' ? '' : time };
    }
  });

  if (mode === 'at') {
    autoSpaceSchedules(0);
  }

  renderScheduleTable();
  updateScheduleSummary();
  showToast(mode === 'now' ? 'All set to Restart Now' : 'Schedules spaced and applied.', 'info');
}

function getSelectedFirewalls() {
  return state.firewalls.filter((fw) => state.selectedIds.has(fw._id));
}

function getSchedule(id) {
  return state.schedules[id] || { mode: 'at', date: dom.quickDateInput.value, time: dom.quickTimeInput.value || '03:00' };
}

function buildSonicwallDatetime(date, time) {
  if (!date || !time) return null;
  const [y, m, d] = date.split('-');
  const [hh, mm] = time.split(':');
  return `${y}:${m}:${d}:${hh}:${mm}:00`;
}

function getCommandPreview(sched) {
  if (sched.mode === 'now') return 'restart now';
  if (!sched.date || !sched.time) return 'restart at (set date/time)';

  try {
    const [y, m, d] = sched.date.split('-');
    const [hh, mm] = sched.time.split(':');
    const targetDate = new Date(y, m - 1, d, hh, mm, 0);
    const now = new Date();

    // Check if the scheduled date is the same day
    const isSameDay = (
      targetDate.getFullYear() === now.getFullYear() &&
      targetDate.getMonth() === now.getMonth() &&
      targetDate.getDate() === now.getDate()
    );

    if (isSameDay) {
      const diffMs = targetDate - now;
      const diffMins = Math.round(diffMs / 60000);
      if (diffMins > 0) {
        return `restart in ${diffMins} minutes`;
      }
    }
  } catch (e) {
    console.error('Failed to parse date for command preview:', e);
  }

  const dt = buildSonicwallDatetime(sched.date, sched.time);
  return dt ? `restart at ${dt}` : 'restart at (set date/time)';
}

function formatHighLevelTime(dateStr, timeStr) {
  if (!dateStr || !timeStr) return 'N/A';
  const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  try {
    const [y, m, d] = dateStr.split('-');
    const [hh, mm] = timeStr.split(':');
    const monthName = months[parseInt(m, 10) - 1];
    const hour = parseInt(hh, 10);
    const ampm = hour >= 12 ? 'PM' : 'AM';
    const hour12 = hour % 12 || 12;
    return `${monthName} ${parseInt(d, 10)}, ${y} at ${hour12}:${mm} ${ampm}`;
  } catch (e) {
    return `${dateStr} ${timeStr}`;
  }
}

function renderScheduleTable() {
  const selected = getSelectedFirewalls();
  dom.scheduleTableBody.innerHTML = '';

  selected.forEach((fw, idx) => {
    const sched = getSchedule(fw._id);
    const tr = document.createElement('tr');
    tr.style.animationDelay = `${idx * 0.02}s`;
    tr.innerHTML = `
      <td class="fw-name">${esc(fw.Name)}</td>
      <td class="fw-ip">${esc(fw.IP)}</td>
      <td class="fw-site">${esc(fw.Site)}</td>
      <td>
        <select class="form-select sched-mode" data-id="${fw._id}">
          <option value="at" ${sched.mode === 'at' ? 'selected' : ''}>Schedule At</option>
          <option value="now" ${sched.mode === 'now' ? 'selected' : ''}>Restart Now</option>
        </select>
      </td>
      <td><input type="date" class="form-input form-input-sm sched-date" data-id="${fw._id}" value="${sched.date}" ${sched.mode === 'now' ? 'disabled' : ''}></td>
      <td><input type="time" class="form-input form-input-sm sched-time" data-id="${fw._id}" value="${sched.time}" ${sched.mode === 'now' ? 'disabled' : ''}></td>
      <td><code class="cmd-preview" id="cmd-${fw._id}">${esc(getCommandPreview(sched))}</code></td>`;
    dom.scheduleTableBody.appendChild(tr);
  });

  // Bind events
  dom.scheduleTableBody.querySelectorAll('.sched-mode').forEach((sel) => {
    sel.addEventListener('change', (e) => {
      const id = parseInt(e.target.dataset.id, 10);
      const s = getSchedule(id);
      s.mode = e.target.value;
      state.schedules[id] = s;
      renderScheduleTable();
      updateScheduleSummary();
    });
  });
  dom.scheduleTableBody.querySelectorAll('.sched-date').forEach((inp) => {
    inp.addEventListener('change', (e) => {
      e.target.blur();
      const id = parseInt(e.target.dataset.id, 10);
      const s = getSchedule(id);
      s.date = e.target.value;
      state.schedules[id] = s;
      const selected = getSelectedFirewalls();
      const idx = selected.findIndex((fw) => fw._id === id);
      if (idx !== -1) {
        autoSpaceSchedules(idx);
      }
      renderScheduleTable();
      updateScheduleSummary();
    });
  });
  dom.scheduleTableBody.querySelectorAll('.sched-time').forEach((inp) => {
    inp.addEventListener('change', (e) => {
      e.target.blur();
      const id = parseInt(e.target.dataset.id, 10);
      const s = getSchedule(id);
      s.time = e.target.value;
      state.schedules[id] = s;
      const selected = getSelectedFirewalls();
      const idx = selected.findIndex((fw) => fw._id === id);
      if (idx !== -1) {
        autoSpaceSchedules(idx);
      }
      renderScheduleTable();
      updateScheduleSummary();
    });
  });
}

function updateScheduleSummary() {
  const selected = getSelectedFirewalls();
  let scheduled = 0, now = 0;
  selected.forEach((fw) => { const s = getSchedule(fw._id); if (s.mode === 'now') now++; else scheduled++; });
  dom.summaryFwCount.textContent = `${selected.length} selected`;
  dom.summaryScheduledCount.textContent = scheduled;
  dom.summaryNowCount.textContent = now;
}

// ─── Execute (Step 4) ──────────────────────
function showConfirmModal() {
  // Validate all 'at' schedules have date/time
  const selected = getSelectedFirewalls();
  for (const fw of selected) {
    const s = getSchedule(fw._id);
    if (s.mode === 'at' && (!s.date || !s.time)) {
      showToast(`Set date & time for ${fw.Name}`, 'warning');
      return;
    }
  }
  dom.modalFwCount.textContent = selected.length;
  dom.confirmModal.classList.add('visible');
}

function hideConfirmModal() { dom.confirmModal.classList.remove('visible'); }

function prepareExecutionView() {
  const selected = getSelectedFirewalls();
  state.results = {};
  state.rebootIdMap = {};

  dom.statTotal.textContent = selected.length;
  dom.statCompleted.textContent = '0';
  dom.statSuccess.textContent = '0';
  dom.statFailed.textContent = '0';
  dom.progressFill.style.width = '0%';
  dom.progressPercent.textContent = '0%';
  dom.progressLabel.textContent = 'Waiting to start…';
  dom.progressFill.classList.remove('running');
  dom.resultsTableBody.innerHTML = '';

  selected.forEach((fw, idx) => {
    const sched = getSchedule(fw._id);
    const cmd = getCommandPreview(sched);
    const tr = document.createElement('tr');
    tr.id = `result-row-${fw._id}`;
    tr.style.animationDelay = `${idx * 0.02}s`;
    tr.innerHTML = `
      <td class="result-name">${esc(fw.Name)}</td>
      <td class="result-ip">${esc(fw.IP)}</td>
      <td>${esc(fw.Site)}</td>
      <td><code class="cmd-preview">${esc(cmd)}</code></td>
      <td class="result-sched-time">${esc(sched.mode === 'now' ? 'Immediate (Now)' : formatHighLevelTime(sched.date, sched.time))}</td>
      <td class="result-status-cell"><span class="status-badge pending"><span class="status-badge-dot"></span>Pending</span></td>
      <td class="result-msg">—</td>
      <td class="result-time">—</td>`;
    dom.resultsTableBody.appendChild(tr);
  });

  dom.btnCancelExecution.classList.add('hidden');
  dom.btnExportResults.classList.add('hidden');
  dom.btnStartOver.classList.add('hidden');
}

async function executeReboot() {
  hideConfirmModal();
  goToStep(3);
  state.isRunning = true;
  dom.progressFill.classList.add('running');
  dom.progressLabel.textContent = 'Sending reboot commands…';
  dom.btnCancelExecution.classList.remove('hidden');

  const selected = getSelectedFirewalls();
  state.rebootIdMap = {};
  const fwPayload = selected.map((fw) => {
    const bid = `fw-${fw._id}`;
    state.rebootIdMap[bid] = fw._id;
    const sched = getSchedule(fw._id);
    const dt = sched.mode === 'at' ? buildSonicwallDatetime(sched.date, sched.time) : null;
    return { id: bid, name: fw.Name, ip: fw.IP, port: parseInt(fw.Port, 10) || 22, username: fw.Username, password: fw.Password, site: fw.Site, mode: sched.mode, datetime: dt || '' };
  });

  try {
    const res = await fetch(`${API_BASE}/schedule-reboot`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ firewalls: fwPayload, batchSize: 10 }) });
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || `Error ${res.status}`); }
    showToast('Execution started.', 'info');
    connectSSE();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
    state.isRunning = false;
    dom.progressFill.classList.remove('running');
    dom.progressLabel.textContent = 'Failed to start';
    dom.btnCancelExecution.classList.add('hidden');
    dom.btnStartOver.classList.remove('hidden');
  }
}

function connectSSE() {
  if (state.sseSource) state.sseSource.close();
  state.sseSource = new EventSource(`${API_BASE}/status`);
  state.sseSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if ((data.id === '-1' || data.id === -1) && data.status === 'complete') { handleCompletion(); return; }
      const localId = state.rebootIdMap[data.id];
      if (localId === undefined) return;
      state.results[localId] = data;
      const tr = document.getElementById(`result-row-${localId}`);
      if (tr) {
        const sl = data.status.charAt(0).toUpperCase() + data.status.slice(1);
        const statusCell = tr.querySelector('.result-status-cell');
        if (statusCell) statusCell.innerHTML = `<span class="status-badge ${data.status}"><span class="status-badge-dot"></span>${sl}</span>`;
        const msgCell = tr.querySelector('.result-msg');
        if (msgCell) msgCell.textContent = data.message || '—';
        const timeCell = tr.querySelector('.result-time');
        if (timeCell) timeCell.textContent = new Date().toLocaleTimeString();
      }
      updateExecutionStats();
    } catch {}
  };
  state.sseSource.onerror = () => { if (state.isRunning) setTimeout(() => { if (state.isRunning) connectSSE(); }, 3000); };
}

function updateExecutionStats() {
  const total = getSelectedFirewalls().length;
  const rv = Object.values(state.results);
  const done = rv.filter((r) => ['success', 'failed', 'cancelled'].includes(r.status)).length;
  const ok = rv.filter((r) => r.status === 'success').length;
  const fail = rv.filter((r) => r.status === 'failed').length;
  dom.statCompleted.textContent = done;
  dom.statSuccess.textContent = ok;
  dom.statFailed.textContent = fail;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  dom.progressFill.style.width = `${pct}%`;
  dom.progressPercent.textContent = `${pct}%`;
  dom.progressLabel.textContent = `${done} of ${total} completed`;
}

function handleCompletion() {
  state.isRunning = false;
  if (state.sseSource) { state.sseSource.close(); state.sseSource = null; }
  dom.progressFill.classList.remove('running');
  dom.progressFill.style.width = '100%';
  dom.progressPercent.textContent = '100%';
  dom.progressLabel.textContent = 'Complete';
  dom.btnCancelExecution.classList.add('hidden');
  dom.btnExportResults.classList.remove('hidden');
  dom.btnStartOver.classList.remove('hidden');
  const rv = Object.values(state.results);
  const ok = rv.filter((r) => r.status === 'success').length;
  const fail = rv.filter((r) => r.status === 'failed').length;
  showToast(fail === 0 ? `All ${ok} firewalls done!` : `${ok} success, ${fail} failed`, fail === 0 ? 'success' : 'warning');
}

async function cancelExecution() {
  try { await fetch(`${API_BASE}/cancel`, { method: 'POST' }); showToast('Cancel requested.', 'warning'); } catch {}
  state.isRunning = false;
  if (state.sseSource) { state.sseSource.close(); state.sseSource = null; }
  dom.progressFill.classList.remove('running');
  dom.progressLabel.textContent = 'Cancelled';
  dom.btnCancelExecution.classList.add('hidden');
  dom.btnExportResults.classList.remove('hidden');
  dom.btnStartOver.classList.remove('hidden');
}

function startOver() {
  state.firewalls = []; state.selectedIds.clear(); state.sites = [];
  state.activeSite = 'all'; state.searchQuery = '';
  state.isRunning = false; state.results = {};
  state.schedules = {}; state.uptimeResults = {};
  state.scheduleCheckResults = {};
  state.isTimezoneRunning = false;
  state.timezoneResults = {};
  if (state.timezoneSse) { state.timezoneSse.close(); state.timezoneSse = null; }
  dom.fileLoadedInfo.classList.add('hidden');
  dom.btnStep1Next.disabled = true;
  dom.fileInput.value = '';
  dom.searchInput.value = '';
  dom.btnExportUptime.classList.add('hidden');
  setDefaultQuickDatetime();
  goToStep(0);
  showToast('Ready for a new session.', 'info');
}

function clearAllData() {
  if (confirm('Are you sure you want to clear all loaded firewall data and credentials from memory?')) {
    state.firewalls = [];
    state.selectedIds.clear();
    state.sites = [];
    state.schedules = {};
    state.uptimeResults = {};
    state.timezoneResults = {};
    state.results = {};
    if (dom.fileInput) dom.fileInput.value = '';
    if (dom.loadedFileName) dom.loadedFileName.textContent = '—';
    if (dom.loadedFwCount) dom.loadedFwCount.textContent = '0';
    if (dom.fileLoadedInfo) dom.fileLoadedInfo.classList.add('hidden');
    if (dom.btnStep1Next) dom.btnStep1Next.disabled = true;

    fetch(`${API_BASE}/clear`, { method: 'POST' }).catch((e) => console.warn('Server clear failed:', e));
    goToStep(0);
    showToast('All firewall data and credentials cleared from memory.', 'success');
  }
}

// ─── Export Results ─────────────────────────
function exportResults() {
  const rows = [['Name', 'IP', 'Site', 'Command', 'Scheduled Restart Time', 'Status', 'Message', 'Command Executed at']];
  getSelectedFirewalls().forEach((fw) => {
    const r = state.results[fw._id] || {};
    const sched = getSchedule(fw._id);
    const cmd = getCommandPreview(sched);
    const schedTimeFormatted = sched.mode === 'now' ? 'Immediate (Now)' : formatHighLevelTime(sched.date, sched.time);
    const tr = document.getElementById(`result-row-${fw._id}`);
    const execTime = tr ? tr.querySelector('.result-time').textContent : '—';
    rows.push([fw.Name, fw.IP, fw.Site, cmd, schedTimeFormatted, r.status || 'pending', r.message || '', execTime || '—']);
  });
  downloadCSV(rows, `reboot_results_${new Date().toISOString().slice(0, 10)}.csv`);
  showToast('Results exported.', 'success');
}

// ─── Utilities ──────────────────────────────
function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
function debounce(fn, ms) { let t; return function (...a) { clearTimeout(t); t = setTimeout(() => fn.apply(this, a), ms); }; }
function fmtDate(d) { return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; }

function downloadCSV(rows, filename) {
  const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename; a.click(); URL.revokeObjectURL(a.href);
}

function showToast(message, type = 'info') {
  const icons = {
    success: '<svg viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="8" stroke="currentColor" stroke-width="1.5"/><path d="M5.5 9l2.5 2.5 4.5-5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    error: '<svg viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="8" stroke="currentColor" stroke-width="1.5"/><path d="M6.5 6.5l5 5M11.5 6.5l-5 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
    warning: '<svg viewBox="0 0 18 18" fill="none"><path d="M9 2L1 16h16L9 2z" stroke="currentColor" stroke-width="1.5"/><path d="M9 7v4M9 13v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
    info: '<svg viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="8" stroke="currentColor" stroke-width="1.5"/><path d="M9 8v5M9 5.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
  };
  const t = document.createElement('div'); t.className = `toast ${type}`;
  t.innerHTML = `${icons[type] || icons.info}<span>${esc(message)}</span>`;
  dom.toastContainer.appendChild(t);
  setTimeout(() => { t.classList.add('removing'); setTimeout(() => t.remove(), 300); }, 4000);
}

// ─── Settings Modal ─────────────────────────
async function showSettingsModal() {
  try {
    const res = await fetch(`${API_BASE}/settings`);
    if (!res.ok) throw new Error();
    const data = await res.json();
    
    dom.settingSmtpServer.value = data.smtp_server || '';
    dom.settingSmtpPort.value = data.smtp_port || 587;
    dom.settingSmtpUsername.value = data.smtp_username || '';
    dom.settingSmtpPassword.value = data.smtp_password || '';
    dom.settingRecipientEmail.value = data.recipient_email || '';
    dom.settingEnableEmails.checked = !!data.enable_emails;
    dom.settingEnableMonitoring.checked = !!data.enable_monitoring;
    dom.settingMonitoringTimeout.value = data.monitoring_timeout_minutes || 10;
    
    dom.timeoutConfigWrapper.style.display = dom.settingEnableMonitoring.checked ? 'block' : 'none';
    dom.settingsModal.classList.add('visible');
  } catch (err) {
    showToast('Failed to fetch settings from backend.', 'error');
  }
}

function hideSettingsModal() {
  dom.settingsModal.classList.remove('visible');
}

async function saveSettings() {
  const payload = {
    smtp_server: dom.settingSmtpServer.value.trim(),
    smtp_port: parseInt(dom.settingSmtpPort.value, 10) || 587,
    smtp_username: dom.settingSmtpUsername.value.trim(),
    smtp_password: dom.settingSmtpPassword.value,
    recipient_email: dom.settingRecipientEmail.value.trim(),
    enable_emails: dom.settingEnableEmails.checked,
    enable_monitoring: dom.settingEnableMonitoring.checked,
    monitoring_timeout_minutes: parseInt(dom.settingMonitoringTimeout.value, 10) || 10
  };

  try {
    const res = await fetch(`${API_BASE}/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error();
    showToast('Settings saved successfully.', 'success');
    hideSettingsModal();
  } catch (err) {
    showToast('Failed to save settings.', 'error');
  }
}

async function testSettings() {
  const payload = {
    smtp_server: dom.settingSmtpServer.value.trim(),
    smtp_port: parseInt(dom.settingSmtpPort.value, 10) || 587,
    smtp_username: dom.settingSmtpUsername.value.trim(),
    smtp_password: dom.settingSmtpPassword.value,
    recipient_email: dom.settingRecipientEmail.value.trim(),
    enable_emails: dom.settingEnableEmails.checked,
    enable_monitoring: dom.settingEnableMonitoring.checked,
    monitoring_timeout_minutes: parseInt(dom.settingMonitoringTimeout.value, 10) || 10
  };

  dom.btnSettingsTest.disabled = true;
  dom.btnSettingsTest.textContent = 'Testing...';

  try {
    const res = await fetch(`${API_BASE}/settings/test-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok) {
      showToast(data.message || 'Test email sent successfully!', 'success');
    } else {
      throw new Error(data.error || 'Failed to send test email.');
    }
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    dom.btnSettingsTest.disabled = false;
    dom.btnSettingsTest.textContent = 'Test Connection';
  }
}
