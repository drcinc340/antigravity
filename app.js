// ---------------- ENVIRONMENT & DEVICE DETECTION ----------------
const IS_GITHUB_PORTAL = window.location.hostname.endsWith('github.io');
const RAW_TUNNEL_JSON_URL = 'https://raw.githubusercontent.com/drcinc340/antigravity/main/tunnel.json';

function getClientDeviceLabel() {
  const ua = navigator.userAgent || '';
  const platform = navigator.platform || '';
  if (/iPhone/i.test(ua)) return 'iPhone';
  if (/iPad/i.test(ua) || (platform === 'MacIntel' && navigator.maxTouchPoints > 1)) return 'iPad';
  if (/Mac/i.test(platform) || /Macintosh/i.test(ua)) return 'MacBook';
  if (/Win/i.test(platform)) return 'Windows';
  return 'Remote';
}

const CLIENT_DEVICE = getClientDeviceLabel();
const IS_DESKTOP_WIDTH = () => window.innerWidth >= 900;

// State
let apiBase = IS_GITHUB_PORTAL ? (sessionStorage.getItem('antigravity_api_base') || '') : '';
let currentPin = localStorage.getItem('antigravity_pin') || '';
let currentConversationId = localStorage.getItem('antigravity_last_convo') || '';
let currentEventSource = null;
let conversationsList = [];
let enteredPin = '';
let isVerifyingPin = false;
let isRecording = false;
let speechRecognizer = null;
let activeDesktopInspector = localStorage.getItem('antigravity_inspector') ?? (window.innerWidth >= 1280 ? 'artifactsView' : '');
let sseReconnectTimer = null;

// DOM Elements
const connectionOrb = document.getElementById('connectionOrb');
const connModeBadge = document.getElementById('connModeBadge');
const headerConvoTitle = document.getElementById('headerConvoTitle');
const convoDropdownBtn = document.getElementById('convoDropdownBtn');
const newConvoBtn = document.getElementById('newConvoBtn');
const desktopNewConvoBtn = document.getElementById('desktopNewConvoBtn');
const toggleArtifactsDrawerBtn = document.getElementById('toggleArtifactsDrawerBtn');
const toggleSystemDrawerBtn = document.getElementById('toggleSystemDrawerBtn');
const desktopArtifactsCount = document.getElementById('desktopArtifactsCount');
const chatMessages = document.getElementById('chatMessages');
const emptyState = document.getElementById('emptyState');
const emptyStateHeading = document.getElementById('emptyStateHeading');
const promptInput = document.getElementById('promptInput');
const sendBtn = document.getElementById('sendBtn');
const micBtn = document.getElementById('micBtn');
const slashToggleBtn = document.getElementById('slashToggleBtn');
const slashBar = document.getElementById('slashBar');
const convosList = document.getElementById('convosList');
const convosCount = document.getElementById('convosCount');
const searchConvosInput = document.getElementById('searchConvosInput');
const artifactsList = document.getElementById('artifactsList');
const pinLockModal = document.getElementById('pinLockModal');
const pinDots = document.getElementById('pinDots');
const pinError = document.getElementById('pinError');
const newConvoModal = document.getElementById('newConvoModal');
const closeNewConvoBtn = document.getElementById('closeNewConvoBtn');
const startConvoSubmitBtn = document.getElementById('startConvoSubmitBtn');
const artifactModal = document.getElementById('artifactModal');
const artifactTitle = document.getElementById('artifactTitle');
const artifactContent = document.getElementById('artifactContent');
const closeArtifactBtn = document.getElementById('closeArtifactBtn');

// Set device-tailored welcome title
if (emptyStateHeading) {
  if (CLIENT_DEVICE === 'MacBook') emptyStateHeading.textContent = 'Antigravity for Mac';
  else if (CLIENT_DEVICE === 'iPhone') emptyStateHeading.textContent = 'Antigravity for iPhone';
  else if (CLIENT_DEVICE === 'iPad') emptyStateHeading.textContent = 'Antigravity for iPad';
  else emptyStateHeading.textContent = 'Antigravity Remote';
}

function updateConnectionBadge() {
  if (!connModeBadge) return;
  const host = apiBase || window.location.origin;
  if (/192\.168\.|10\.|127\.0\.0\.1|localhost/.test(host)) {
    connModeBadge.textContent = 'Home Wi-Fi';
  } else {
    connModeBadge.textContent = 'Cloud Tunnel';
  }
}

// ---------------- ENCRYPTED PORTAL ENDPOINT RESOLUTION ----------------
function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function decryptEndpointPayload(enc, pin) {
  const salt = b64ToBytes(enc.salt);
  const iv = b64ToBytes(enc.iv);
  const ct = b64ToBytes(enc.ct);
  const pinBytes = new TextEncoder().encode(String(pin));

  const baseKey = await crypto.subtle.importKey('raw', pinBytes, 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: enc.iter || 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

async function resolvePortalApiBase(pin) {
  if (!IS_GITHUB_PORTAL) {
    apiBase = '';
    updateConnectionBadge();
    return '';
  }

  let enc = null;
  const urlsToTry = [
    `${RAW_TUNNEL_JSON_URL}?t=${Date.now()}`,
    `./tunnel.json?t=${Date.now()}`
  ];

  for (const u of urlsToTry) {
    try {
      const r = await fetch(u, { cache: 'no-store' });
      if (r.ok) {
        enc = await r.json();
        if (enc && enc.ct) break;
      }
    } catch (e) {}
  }

  if (!enc || !enc.ct) {
    throw new Error('Could not reach tunnel directory.');
  }

  let decrypted;
  try {
    decrypted = await decryptEndpointPayload(enc, pin);
  } catch (decErr) {
    const authErr = new Error('Incorrect PIN');
    authErr.isPinError = true;
    throw authErr;
  }

  if (!decrypted || !decrypted.tunnelUrl) {
    throw new Error('Invalid tunnel endpoint.');
  }

  apiBase = decrypted.tunnelUrl.replace(/\/$/, '');
  sessionStorage.setItem('antigravity_api_base', apiBase);
  updateConnectionBadge();
  return apiBase;
}

function buildApiUrl(pathWithSlash) {
  return `${apiBase}${pathWithSlash}`;
}

// Helper for authenticated fetch (auto-refreshes tunnel URL if rotated on GitHub Portal)
async function apiFetch(pathWithSlash, options = {}, retried = false) {
  const headers = { ...(options.headers || {}) };
  headers['x-access-pin'] = currentPin;
  headers['Content-Type'] = headers['Content-Type'] || 'application/json';

  try {
    const res = await fetch(buildApiUrl(pathWithSlash), { ...options, headers });
    if (res.status === 401) {
      showPinModal();
      throw new Error('Unauthorized');
    }
    if (res.status === 429) {
      const d = await res.json().catch(() => ({}));
      throw new Error(d.error || 'Too many attempts');
    }
    if (!res.ok && res.status >= 502 && IS_GITHUB_PORTAL && !retried && currentPin) {
      await resolvePortalApiBase(currentPin);
      return apiFetch(pathWithSlash, options, true);
    }
    return res;
  } catch (err) {
    if (IS_GITHUB_PORTAL && !retried && currentPin && err.message !== 'Unauthorized') {
      try {
        await resolvePortalApiBase(currentPin);
        return await apiFetch(pathWithSlash, options, true);
      } catch (e) {}
    }
    throw err;
  }
}

// ---------------- PIN KEYPAD, KEYBOARD & AUTH ----------------
function showPinModal() {
  enteredPin = '';
  updatePinDots();
  pinError.textContent = '';
  pinLockModal.classList.remove('hidden');
}

function hidePinModal() {
  pinLockModal.classList.add('hidden');
}

function updatePinDots() {
  const dots = pinDots.querySelectorAll('.dot');
  dots.forEach((dot, index) => {
    if (index < enteredPin.length) dot.classList.add('filled');
    else dot.classList.remove('filled');
  });
}

async function verifyPin(pinToTest) {
  if (isVerifyingPin) return;
  isVerifyingPin = true;
  pinError.style.color = 'var(--text-secondary)';
  pinError.textContent = 'Connecting to workstation...';

  try {
    if (IS_GITHUB_PORTAL) {
      await resolvePortalApiBase(pinToTest);
    } else {
      updateConnectionBadge();
    }

    const res = await fetch(buildApiUrl('/api/auth/login'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin: pinToTest })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      currentPin = pinToTest;
      localStorage.setItem('antigravity_pin', currentPin);
      pinError.textContent = '';
      hidePinModal();
      initApp();
    } else {
      pinError.style.color = 'var(--danger)';
      pinError.textContent = data.error || 'Incorrect PIN. Try again.';
      enteredPin = '';
      updatePinDots();
      if (res.status === 401 || res.status === 429) {
        localStorage.removeItem('antigravity_pin');
        showPinModal();
      }
    }
  } catch (err) {
    pinError.style.color = 'var(--danger)';
    if (err && err.isPinError) {
      pinError.textContent = 'Incorrect PIN. Try again.';
      localStorage.removeItem('antigravity_pin');
    } else {
      pinError.textContent = 'Connection error. Verifying workstation tunnel...';
    }
    enteredPin = '';
    updatePinDots();
    showPinModal();
  } finally {
    isVerifyingPin = false;
  }
}

function handlePinDigit(digit) {
  if (isVerifyingPin || enteredPin.length >= 4) return;
  enteredPin += digit;
  updatePinDots();

  const btn = document.querySelector(`.key-btn[data-key="${digit}"]`);
  if (btn) {
    btn.classList.add('pressed');
    setTimeout(() => btn.classList.remove('pressed'), 130);
  }

  if (enteredPin.length === 4) {
    verifyPin(enteredPin);
  }
}

function handlePinBackspace() {
  if (isVerifyingPin || enteredPin.length === 0) return;
  enteredPin = enteredPin.slice(0, -1);
  updatePinDots();
}

document.querySelectorAll('.key-btn[data-key]').forEach(btn => {
  btn.addEventListener('click', () => handlePinDigit(btn.dataset.key));
});

document.getElementById('pinBackspaceBtn')?.addEventListener('click', handlePinBackspace);

document.getElementById('logoutBtn')?.addEventListener('click', () => {
  localStorage.removeItem('antigravity_pin');
  sessionStorage.removeItem('antigravity_api_base');
  currentPin = '';
  if (currentEventSource) currentEventSource.close();
  showPinModal();
});

// ---------------- DESKTOP INSPECTOR & MOBILE TAB NAVIGATION ----------------
const tabItems = document.querySelectorAll('.tab-item');
const tabPanes = document.querySelectorAll('.tab-pane');

function applyDesktopInspectorState() {
  const artPane = document.getElementById('artifactsView');
  const sysPane = document.getElementById('systemView');
  artPane?.classList.toggle('desktop-inspector-open', activeDesktopInspector === 'artifactsView');
  sysPane?.classList.toggle('desktop-inspector-open', activeDesktopInspector === 'systemView');
  toggleArtifactsDrawerBtn?.classList.toggle('active', activeDesktopInspector === 'artifactsView');
  toggleSystemDrawerBtn?.classList.toggle('active', activeDesktopInspector === 'systemView');

  if (activeDesktopInspector === 'systemView') loadSystemStatus();
  if (activeDesktopInspector === 'artifactsView' && currentConversationId) loadArtifacts(currentConversationId);
}

function toggleDesktopInspector(targetId) {
  if (activeDesktopInspector === targetId) {
    activeDesktopInspector = '';
  } else {
    activeDesktopInspector = targetId;
  }
  localStorage.setItem('antigravity_inspector', activeDesktopInspector);
  applyDesktopInspectorState();
}

toggleArtifactsDrawerBtn?.addEventListener('click', () => toggleDesktopInspector('artifactsView'));
toggleSystemDrawerBtn?.addEventListener('click', () => toggleDesktopInspector('systemView'));
document.querySelectorAll('[data-close-inspector]').forEach(btn => {
  btn.addEventListener('click', () => {
    activeDesktopInspector = '';
    localStorage.setItem('antigravity_inspector', '');
    applyDesktopInspectorState();
  });
});

tabItems.forEach(tab => {
  tab.addEventListener('click', () => {
    const targetId = tab.dataset.tab;
    tabItems.forEach(t => t.classList.remove('active'));
    tabPanes.forEach(p => p.classList.remove('active'));

    tab.classList.add('active');
    document.getElementById(targetId)?.classList.add('active');

    if (targetId === 'historyView') loadConversations();
    if (targetId === 'artifactsView') loadArtifacts(currentConversationId);
    if (targetId === 'systemView') loadSystemStatus();
  });
});

// ---------------- KEYBOARD SHORTCUTS (MACBOOK & DESKTOP) ----------------
document.addEventListener('keydown', (e) => {
  // 1. PIN Lock Screen Keyboard Support
  if (!pinLockModal.classList.contains('hidden')) {
    if (/^[0-9]$/.test(e.key)) {
      e.preventDefault();
      handlePinDigit(e.key);
      return;
    }
    if (e.key === 'Backspace') {
      e.preventDefault();
      handlePinBackspace();
      return;
    }
    if (e.key === 'Escape') {
      enteredPin = '';
      updatePinDots();
      return;
    }
    return;
  }

  // 2. Escape closes open modals
  if (e.key === 'Escape') {
    if (!artifactModal.classList.contains('hidden')) {
      artifactModal.classList.add('hidden');
      return;
    }
    if (!newConvoModal.classList.contains('hidden')) {
      newConvoModal.classList.add('hidden');
      return;
    }
  }

  // 3. Cmd+K / Ctrl+K -> Focus Conversation Search
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (!IS_DESKTOP_WIDTH()) {
      document.querySelector('.tab-item[data-tab="historyView"]')?.click();
    }
    searchConvosInput?.focus();
    searchConvosInput?.select();
    return;
  }

  // 4. Option+N / Alt+N or Cmd+Shift+O -> New Task Modal
  if ((e.altKey && e.key.toLowerCase() === 'n') || ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === 'o')) {
    e.preventDefault();
    openNewConvoModal();
  }
});

// Close modals on backdrop click
[newConvoModal, artifactModal].forEach(modal => {
  modal?.addEventListener('click', (e) => {
    if (e.target === modal) modal.classList.add('hidden');
  });
});

// ---------------- CONVERSATIONS ----------------
async function loadConversations() {
  try {
    const res = await apiFetch('/api/conversations');
    const data = await res.json();
    conversationsList = data.conversations || [];
    renderConversations(conversationsList);
    convosCount.textContent = conversationsList.length;

    if (!currentConversationId && conversationsList.length > 0) {
      selectConversation(conversationsList[0].conversation_id, conversationsList[0].title || conversationsList[0].preview);
    } else if (currentConversationId) {
      const match = conversationsList.find(c => c.conversation_id === currentConversationId);
      selectConversation(currentConversationId, match ? (match.title || match.preview) : 'Active Task');
    }
  } catch (e) {
    console.error('Failed to load conversations:', e);
  }
}

function renderConversations(list) {
  convosList.innerHTML = '';
  if (list.length === 0) {
    convosList.innerHTML = '<p class="empty-hint">No conversations found.</p>';
    return;
  }

  list.forEach(c => {
    const item = document.createElement('div');
    item.dataset.convoId = c.conversation_id;
    item.className = `convo-item ${c.conversation_id === currentConversationId ? 'active' : ''}`;
    
    const title = c.title || c.preview || 'Untitled Task';
    const dateStr = c.last_modified_time ? new Date(c.last_modified_time).toLocaleDateString() : '';
    const preview = c.preview || 'No preview available.';

    item.innerHTML = `
      <div class="convo-top">
        <div class="convo-title">${escapeHtml(title)}</div>
        <div class="convo-time">${dateStr}</div>
      </div>
      <div class="convo-preview">${escapeHtml(preview)}</div>
      <div class="convo-footer">
        <span class="convo-tag">${c.step_count || 0} steps</span>
        <span>ID: ${c.conversation_id.slice(0, 8)}...</span>
      </div>
    `;

    item.addEventListener('click', () => {
      selectConversation(c.conversation_id, title);
      if (!IS_DESKTOP_WIDTH()) {
        document.querySelector('.tab-item[data-tab="chatView"]')?.click();
      }
    });

    convosList.appendChild(item);
  });
}

searchConvosInput?.addEventListener('input', (e) => {
  const query = e.target.value.toLowerCase().trim();
  const filtered = conversationsList.filter(c => 
    (c.title && c.title.toLowerCase().includes(query)) ||
    (c.preview && c.preview.toLowerCase().includes(query))
  );
  renderConversations(filtered);
});

function selectConversation(id, title) {
  currentConversationId = id;
  localStorage.setItem('antigravity_last_convo', id);
  headerConvoTitle.textContent = title || 'Active Task';

  document.querySelectorAll('.convo-item').forEach(el => {
    el.classList.toggle('active', el.dataset.convoId === id);
  });

  loadConversationDetails(id);
  connectSse(id);
}

// ---------------- CODE BLOCK ENHANCEMENT ----------------
function enhanceCodeBlocks(container) {
  container.querySelectorAll('pre code').forEach((block) => {
    try { hljs.highlightElement(block); } catch (e) {}
    const pre = block.parentElement;
    if (!pre || pre.parentElement?.classList.contains('code-block-wrapper')) return;

    const wrapper = document.createElement('div');
    wrapper.className = 'code-block-wrapper';
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);

    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-code-btn';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(block.innerText || block.textContent || '').then(() => {
        copyBtn.textContent = 'Copied ✓';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      });
    });
    wrapper.appendChild(copyBtn);
  });
}

// ---------------- CHAT & TRANSCRIPT ----------------
async function loadConversationDetails(id) {
  if (!id) return;
  try {
    chatMessages.innerHTML = '';
    const res = await apiFetch(`/api/conversations/${id}`);
    const data = await res.json();

    if (data.summary) {
      headerConvoTitle.textContent = data.summary.title || data.summary.preview || 'Active Task';
    }

    // Update artifacts count & drawer simultaneously
    const artifacts = data.artifacts || [];
    if (desktopArtifactsCount) desktopArtifactsCount.textContent = artifacts.length;
    renderArtifacts(artifacts);

    if (!data.steps || data.steps.length === 0) {
      chatMessages.appendChild(emptyState);
      return;
    }

    renderTranscriptSteps(data.steps);
    scrollChatBottom();
  } catch (err) {
    console.error('Failed to load conversation details:', err);
  }
}

function renderTranscriptSteps(steps) {
  chatMessages.innerHTML = '';
  steps.forEach(step => {
    appendStepElement(step);
  });
}

function appendStepElement(step) {
  // 1. User Message
  if (step.source === 'USER_EXPLICIT' && (step.displayContent || step.content)) {
    const text = step.displayContent || step.content;
    const row = document.createElement('div');
    row.className = 'message-row user';
    row.id = `step-${step.step_index}`;
    row.innerHTML = `<div class="bubble user">${escapeHtml(text)}</div>`;
    chatMessages.appendChild(row);
    return;
  }

  // 2. Model Planner Response
  if (step.source === 'MODEL') {
    const row = document.createElement('div');
    row.className = 'message-row model';
    row.id = `step-${step.step_index}`;

    let html = '';

    if (step.thinking) {
      html += `
        <div class="thinking-card">
          <div class="thinking-header" onclick="this.parentElement.classList.toggle('open')">
            <span>🧠 Thinking Process</span>
            <span class="chevron">▼</span>
          </div>
          <div class="thinking-content">${escapeHtml(step.thinking)}</div>
        </div>
      `;
    }

    if (step.tool_calls && step.tool_calls.length > 0) {
      step.tool_calls.forEach(tc => {
        const action = tc.toolAction || tc.name;
        const argsJson = typeof tc.args === 'string' ? tc.args : JSON.stringify(tc.args, null, 2);

        html += `
          <div class="tool-card">
            <div class="tool-header" onclick="this.parentElement.classList.toggle('open')">
              <div>
                <span class="tool-badge">🛠️ ${escapeHtml(tc.name)}</span>
                <span>${escapeHtml(action)}</span>
              </div>
              <span style="font-size: 11px; opacity: 0.6;">Details ▼</span>
            </div>
            <div class="tool-details"><b>Arguments:</b>\n${escapeHtml(argsJson)}</div>
          </div>
        `;
      });
    }

    if (step.content) {
      const rendered = marked.parse(step.content);
      html += `<div class="bubble model">${rendered}</div>`;
    }

    if (html) {
      row.innerHTML = html;
      chatMessages.appendChild(row);
      enhanceCodeBlocks(row);
    }
  }

  // 3. Generic Tool Execution Output
  if (step.source === 'MODEL' && step.type === 'GENERIC' && step.content) {
    const prev = chatMessages.lastElementChild;
    if (prev && prev.classList.contains('model')) {
      const lastToolDetails = prev.querySelector('.tool-card:last-of-type .tool-details');
      if (lastToolDetails) {
        lastToolDetails.innerHTML += `\n\n<b>Output:</b>\n${escapeHtml(step.content)}`;
      }
    }
  }
}

function scrollChatBottom() {
  setTimeout(() => {
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }, 50);
}

// ---------------- REAL-TIME SSE STREAMING ----------------
function connectSse(id) {
  if (currentEventSource) {
    currentEventSource.close();
  }
  if (sseReconnectTimer) {
    clearTimeout(sseReconnectTimer);
    sseReconnectTimer = null;
  }
  if (!id) return;

  const url = buildApiUrl(`/api/conversations/${id}/stream?pin=${encodeURIComponent(currentPin)}`);
  currentEventSource = new EventSource(url);

  currentEventSource.onopen = () => {
    connectionOrb.className = 'orb-pulsing';
  };

  currentEventSource.onmessage = (e) => {
    try {
      const step = JSON.parse(e.data);
      const existing = document.getElementById(`step-${step.step_index}`);
      if (!existing) {
        if (emptyState && emptyState.parentNode === chatMessages) {
          chatMessages.removeChild(emptyState);
        }
        appendStepElement(step);
        scrollChatBottom();
      }

      if (step.thinking || (step.tool_calls && step.tool_calls.length > 0)) {
        connectionOrb.className = 'orb-pulsing thinking';
      } else {
        connectionOrb.className = 'orb-pulsing';
      }
    } catch (err) {}
  };

  currentEventSource.onerror = () => {
    connectionOrb.className = 'orb-pulsing disconnected';
    if (IS_GITHUB_PORTAL && currentPin && !sseReconnectTimer) {
      sseReconnectTimer = setTimeout(async () => {
        sseReconnectTimer = null;
        try {
          const prevBase = apiBase;
          await resolvePortalApiBase(currentPin);
          if (apiBase !== prevBase && currentConversationId) {
            connectSse(currentConversationId);
          }
        } catch (e) {}
      }, 5000);
    }
  };
}

// ---------------- SEND MESSAGE ----------------
async function sendMessage() {
  const text = promptInput.value.trim();
  if (!text) return;

  // If no conversation is selected yet, start a new conversation seamlessly
  if (!currentConversationId) {
    promptInput.value = '';
    promptInput.style.height = 'auto';
    sendBtn.disabled = true;
    try {
      const res = await apiFetch('/api/conversations/new', {
        method: 'POST',
        body: JSON.stringify({ prompt: text, title: text.slice(0, 60), model: 'default' })
      });
      const data = await res.json();
      if (data.success && data.conversationId) {
        await loadConversations();
        selectConversation(data.conversationId, text.slice(0, 60));
      }
    } catch (e) {
      alert('Failed to start conversation. Verify workstation connection.');
    } finally {
      sendBtn.disabled = false;
    }
    return;
  }

  promptInput.value = '';
  promptInput.style.height = 'auto';
  sendBtn.disabled = true;

  if (emptyState && emptyState.parentNode === chatMessages) {
    chatMessages.removeChild(emptyState);
  }

  const userRow = document.createElement('div');
  userRow.className = 'message-row user';
  userRow.innerHTML = `<div class="bubble user">${escapeHtml(text)}</div>`;
  chatMessages.appendChild(userRow);
  scrollChatBottom();

  connectionOrb.className = 'orb-pulsing thinking';

  try {
    await apiFetch(`/api/conversations/${currentConversationId}/send`, {
      method: 'POST',
      body: JSON.stringify({ message: text, device: CLIENT_DEVICE })
    });
  } catch (e) {
    console.error('Failed to send message:', e);
    alert('Failed to send instruction. Please verify workstation connection.');
  } finally {
    sendBtn.disabled = false;
    promptInput.focus();
  }
}

sendBtn.addEventListener('click', sendMessage);
promptInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

promptInput.addEventListener('input', () => {
  promptInput.style.height = 'auto';
  promptInput.style.height = `${Math.min(promptInput.scrollHeight, 140)}px`;
});

// ---------------- QUICK PROMPTS & SLASH COMMANDS ----------------
document.querySelectorAll('.quick-prompt-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    promptInput.value = btn.dataset.prompt;
    promptInput.focus();
  });
});

slashToggleBtn?.addEventListener('click', () => {
  slashBar.classList.toggle('hidden');
});

document.querySelectorAll('.slash-tag').forEach(tag => {
  tag.addEventListener('click', () => {
    promptInput.value = `${tag.dataset.cmd} ${promptInput.value}`;
    slashBar.classList.add('hidden');
    promptInput.focus();
  });
});

// ---------------- VOICE DICTATION ----------------
if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  speechRecognizer = new SpeechRecognition();
  speechRecognizer.continuous = false;
  speechRecognizer.interimResults = false;
  speechRecognizer.lang = 'en-US';

  speechRecognizer.onresult = (event) => {
    const transcript = event.results[0][0].transcript;
    promptInput.value += (promptInput.value ? ' ' : '') + transcript;
    promptInput.style.height = 'auto';
    promptInput.style.height = `${Math.min(promptInput.scrollHeight, 140)}px`;
  };

  speechRecognizer.onerror = () => {
    isRecording = false;
    micBtn.classList.remove('recording');
  };

  speechRecognizer.onend = () => {
    isRecording = false;
    micBtn.classList.remove('recording');
  };

  micBtn.addEventListener('click', () => {
    if (!isRecording) {
      try {
        speechRecognizer.start();
        isRecording = true;
        micBtn.classList.add('recording');
      } catch (err) {}
    } else {
      speechRecognizer.stop();
      isRecording = false;
      micBtn.classList.remove('recording');
    }
  });
} else {
  micBtn.style.display = 'none';
}

// ---------------- NEW CONVERSATION MODAL ----------------
function openNewConvoModal() {
  newConvoModal.classList.remove('hidden');
  setTimeout(() => document.getElementById('newConvoPrompt')?.focus(), 50);
}

newConvoBtn?.addEventListener('click', openNewConvoModal);
desktopNewConvoBtn?.addEventListener('click', openNewConvoModal);

convoDropdownBtn?.addEventListener('click', () => {
  if (!IS_DESKTOP_WIDTH()) {
    document.querySelector('.tab-item[data-tab="historyView"]')?.click();
  }
});

closeNewConvoBtn?.addEventListener('click', () => {
  newConvoModal.classList.add('hidden');
});

startConvoSubmitBtn?.addEventListener('click', async () => {
  const title = document.getElementById('newConvoTitle').value.trim();
  const prompt = document.getElementById('newConvoPrompt').value.trim();
  const model = document.querySelector('input[name="modelTier"]:checked')?.value || 'default';

  if (!prompt) {
    alert('Please enter an instruction or prompt.');
    return;
  }

  startConvoSubmitBtn.disabled = true;
  startConvoSubmitBtn.textContent = 'Starting Task...';

  try {
    const res = await apiFetch('/api/conversations/new', {
      method: 'POST',
      body: JSON.stringify({ prompt, title, model })
    });
    const data = await res.json();

    if (data.success && data.conversationId) {
      newConvoModal.classList.add('hidden');
      document.getElementById('newConvoTitle').value = '';
      document.getElementById('newConvoPrompt').value = '';
      await loadConversations();
      selectConversation(data.conversationId, title || prompt);
      if (!IS_DESKTOP_WIDTH()) {
        document.querySelector('.tab-item[data-tab="chatView"]')?.click();
      }
    } else {
      alert('Could not start conversation: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    alert('Error connecting to Antigravity: ' + err.message);
  } finally {
    startConvoSubmitBtn.disabled = false;
    startConvoSubmitBtn.textContent = 'Start Task';
  }
});

// ---------------- ARTIFACTS ----------------
async function loadArtifacts(id) {
  if (!id) return;
  try {
    const res = await apiFetch(`/api/conversations/${id}`);
    const data = await res.json();
    const artifacts = data.artifacts || [];
    if (desktopArtifactsCount) desktopArtifactsCount.textContent = artifacts.length;
    renderArtifacts(artifacts);
  } catch (e) {
    console.error('Failed to load artifacts:', e);
  }
}

function renderArtifacts(artifacts) {
  artifactsList.innerHTML = '';
  if (artifacts.length === 0) {
    artifactsList.innerHTML = '<p class="empty-hint">No artifacts generated in this conversation yet.</p>';
    return;
  }

  artifacts.forEach(a => {
    const card = document.createElement('div');
    card.className = 'artifact-card';
    const isDoc = a.name.endsWith('.md') || a.name.endsWith('.txt');
    const isImg = /\.(png|jpg|jpeg|svg|webp)$/i.test(a.name);
    const icon = isDoc ? '📄' : (isImg ? '🖼️' : '📦');

    card.innerHTML = `
      <div class="artifact-icon">${icon}</div>
      <div class="artifact-info">
        <div class="artifact-name">${escapeHtml(a.name)}</div>
        <div class="artifact-meta">${formatBytes(a.sizeBytes)} &bull; Click to open</div>
      </div>
    `;

    card.addEventListener('click', () => viewArtifact(a.name));
    artifactsList.appendChild(card);
  });
}

async function viewArtifact(filename) {
  if (!currentConversationId) return;
  try {
    artifactTitle.textContent = filename;
    artifactContent.innerHTML = '<p>Loading artifact...</p>';
    artifactModal.classList.remove('hidden');

    if (filename.match(/\.(png|jpg|jpeg|svg|webp)$/i)) {
      const imgUrl = buildApiUrl(`/api/conversations/${currentConversationId}/artifacts/${encodeURIComponent(filename)}?pin=${encodeURIComponent(currentPin)}`);
      artifactContent.innerHTML = `<img src="${imgUrl}" style="max-width: 100%; border-radius: 8px;">`;
      return;
    }

    const res = await apiFetch(`/api/conversations/${currentConversationId}/artifacts/${encodeURIComponent(filename)}`);
    const data = await res.json();
    if (data.ext === '.md') {
      artifactContent.innerHTML = marked.parse(data.content);
      enhanceCodeBlocks(artifactContent);
    } else {
      artifactContent.innerHTML = `<pre><code>${escapeHtml(data.content)}</code></pre>`;
      enhanceCodeBlocks(artifactContent);
    }
  } catch (e) {
    artifactContent.innerHTML = `<p style="color: var(--danger)">Error loading artifact: ${escapeHtml(e.message)}</p>`;
  }
}

closeArtifactBtn?.addEventListener('click', () => {
  artifactModal.classList.add('hidden');
});

// ---------------- SYSTEM STATUS & RUNNER ----------------
async function loadSystemStatus() {
  try {
    const res = await fetch(buildApiUrl('/api/status'));
    const data = await res.json();

    const portalEl = document.getElementById('statPortalUrl');
    if (portalEl && data.portalUrl) portalEl.textContent = data.portalUrl;
    document.getElementById('statLocalIp').textContent = data.localUrl || '-';
    document.getElementById('statTunnelUrl').textContent = data.tunnelUrl || 'Active on Home Wi-Fi';
    document.getElementById('statAgentReady').textContent = data.agentReady ? '🟢 Ready & Listening' : '🔴 Offline';
    document.getElementById('statMem').textContent = `${data.freeMemMb} MB free of ${data.totalMemMb} MB`;

    document.getElementById('copyUrlBtn').onclick = () => {
      const url = data.portalUrl || data.tunnelUrl || data.localUrl;
      navigator.clipboard.writeText(url).then(() => alert('Permanent link copied to clipboard!'));
    };

    document.getElementById('viewQrBtn').onclick = () => {
      window.open(buildApiUrl('/mac'), '_blank');
    };
  } catch (err) {}
}

async function runQuickShellCommand() {
  const cmd = document.getElementById('terminalCmdInput').value.trim();
  const out = document.getElementById('terminalOutput');
  if (!cmd) return;

  out.textContent = `Running: ${cmd}...\n`;
  try {
    const res = await apiFetch('/api/system/exec', {
      method: 'POST',
      body: JSON.stringify({ command: cmd })
    });
    const data = await res.json();
    out.textContent = data.stdout || data.stderr || 'Command executed with no output.';
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

document.getElementById('runCmdBtn')?.addEventListener('click', runQuickShellCommand);
document.getElementById('terminalCmdInput')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    runQuickShellCommand();
  }
});

// ---------------- UTILS ----------------
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, (m) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  })[m]);
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ---------------- INIT ----------------
function initApp() {
  applyDesktopInspectorState();
  loadConversations();
  loadSystemStatus();
}

// Service Worker Registration (relative path works on both / and /antigravity/)
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('./sw.js').catch(() => {});
}

// Check auth on startup
if (!currentPin) {
  showPinModal();
} else {
  verifyPin(currentPin);
}
