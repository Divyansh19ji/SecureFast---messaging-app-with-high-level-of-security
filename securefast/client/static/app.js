"use strict";

let appState = null;
let activeTab = "chat";
let uiSocket = null;
let typingTimeout = null;
let toastTimer = null;

const $ = (id) => document.getElementById(id);

function showToast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.className = "toast show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3600);
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function roleBadgeClass(role) {
  if (role === "ADMIN") return "badge badge-admin";
  if (role === "GUEST") return "badge badge-guest";
  return "badge badge-member";
}

async function apiPost(path, body = {}) {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || data.error || `HTTP ${resp.status}`);
  }
  return data;
}

function openModal(id) {
  $(id).classList.add("open");
}

function closeModal(id) {
  $(id).classList.remove("open");
}
window.closeModal = closeModal;

function activateShield() {
  document.body.classList.add("shield-active");
}

function unlockShield() {
  document.body.classList.remove("shield-active");
}
window.unlockShield = unlockShield;

// =========================================================================
// Live UI WebSocket Connection to Local Python + C11 Device Engine
// =========================================================================

function connectUiSocket() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  uiSocket = new WebSocket(`${proto}//${location.host}/ws/ui`);

  uiSocket.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "state") {
      appState = msg.data;
      renderAll();
    } else if (msg.type === "message:new") {
      if (!appState) return;
      const idx = appState.messages.findIndex((m) => m.message_id === msg.data.message_id);
      if (idx >= 0) appState.messages[idx] = msg.data;
      else appState.messages.push(msg.data);
      renderMessages();
    } else if (msg.type === "message:update") {
      if (!appState) return;
      const idx = appState.messages.findIndex((m) => m.message_id === msg.data.message_id);
      if (idx >= 0) appState.messages[idx] = msg.data;
      else appState.messages.push(msg.data);
      renderMessages();
    } else if (msg.type === "typing") {
      if (!appState) return;
      appState.peer_typing = Boolean(msg.data.typing);
      renderHeader();
    } else if (msg.type === "alert") {
      showToast(msg.data.message, msg.data.level === "error" || msg.data.level === "warning");
    }
  };

  uiSocket.onclose = () => {
    setTimeout(connectUiSocket, 1500);
  };
}

// =========================================================================
// Rendering Functions
// =========================================================================

function renderAll() {
  if (!appState) return;

  $("engineBadge").textContent = appState.native_engine || "C11 Core";
  if ($("usernameInput").value === "" && appState.username) {
    $("usernameInput").value = appState.username;
  }
  $("roleSelect").value = appState.role || "ADMIN";
  if ($("relayUrlInput").value === "" && appState.relay_url) {
    $("relayUrlInput").value = appState.relay_url;
  }

  $("keyInfo").textContent = `Device ECDH P-256 PubKey: ${appState.public_key_fingerprint}`;

  // Connection badge
  const badge = $("connStatusBadge");
  if (appState.handshake_complete) {
    badge.textContent = "E2EE Active";
    badge.className = "badge badge-member";
  } else if (appState.connection_status === "waiting") {
    badge.textContent = "Waiting for Friend";
    badge.className = "badge badge-guest";
  } else if (appState.connection_status === "connecting") {
    badge.textContent = "Connecting...";
    badge.className = "badge badge-guest";
  } else {
    badge.textContent = "Offline";
    badge.className = "badge badge-admin";
  }

  // Invite QR & one-paste invite code
  if (appState.invite && appState.path_id) {
    $("inviteSection").style.display = "block";
    $("pathIdDisplay").textContent = appState.invite.path_id;
    $("inviteCodeDisplay").textContent = appState.invite.invite_code;
    $("qrImage").src = appState.invite.qr_svg_data_url;
  } else {
    $("inviteSection").style.display = "none";
  }

  // Update allowed clearance options based on local role
  const roleRank = { GUEST: 1, MEMBER: 2, ADMIN: 3 };
  const myRank = roleRank[appState.role] || 2;
  const reqSel = $("requiredRoleSelect");
  for (const opt of reqSel.options) {
    opt.disabled = (roleRank[opt.value] || 1) > myRank;
  }
  if ((roleRank[reqSel.value] || 1) > myRank) {
    reqSel.value = appState.role;
  }

  const canSend = Boolean(appState.handshake_complete);
  $("messageInput").disabled = !canSend;
  $("sendBtn").disabled = !canSend;

  renderHeader();
  renderMessages();
}

function renderHeader() {
  if (!appState) return;
  const hasPath = Boolean(appState.path_id);
  $("destroyPathBtn").style.display = hasPath ? "inline-flex" : "none";
  $("safetyBtn").style.display = appState.safety_number ? "inline-flex" : "none";

  if (!hasPath) {
    $("peerAvatar").textContent = "SF";
    $("peerNameDisplay").textContent = "No Active Path";
    $("peerRoleBadge").style.display = "none";
    $("peerStatusDisplay").textContent = "Create or join an ephemeral 1:1 path to start chatting";
    return;
  }

  const peerName = appState.peer_username || "Waiting for Friend...";
  $("peerAvatar").textContent = peerName.slice(0, 2).toUpperCase();
  $("peerNameDisplay").textContent = peerName;

  if (appState.peer_role) {
    $("peerRoleBadge").style.display = "inline-flex";
    $("peerRoleBadge").className = roleBadgeClass(appState.peer_role);
    $("peerRoleBadge").textContent = appState.peer_role;
  } else {
    $("peerRoleBadge").style.display = "none";
  }

  if (appState.peer_typing) {
    $("peerStatusDisplay").textContent = "typing...";
  } else if (appState.handshake_complete && appState.peer_online) {
    $("peerStatusDisplay").textContent = `online • AES-256-GCM + C11 Anti-OCR Glyphs • Path ${appState.path_id}`;
  } else if (appState.handshake_complete) {
    $("peerStatusDisplay").textContent = `offline (24h encrypted queue active) • Path ${appState.path_id}`;
  } else {
    $("peerStatusDisplay").textContent = `Share Invite Code / QR with friend • Path ${appState.path_id}`;
  }
}

function formatTick(msg) {
  if (msg.direction !== "sent") return "";
  if (msg.status === "read") return `<span class="tick-read">✓✓ Read</span>`;
  if (msg.status === "delivered") return `<span>✓✓ Delivered</span>`;
  if (msg.status === "sending") return `<span>✓ Sending (${msg.acked_chunks}/${msg.total_chunks})</span>`;
  if (msg.status === "burned") return `<span style="color:var(--coral);">🔥 Burned</span>`;
  return `<span>Encrypting...</span>`;
}

function formatTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function renderMessages() {
  if (!appState) return;
  const feed = $("messageFeed");
  const filtered = appState.messages.filter((m) => m.kind === activeTab);

  if (filtered.length === 0) {
    if (activeTab === "vault") {
      feed.innerHTML = `
        <div class="empty-state">
          <h3>🗄️ Role-Gated Encrypted Vault</h3>
          <p>
            Store &amp; share confidential secrets (credentials, API keys, figures) tagged with
            <strong>Role-Based Decryption</strong> (<code>ADMIN</code>, <code>MEMBER</code>, or <code>GUEST</code>).
            Lower-clearance roles mathematically cannot decrypt restricted records!
          </p>
        </div>`;
    } else {
      feed.innerHTML = `
        <div class="empty-state">
          <h3>🔒 Zero-Knowledge Anti-OCR Messaging</h3>
          <p>
            Every token is rendered in <strong>C11</strong> into a key-derived secret geometric glyph image,
            encrypted with <strong>AES-256-GCM</strong>, and relayed in verified <strong>≤ 2 KB chunks</strong>.
          </p>
          <div class="steps-list">
            <div><strong>1.</strong> Save your Display Name &amp; Role on the left.</div>
            <div><strong>2.</strong> Create a Path and send the Invite Code (or QR) to your friend.</div>
            <div><strong>3.</strong> Received messages stay locked until tapped; click <em>🔍 5 Forms</em> to inspect the glyphs!</div>
          </div>
        </div>`;
    }
    return;
  }

  feed.innerHTML = filtered
    .map((m) => {
      const titleHtml = m.vault_title
        ? `<div style="font-weight:700;color:var(--accent);margin-bottom:5px;">🗄️ ${escapeHtml(m.vault_title)}</div>`
        : "";

      let bodyHtml = "";
      if (m.status === "burned") {
        bodyHtml = `<div class="burned-text">🔥 Message burned — plaintext &amp; glyph buffers scrubbed from memory.</div>`;
      } else if (m.status === "locked_role") {
        bodyHtml = `
          <div class="locked-box" style="cursor:not-allowed;">
            <div class="locked-title">🛡️ Role-Based Decryption Denied</div>
            <div class="locked-sub">
              Requires <strong>${escapeHtml(m.required_role)}</strong> clearance. Your device role is
              <strong>${escapeHtml(appState.role)}</strong>, so the HKDF decryption key is not held on this device.
            </div>
          </div>`;
      } else if (m.direction === "received" && !m.revealed) {
        const thumbs = (m.glyph_preview || [])
          .map((g) => `<img class="glyph-thumb" src="${g.data_url}" alt="Secret Glyph" />`)
          .join("");
        bodyHtml = `
          <div class="locked-box" onclick="revealMsg('${escapeHtml(m.message_id)}')">
            <div class="locked-title">🔒 Tap to Reveal Decrypted Message</div>
            <div class="locked-sub">
              Decoded ${m.total_chunks} verified ≤ 2 KB chunk(s) in ${m.latency_ms} ms (C11 match ${(m.decode_confidence * 100).toFixed(1)}%).
            </div>
            ${thumbs ? `<div class="glyph-strip">${thumbs}</div>` : ""}
          </div>`;
      } else {
        bodyHtml = `${titleHtml}<div class="bubble-body">${escapeHtml(m.text)}</div>`;
      }

      const burnBadge =
        m.remaining_sec !== null && m.remaining_sec !== undefined && m.status !== "burned"
          ? `<span style="color:var(--coral);font-weight:600;">🔥 ${m.remaining_sec}s</span>`
          : "";

      const inspectBtn = m.has_inspector
        ? `<button class="inspect-link" onclick="inspectMsg('${escapeHtml(m.message_id)}')">🔍 5 Forms</button>`
        : "";

      return `
        <div class="msg-row ${m.direction}">
          <div class="bubble">
            <div class="bubble-top">
              <span><strong>${escapeHtml(m.sender_name)}</strong></span>
              <span class="${roleBadgeClass(m.required_role)}">${escapeHtml(m.required_role)}</span>
            </div>
            ${bodyHtml}
            <div class="bubble-footer">
              <div class="row-gap">
                <span>${formatTime(m.timestamp)}</span>
                <span>• ${m.total_chunks} chunk(s) • ${m.latency_ms} ms</span>
                ${burnBadge}
              </div>
              <div class="row-gap">
                ${inspectBtn}
                ${formatTick(m)}
              </div>
            </div>
          </div>
        </div>`;
    })
    .join("");

  feed.scrollTop = feed.scrollHeight;
}

// =========================================================================
// Actions
// =========================================================================

async function revealMsg(messageId) {
  try {
    await apiPost(`/api/messages/${encodeURIComponent(messageId)}/reveal`);
  } catch (err) {
    showToast(err.message, true);
  }
}
window.revealMsg = revealMsg;

async function inspectMsg(messageId) {
  try {
    const resp = await fetch(`/api/messages/${encodeURIComponent(messageId)}/inspect`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Unable to inspect message");

    if (data.burned) {
      $("inspectorBody").innerHTML = `<p class="burned-text">Message has self-destructed and been scrubbed.</p>`;
      openModal("inspectorModal");
      return;
    }

    if (data.role_denied) {
      $("inspectorBody").innerHTML = `
        <div class="form-stage">
          <h4>🛡️ Role-Based Decryption Gate</h4>
          <p style="font-size:0.84rem;color:var(--text-secondary);">
            Required Clearance: <strong>${escapeHtml(data.required_role)}</strong> | Your Device Role: <strong>${escapeHtml(data.local_role)}</strong>.<br/>
            Because HKDF derives isolated keys per role, this device only holds the encrypted ciphertext chunks below:
          </p>
          ${(data.chunks || []).map((c) => `
            <div class="chunk-row">
              Chunk #${c.chunk_index + 1}/${c.total_chunks} • ${c.ciphertext_bytes} B • IV=${escapeHtml(c.iv_b64)}<br/>
              SHA-256=${escapeHtml(c.checksum_hex)}
            </div>`).join("")}
        </div>`;
      openModal("inspectorModal");
      return;
    }

    const tokenPills = (data.form2_tokens || [])
      .map((t) => `<span class="token-pill">${escapeHtml(t === " " ? "␣" : t)}</span>`)
      .join("");

    const glyphImgs = (data.glyph_images || [])
      .map(
        (g) => `
        <div style="display:inline-flex;flex-direction:column;align-items:center;margin:4px;">
          <img src="${g.data_url}" alt="Glyph ${g.index}" style="height:36px;border-radius:6px;border:1px solid var(--border);" />
          <span style="font-size:0.65rem;color:var(--text-muted);">#${g.index} (${g.png_bytes} B)</span>
        </div>`
      )
      .join("");

    const chunkRows = (data.chunks || [])
      .map(
        (c) => `
        <div class="chunk-row">
          <strong>Chunk ${c.chunk_index + 1}/${c.total_chunks}</strong> — ${c.ciphertext_bytes} B (≤ 2048 B) • IV: <code>${escapeHtml(c.iv_b64)}</code><br/>
          Ciphertext: <code>${escapeHtml(c.ciphertext_preview)}</code><br/>
          SHA-256: <code>${escapeHtml(c.checksum_hex)}</code>
        </div>`
      )
      .join("");

    $("inspectorBody").innerHTML = `
      <div class="form-stage">
        <h4>Engine &amp; Performance</h4>
        <div style="font-size:0.82rem;color:var(--text-secondary);">
          Native Core: <code>${escapeHtml(data.native_engine)}</code> • Pipeline Latency: <strong>${data.latency_ms} ms</strong> •
          RBAC Tier: <strong>${escapeHtml(data.required_role)}</strong> • Bundle Size: <strong>${data.bundle_bytes} B</strong>
        </div>
      </div>
      <div class="form-stage">
        <h4>Form 2 — Atomic Tokens (${data.token_count} total)</h4>
        <div>${tokenPills}</div>
      </div>
      <div class="form-stage">
        <h4>Form 3 — C11 Key-Derived Secret Glyph Images (Anti-OCR / Anti-AI)</h4>
        <div style="font-size:0.75rem;color:var(--text-secondary);margin-bottom:6px;">
          Generated via BCH(15,7,5) keyed runes + coral decoy lines + jitter. Unreadable to OCR/AI without your HKDF glyph seed!
        </div>
        <div>${glyphImgs}</div>
      </div>
      <div class="form-stage">
        <h4>Form 4 &amp; 5 — AES-256-GCM Encrypted ≤ 2 KB Chunks &amp; SHA-256 Checksums</h4>
        ${chunkRows}
      </div>`;
    openModal("inspectorModal");
  } catch (err) {
    showToast(err.message, true);
  }
}
window.inspectMsg = inspectMsg;

async function openRelayAudit() {
  try {
    const resp = await fetch("/api/relay/audit");
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Relay unreachable");

    const entries = (data.recent_opaque_chunks || [])
      .slice()
      .reverse()
      .map(
        (e) => `
        <div class="chunk-row">
          Path <code>${escapeHtml(e.path_id)}</code> • Msg <code>${escapeHtml(e.message_id)}</code> • Chunk <strong>${escapeHtml(e.chunk)}</strong>
          • ${e.ciphertext_bytes} B • Role: <strong>${escapeHtml(e.required_role)}</strong> • SHA-256: <code>${escapeHtml(e.checksum_prefix)}</code>
          • Plaintext on server: <strong style="color:var(--accent);">NONE</strong>
        </div>`
      )
      .join("");

    $("relayAuditBody").innerHTML = `
      <div class="form-stage">
        <h4>Zero-Knowledge Relay Metrics</h4>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:0.83rem;">
          <div>Messages Decrypted by Server: <strong style="color:var(--accent);">${data.messages_decrypted_by_server}</strong></div>
          <div>Disk Writes: <strong style="color:var(--accent);">${data.disk_writes}</strong></div>
          <div>Active Ephemeral Paths: <strong>${data.active_paths}</strong></div>
          <div>Connected Peers: <strong>${data.connected_peers}</strong></div>
          <div>Total Encrypted Chunks Relayed: <strong>${data.total_chunks_relayed}</strong></div>
          <div>Max Chunk Limit: <strong>${data.max_chunk_bytes} bytes</strong></div>
        </div>
      </div>
      <div class="form-stage">
        <h4>Recent Opaque Chunks Seen by Relay (Ciphertext Metadata Only)</h4>
        ${entries || '<div style="font-size:0.82rem;color:var(--text-muted);">No chunks relayed yet. Send a message to observe live zero-knowledge traffic!</div>'}
      </div>`;
    openModal("relayModal");
  } catch (err) {
    showToast(err.message, true);
  }
}

// =========================================================================
// Event Listeners
// =========================================================================

$("saveIdentityBtn").addEventListener("click", async () => {
  try {
    const username = $("usernameInput").value.trim();
    const role = $("roleSelect").value;
    const relay_url = $("relayUrlInput").value.trim();
    appState = await apiPost("/api/identity", { username, role, relay_url });
    renderAll();
    showToast(`Identity saved as ${username} (${role}). Local ECDH keys ready!`);
  } catch (err) {
    showToast(err.message, true);
  }
});

$("createPathBtn").addEventListener("click", async () => {
  try {
    if (!appState || !appState.username) {
      const name = $("usernameInput").value.trim();
      if (!name) return showToast("Enter your Display Name first!", true);
      await apiPost("/api/identity", {
        username: name,
        role: $("roleSelect").value,
        relay_url: $("relayUrlInput").value.trim(),
      });
    }
    appState = await apiPost("/api/path/create", {
      relay_url: $("relayUrlInput").value.trim(),
    });
    renderAll();
    showToast(`Path ${appState.path_id} created! Share the Invite Code or QR with your friend.`);
  } catch (err) {
    showToast(err.message, true);
  }
});

$("joinPathBtn").addEventListener("click", async () => {
  try {
    if (!appState || !appState.username) {
      const name = $("usernameInput").value.trim();
      if (!name) return showToast("Enter your Display Name first!", true);
      await apiPost("/api/identity", {
        username: name,
        role: $("roleSelect").value,
        relay_url: $("relayUrlInput").value.trim(),
      });
    }
    const raw = $("joinInput").value.trim();
    if (!raw) return showToast("Paste your friend's Invite Code or Path ID", true);
    appState = await apiPost("/api/path/join", {
      path_id: raw,
      relay_url: $("relayUrlInput").value.trim(),
    });
    renderAll();
    showToast(`Joined Path ${appState.path_id}! Completing ECDH P-256 handshake...`);
  } catch (err) {
    showToast(err.message, true);
  }
});

$("copyInviteBtn").addEventListener("click", async () => {
  if (!appState?.invite?.invite_code) return;
  try {
    await navigator.clipboard.writeText(appState.invite.invite_code);
    showToast("Invite Code copied! Send it to your friend.");
  } catch {
    showToast("Select and copy the Invite Code manually.", false);
  }
});

$("safetyBtn").addEventListener("click", () => {
  if (!appState?.safety_number) return;
  $("safetyNumberDigits").textContent = appState.safety_number;
  openModal("safetyModal");
});

$("relayAuditBtn").addEventListener("click", openRelayAudit);

$("destroyPathBtn").addEventListener("click", async () => {
  try {
    appState = await apiPost("/api/path/leave?destroy=true");
    renderAll();
    showToast("Path destroyed and session keys scrubbed from memory.");
  } catch (err) {
    showToast(err.message, true);
  }
});

async function handleSend() {
  const input = $("messageInput");
  const text = input.value.trim();
  if (!text) return;
  const required_role = $("requiredRoleSelect").value;
  const self_destruct_sec = parseInt($("selfDestructSelect").value, 10) || 0;
  const vault_title = activeTab === "vault" ? $("vaultTitleInput").value.trim() || "Encrypted Note" : null;

  input.value = "";
  if (activeTab === "vault") $("vaultTitleInput").value = "";

  try {
    await apiPost("/api/messages/send", {
      text,
      required_role,
      self_destruct_sec,
      kind: activeTab,
      vault_title,
    });
    apiPost("/api/typing", { typing: false }).catch(() => {});
  } catch (err) {
    showToast(err.message, true);
    input.value = text;
  }
}

$("sendBtn").addEventListener("click", handleSend);
$("messageInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    handleSend();
  }
});

$("messageInput").addEventListener("input", () => {
  apiPost("/api/typing", { typing: true }).catch(() => {});
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => {
    apiPost("/api/typing", { typing: false }).catch(() => {});
  }, 1400);
});

for (const btn of document.querySelectorAll(".tab-btn")) {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    activeTab = btn.dataset.tab;
    $("vaultTitleInput").style.display = activeTab === "vault" ? "inline-block" : "none";
    $("messageInput").placeholder =
      activeTab === "vault"
        ? "Enter confidential vault secret (encrypted & role-gated)..."
        : "Type a confidential message... (converted to secret glyphs + 2 KB AES-GCM chunks)";
    renderMessages();
  });
}

// Theme toggle
$("themeToggle").addEventListener("click", () => {
  const isLight = document.body.classList.toggle("light-theme");
  $("themeToggle").textContent = isLight ? "🌙" : "☀️";
  localStorage.setItem("sf_theme", isLight ? "light" : "dark");
});

if (localStorage.getItem("sf_theme") === "light") {
  document.body.classList.add("light-theme");
  $("themeToggle").textContent = "🌙";
}

// Privacy Shield (Manual + Auto-blur on focus loss)
$("shieldBtn").addEventListener("click", activateShield);
window.addEventListener("blur", () => {
  if ($("autoShieldToggle").checked) activateShield();
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden && $("autoShieldToggle").checked) activateShield();
});

// Close modals on backdrop click
for (const backdrop of document.querySelectorAll(".modal-backdrop")) {
  backdrop.addEventListener("click", (e) => {
    if (e.target === backdrop) backdrop.classList.remove("open");
  });
}

// Refresh live self-destruct countdown every second
setInterval(() => {
  if (!appState) return;
  let dirty = false;
  for (const m of appState.messages) {
    if (m.remaining_sec !== null && m.remaining_sec !== undefined && m.remaining_sec > 0 && m.status !== "burned") {
      m.remaining_sec = Math.max(0, m.remaining_sec - 1);
      dirty = true;
    }
  }
  if (dirty) renderMessages();
}, 1000);

// Register PWA Service Worker
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js").catch(() => {});
}

// Boot!
connectUiSocket();
