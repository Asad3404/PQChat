// PQ-Chat local UI. Talks only to the local client on this origin; never does crypto.
// Untrusted text (messages, names) is always inserted with textContent.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const TOKEN_KEY = "pqchat-token";

  // The token arrives once in the URL fragment (never sent to a server), then moves to
  // sessionStorage and is removed from the address bar and history.
  const m = location.hash.match(/token=([A-Za-z0-9_-]{20,})/);
  if (m) {
    try { sessionStorage.setItem(TOKEN_KEY, m[1]); } catch (_) { /* private mode */ }
    history.replaceState(null, "", location.pathname);
  }
  let token = m ? m[1] : null;
  try { token = token || sessionStorage.getItem(TOKEN_KEY); } catch (_) { /* ignore */ }

  let current = null;     // open chat name
  let lastVersion = -1;

  async function api(path, body) {
    const opts = { method: body === undefined ? "GET" : "POST", headers: { "X-PQChat-Token": token || "" } };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    if (!res.ok) {
      const err = new Error((data && data.detail) || (data && data.error) || res.statusText);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function time(ts) {
    return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  // ---------------------------------------------------------------- lock screen
  async function showLock(status) {
    $("app").hidden = true;
    $("lock").hidden = false;
    $("lock-title").textContent = status.has_keystore ? "PQ-Chat is locked" : "Create your PQ-Chat identity";
    $("unlock-btn").textContent = status.has_keystore ? "Unlock" : "Create identity";
    $("lock-hint").textContent = status.has_keystore
      ? "Your keys are stored encrypted on this device."
      : "New keys are generated on this device. Choose a passphrase of at least 10 characters.";
  }

  $("unlock-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("lock-error").textContent = "";
    $("unlock-btn").disabled = true;
    $("unlock-btn").textContent = "Working…";
    try {
      await api("/api/unlock", { username: $("username").value, passphrase: $("passphrase").value });
      $("passphrase").value = "";
      await refresh(true);
    } catch (e) {
      $("lock-error").textContent = e.status === 401 ? "Wrong username or passphrase." : "Could not unlock: " + e.message;
      $("unlock-btn").disabled = false;
      $("unlock-btn").textContent = "Unlock";
    }
  });

  // ---------------------------------------------------------------- main view
  function renderList(status) {
    $("me-name").textContent = status.username;
    $("me-avatar").textContent = status.username[0].toUpperCase();
    $("me-status").textContent = (status.connected ? "Connected" : "Offline") + " · " + status.one_time_prekeys + " one-time prekeys";
    const list = $("chat-list");
    list.replaceChildren();
    for (const c of status.chats) {
      const li = el("li");
      const b = el("button", "conv" + (c.name === current ? " on" : ""));
      b.type = "button";
      b.append(el("span", "av", c.name[0].toUpperCase()));
      const mid = el("span");
      mid.append(el("span", "who", c.name));
      mid.append(el("div", "last" + (c.key_changed ? " warn" : ""), c.key_changed ? "Safety number changed" : c.last));
      b.append(mid);
      b.append(el("span", "time", c.ts ? time(c.ts) : ""));
      b.addEventListener("click", () => openChat(c.name));
      li.append(b);
      list.append(li);
    }
  }

  function renderChat(v) {
    $("empty").hidden = true;
    $("thead").hidden = false;
    $("peer-name").textContent = v.name;
    $("peer-avatar").textContent = v.name[0].toUpperCase();
    const st = $("peer-status");
    st.replaceChildren();
    st.append(document.createTextNode(v.session ? "Encrypted · " + v.session.mode + " · " : "No session yet · "));
    st.append(el("span", v.key_changed ? "bad" : v.verified ? "ok" : "", v.key_changed ? "safety number changed" : v.verified ? "verified" : "not verified"));

    const msgs = $("msgs");
    const atBottom = msgs.scrollHeight - msgs.scrollTop - msgs.clientHeight < 40;
    msgs.replaceChildren();
    msgs.append(el("div", "note", "Messages are end-to-end encrypted. Keys never leave this device."));
    for (const msg of v.messages) {
      if (msg.dir === "sys") { msgs.append(el("div", "note err", msg.text)); continue; }
      const b = el("div", "b " + (msg.dir === "out" ? "out" : "in"), msg.text);
      b.append(el("span", "ts", time(msg.ts)));
      msgs.append(b);
    }
    if (v.session && v.session.missing > 0) {
      msgs.append(el("div", "note", v.session.missing + " message(s) from " + v.name + " have not arrived yet"));
    }
    if (atBottom) msgs.scrollTop = msgs.scrollHeight;

    $("blocked").hidden = !v.key_changed;
    $("composer").hidden = v.key_changed;
    $("draft").placeholder = "Message " + v.name;

    const safety = $("safety");
    safety.replaceChildren(...(v.safety_number || []).map((g) => el("span", null, g)));
    $("verify-btn").textContent = v.verified ? "Clear verification" : "Mark as verified";
    $("verify-btn").hidden = !v.safety_number || v.key_changed;
    const enc = $("enc");
    enc.replaceChildren();
    const rows = v.session
      ? [["Mode", v.session.mode], ["Key agreement", "X25519 + ML-KEM-768"], ["Signatures", "Ed25519 + ML-DSA-65"],
         ["ML-KEM refresh", v.session.chains_until_pq === 0 ? "next sending chain" : "in " + v.session.chains_until_pq + " sending chain(s)"]]
      : [["Session", "starts with your first message"]];
    for (const [k, val] of rows) { enc.append(el("dt", null, k)); enc.append(el("dd", null, val)); }
  }

  async function openChat(name) {
    current = name;
    $("app").classList.remove("show-list");
    renderChat(await api("/api/chat/" + encodeURIComponent(name)));
    await refresh(true);
    $("draft").focus();
  }

  $("composer").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const text = $("draft").value;
    if (!text.trim() || !current) return;
    $("draft").value = "";
    try {
      renderChat(await api("/api/chat/" + encodeURIComponent(current) + "/send", { text }));
    } catch (e) {
      $("draft").value = text;
      $("msgs").append(el("div", "note err", e.message === "key_changed" ? "Safety number changed. Sending is paused." : "Not sent: " + e.message));
    }
    await refresh(true);
  });

  $("info-btn").addEventListener("click", () => { $("details").hidden = !$("details").hidden; });
  $("close-details").addEventListener("click", () => { $("details").hidden = true; });
  $("compare-btn").addEventListener("click", () => { $("details").hidden = false; });
  $("accept-btn").addEventListener("click", async () => {
    renderChat(await api("/api/chat/" + encodeURIComponent(current) + "/accept-key", {}));
  });
  $("verify-btn").addEventListener("click", async () => {
    const verified = $("verify-btn").textContent.startsWith("Mark");
    renderChat(await api("/api/chat/" + encodeURIComponent(current) + "/verify", { verified }));
  });
  $("new-chat-btn").addEventListener("click", () => { $("new-name").value = ""; $("new-chat").showModal(); });
  $("new-chat").addEventListener("close", () => {
    const name = $("new-name").value;
    if ($("new-chat").returnValue === "ok" && /^[a-z0-9_]{3,32}$/.test(name)) openChat(name);
  });

  // ---------------------------------------------------------------- polling
  async function refresh(force) {
    let status;
    try { status = await api("/api/status"); } catch (e) {
      if (e.status === 401) { document.body.textContent = "Open the link printed by the PQ-Chat client (it contains your access token)."; }
      return;
    }
    if (status.locked) { await showLock(status); return; }
    $("lock").hidden = true;
    $("app").hidden = false;
    if (!force && status.version === lastVersion) return;
    lastVersion = status.version;
    renderList(status);
    if (current) renderChat(await api("/api/chat/" + encodeURIComponent(current)));
  }

  refresh(true);
  setInterval(() => refresh(false), 1500);
})();
