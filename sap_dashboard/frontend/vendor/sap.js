/* ============================================================================
   sap_dashboard/frontend/vendor/sap.js
   SigmanexSec UI helpers: theme toggle, toasts, 401 reauth interceptor,
   HTMX skeleton hooks, status-bar live updates. Loaded after Alpine + HTMX.
   No external dependencies. CSP-safe (no eval, no inline handlers).
   ============================================================================ */
(function (w) {
  'use strict';

  // ── Theme (dark/light) ────────────────────────────────────────────────────
  const THEME_KEY = 'sap.theme';
  const html = document.documentElement;

  function applyTheme(t) {
    html.classList.remove('dark', 'light');
    html.classList.add(t === 'light' ? 'light' : 'dark');
  }
  function getTheme() {
    try { return localStorage.getItem(THEME_KEY) || 'dark'; } catch (_) { return 'dark'; }
  }
  function setTheme(t) {
    try { localStorage.setItem(THEME_KEY, t); } catch (_) {}
    applyTheme(t);
  }
  function toggleTheme() { setTheme(getTheme() === 'dark' ? 'light' : 'dark'); }

  // Apply ASAP to avoid flash
  applyTheme(getTheme());

  // ── Toasts ────────────────────────────────────────────────────────────────
  function ensureToastContainer() {
    let c = document.getElementById('snx-toasts');
    if (!c) {
      c = document.createElement('div');
      c.id = 'snx-toasts';
      c.setAttribute('aria-live', 'polite');
      c.setAttribute('aria-atomic', 'false');
      document.body.appendChild(c);
    }
    return c;
  }
  const ICONS = { ok: '#icon-check', err: '#icon-alert', warn: '#icon-alert', info: '#icon-info' };
  function toast(opts) {
    if (typeof opts === 'string') opts = { msg: opts };
    const type = opts.type || 'info';
    const ms = opts.ms || (type === 'err' ? 6000 : 3500);
    const c = ensureToastContainer();
    const el = document.createElement('div');
    el.className = 'snx-toast snx-toast--' + type;
    el.setAttribute('role', type === 'err' ? 'alert' : 'status');
    el.innerHTML =
      '<svg class="icon" aria-hidden="true"><use href="/assets/brand/icons.svg' + (ICONS[type] || ICONS.info) + '"/></svg>' +
      '<div class="snx-toast__msg"></div>' +
      '<button class="snx-toast__close" aria-label="Chiudi">' +
      '<svg class="icon" aria-hidden="true"><use href="/assets/brand/icons.svg#icon-x"/></svg></button>';
    el.querySelector('.snx-toast__msg').textContent = String(opts.msg || '');
    el.querySelector('.snx-toast__close').addEventListener('click', () => el.remove());
    c.appendChild(el);
    if (ms > 0) setTimeout(() => el.remove(), ms);
    return el;
  }

  // ── 401 reauth interceptor (modal) ────────────────────────────────────────
  // Wrap fetch so authenticated calls that get 401 trigger a re-auth modal
  // rather than silently failing or doing a hard redirect.
  let reauthInFlight = null;
  function showReauthModal() {
    if (reauthInFlight) return reauthInFlight;
    reauthInFlight = new Promise((resolve) => {
      const backdrop = document.createElement('div');
      backdrop.className = 'snx-modal-backdrop';
      backdrop.setAttribute('role', 'dialog');
      backdrop.setAttribute('aria-modal', 'true');
      backdrop.innerHTML =
        '<div class="snx-glass snx-modal">' +
          '<h2>Sessione scaduta</h2>' +
          '<p>Per motivi di sicurezza la sessione è terminata. Reinserisci le credenziali per continuare.</p>' +
          '<form class="snx-login__form" novalidate>' +
            '<div class="snx-field"><label for="re-user">Username</label>' +
              '<input id="re-user" class="snx-input" autocomplete="username" required></div>' +
            '<div class="snx-field"><label for="re-pass">Password</label>' +
              '<input id="re-pass" class="snx-input" type="password" autocomplete="current-password" required></div>' +
            '<div class="snx-login__error" hidden></div>' +
            '<button class="snx-btn snx-btn--primary snx-btn--block" type="submit">' +
              '<span class="label">Sblocca</span></button>' +
          '</form>' +
        '</div>';
      document.body.appendChild(backdrop);
      const form = backdrop.querySelector('form');
      const errBox = backdrop.querySelector('.snx-login__error');
      const userInput = backdrop.querySelector('#re-user');
      const passInput = backdrop.querySelector('#re-pass');
      try { userInput.value = (w.SAP && w.SAP.lastUser) || ''; } catch(_) {}
      setTimeout(() => (userInput.value ? passInput : userInput).focus(), 50);
      form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        errBox.hidden = true;
        const btn = form.querySelector('button[type=submit]');
        btn.disabled = true;
        try {
          const r = await window._snxOriginalFetch('/api/auth/login', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: userInput.value, password: passInput.value }),
          });
          if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            errBox.textContent = j.detail || 'Credenziali non valide';
            errBox.hidden = false;
            btn.disabled = false;
            return;
          }
          try { w.SAP.lastUser = userInput.value; } catch(_) {}
          backdrop.remove();
          reauthInFlight = null;
          resolve(true);
          toast({ type: 'ok', msg: 'Sessione ripristinata' });
        } catch (e) {
          errBox.textContent = 'Errore di rete';
          errBox.hidden = false;
          btn.disabled = false;
        }
      });
    });
    return reauthInFlight;
  }

  // Patch fetch
  const origFetch = w.fetch.bind(w);
  w._snxOriginalFetch = origFetch;
  w.fetch = async function (input, init) {
    let resp;
    try { resp = await origFetch(input, init); }
    catch (e) { throw e; }
    // Skip handling for the login endpoint itself, and for non-API URLs.
    let url = '';
    try { url = typeof input === 'string' ? input : (input && input.url) || ''; } catch (_) {}
    if (resp.status === 401 && url.indexOf('/api/') === 0 && url.indexOf('/api/auth/login') !== 0) {
      const ok = await showReauthModal();
      if (ok) {
        // Retry the original request once with refreshed cookies.
        const newInit = Object.assign({}, init || {});
        // Refresh CSRF header from cookie if present.
        try {
          const m = document.cookie.match(/(?:^|; )sap_csrf=([^;]+)/);
          const csrf = m ? decodeURIComponent(m[1]) : '';
          if (csrf && newInit.method && /^(POST|PUT|PATCH|DELETE)$/i.test(newInit.method)) {
            newInit.headers = Object.assign({}, newInit.headers || {}, { 'X-CSRF-Token': csrf });
          }
        } catch (_) {}
        return origFetch(input, newInit);
      }
    }
    return resp;
  };

  // ── HTMX skeleton hook & error toast ──────────────────────────────────────
  document.body && document.body.addEventListener('htmx:beforeRequest', (ev) => {
    const t = ev.detail && ev.detail.target;
    if (t && t.dataset && t.dataset.skeleton === 'true') {
      t.classList.add('snx-skeleton');
      t.style.minHeight = t.style.minHeight || '180px';
    }
  });
  document.addEventListener('htmx:afterSwap', (ev) => {
    const t = ev.detail && ev.detail.target;
    if (t) t.classList.remove('snx-skeleton');
  });
  document.addEventListener('htmx:responseError', (ev) => {
    const status = ev.detail && ev.detail.xhr && ev.detail.xhr.status;
    if (status && status !== 401) toast({ type: 'err', msg: 'Errore richiesta (' + status + ')' });
  });

  // ── Public API ────────────────────────────────────────────────────────────
  w.SAP = Object.assign(w.SAP || {}, {
    toast, setTheme, getTheme, toggleTheme,
    showReauthModal,
  });

  // Bind theme toggle button(s) when present
  document.addEventListener('click', (ev) => {
    const t = ev.target.closest && ev.target.closest('[data-snx-action="toggle-theme"]');
    if (t) { ev.preventDefault(); toggleTheme(); }
  });
})(window);
