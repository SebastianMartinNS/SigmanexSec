function app() {
  return {
    tabs: [
      {id:'overview',    label:'Overview'},
      {id:'engagements', label:'Engagements'},
      {id:'agent',       label:'Agent Console'},
      {id:'audit',       label:'Audit Live'},
      {id:'sudo',        label:'Sudo Vault'},
      {id:'parrot',      label:'Parrot Tools'},
      {id:'sessions',    label:'Sessions'},
      {id:'reports',     label:'Reports'},
      {id:'settings',    label:'Settings'},
    ],
    active: 'overview',
    auth: { user: '' },
    csrfToken: '',
    form: { user: '', pass: '' },
    error: '',
    sudoError: '',
    engagements: [],
    selectedEngagement: '',
    runForm: { objective: '', mode: 'execution', max_iterations: 12 },
    currentRun: null,
    runStatus: {},
    events: [],
    ws: null,
    pendingGate: null,
    sudo: { locked: true, ttl_remaining_seconds: 0 },
    sudoForm: { password: '', ttl_seconds: 600 },
    showSudoPw: false,
    parrot: { tools: [] },
    parrotQ: '',
    sessForm: { engagement_id: '', tool: '', args_json: '{}' },
    sessList: [],
    sessError: '',
    activeSession: '',
    sessOutput: '',
    sessInput: '',
    sessExpect: '',
    sessPoll: null,
    settings: {},
    audit: { entries: [], ws: null, filter: '' },
    resetDialog: {
      open: false,
      engagement: null,
      body: { wipe_findings:false, wipe_hosts:false, wipe_credentials:false, wipe_runs:false, wipe_audit:false, delete_engagement:false },
      result: '',
    },

    get parrotFiltered() {
      const q = this.parrotQ.toLowerCase();
      return (this.parrot.tools || []).filter(t =>
        !q || t.name.includes(q) || t.category.includes(q) || (t.description||'').toLowerCase().includes(q)
      );
    },

    init() {
      // Restore session if a valid HttpOnly cookie is present.
      this.csrfToken = this._readCsrfCookie();
      fetch('/api/auth/me', { credentials: 'include' }).then(async r => {
        if (r.ok) {
          const j = await r.json();
          this.auth.user = j.username || '';
          this.afterAuth();
        }
      }).catch(() => {});
      setInterval(() => { if (this.auth.user) this.refreshSudo(); }, 5000);
    },

    /** Human label for a tab id (used by topbar breadcrumb). */
    tabLabel(id) {
      const t = (this.tabs || []).find(x => x.id === id);
      return t ? t.label : (id || '');
    },

    /** Alias for signout(); also issues a redirect to /login. */
    async logout() {
      try { await this.signout(); } catch (_) {}
      try { window.location.href = '/login'; } catch (_) {}
    },

    _readCsrfCookie() {
      const m = document.cookie.match(/(?:^|; )sap_csrf=([^;]+)/);
      return m ? decodeURIComponent(m[1]) : '';
    },

    headers(extra) {
      // Cookie auth: only attach CSRF token for state-changing methods.
      const h = Object.assign({}, extra || {});
      if (this.csrfToken) h['X-CSRF-Token'] = this.csrfToken;
      return h;
    },

    async signin() {
      this.error = '';
      const r = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: this.form.user, password: this.form.pass }),
      });
      if (!r.ok) { this.error = 'Invalid credentials'; return; }
      const j = await r.json();
      this.auth.user = j.username || this.form.user;
      this.csrfToken = this._readCsrfCookie();
      // Wipe legacy localStorage tokens from previous installs.
      try { localStorage.removeItem('sap_user'); localStorage.removeItem('sap_token'); } catch (e) {}
      this.form.pass = '';
      this.afterAuth();
    },

    async signout() {
      try {
        await fetch('/api/auth/logout', { method: 'POST', credentials: 'include', headers: this.headers() });
      } catch (e) {}
      this.auth.user = '';
      this.csrfToken = '';
    },

    async afterAuth() {
      await Promise.all([this.loadEngagements(), this.refreshSudo(), this.loadParrot(), this.loadSettings()]);
    },

    async load(id) {
      if (id === 'engagements') await this.loadEngagements();
      if (id === 'sudo')        await this.refreshSudo();
      if (id === 'parrot')      await this.loadParrot();
      if (id === 'sessions')    { await this.loadParrot(); await this.loadSessions(); }
      if (id === 'settings')    await this.loadSettings();
      if (id === 'audit')       this.openAuditWs();
    },

    async loadEngagements() {
      const r = await fetch('/api/engagements', { headers: this.headers() });
      if (r.ok) this.engagements = await r.json();
    },
    async refreshSudo() {
      // When unlocked, use the heartbeat endpoint so the inactivity timer
      // resets while the operator has the dashboard open.
      const path = this.sudo && !this.sudo.locked ? '/api/sudo/heartbeat' : '/api/sudo/status';
      const opts = path === '/api/sudo/heartbeat'
          ? { method: 'POST', headers: this.headers() }
          : { headers: this.headers() };
      const r = await fetch(path, opts);
      if (r.ok) this.sudo = await r.json();
    },
    async loadParrot() {
      const r = await fetch('/api/parrot/tools', { headers: this.headers() });
      if (r.ok) this.parrot = await r.json();
    },
    get interactiveTools() {
      return (this.parrot.tools || []).filter(t => t.interactive && t.available);
    },
    async loadSessions() {
      const r = await fetch('/api/sessions', { headers: this.headers() });
      if (r.ok) { const j = await r.json(); this.sessList = j.sessions || []; }
    },
    async startSession() {
      this.sessError = '';
      let args = {};
      try { args = JSON.parse(this.sessForm.args_json || '{}'); }
      catch (e) { this.sessError = 'invalid JSON args'; return; }
      const r = await fetch('/api/sessions', {
        method:'POST',
        headers: { ...this.headers(), 'Content-Type':'application/json' },
        body: JSON.stringify({
          tool: this.sessForm.tool,
          engagement_id: this.sessForm.engagement_id,
          args,
        }),
      });
      if (!r.ok) { this.sessError = (await r.json()).detail || 'failed'; return; }
      const j = await r.json();
      this.activeSession = j.session_id;
      this.sessOutput = j.banner || '';
      await this.loadSessions();
      this.startSessionPoll();
    },
    selectSession(sid) {
      this.activeSession = sid;
      this.sessOutput = '';
      this.startSessionPoll();
    },
    startSessionPoll() {
      if (this.sessPoll) clearInterval(this.sessPoll);
      this.sessPoll = setInterval(() => this.loadSessions(), 4000);
    },
    async sendSession() {
      if (!this.activeSession || !this.sessInput) return;
      const r = await fetch(`/api/sessions/${this.activeSession}/send`, {
        method:'POST',
        headers: { ...this.headers(), 'Content-Type':'application/json' },
        body: JSON.stringify({
          text: this.sessInput,
          expect_prompt: this.sessExpect || null,
          timeout: 15,
        }),
      });
      if (!r.ok) { this.sessError = (await r.json()).detail || 'send failed'; return; }
      const j = await r.json();
      this.sessOutput += `\n$ ${this.sessInput}\n` + (j.output || '');
      this.sessInput = '';
    },
    async readSession() {
      if (!this.activeSession) return;
      const r = await fetch(`/api/sessions/${this.activeSession}/read`, {
        method:'POST',
        headers: { ...this.headers(), 'Content-Type':'application/json' },
        body: JSON.stringify({ timeout: 3 }),
      });
      if (r.ok) { const j = await r.json(); this.sessOutput += (j.output || ''); }
    },
    async closeSession(sid) {
      const r = await fetch(`/api/sessions/${sid}`, {
        method:'DELETE', headers: this.headers(),
      });
      if (r.ok && sid === this.activeSession) {
        this.activeSession = ''; this.sessOutput = '';
        if (this.sessPoll) { clearInterval(this.sessPoll); this.sessPoll = null; }
      }
      await this.loadSessions();
    },
    async loadSettings() {
      const r = await fetch('/api/settings', { headers: this.headers() });
      if (r.ok) this.settings = await r.json();
    },

    async unlockSudo() {
      this.sudoError = '';
      const r = await fetch('/api/sudo/unlock', {
        method:'POST', headers: { ...this.headers(), 'Content-Type':'application/json' },
        body: JSON.stringify(this.sudoForm),
      });
      if (!r.ok) { this.sudoError = (await r.json()).detail || 'failed'; return; }
      this.sudoForm.password = '';
      this.sudo = await r.json();
    },
    async lockSudo() {
      const r = await fetch('/api/sudo', { method:'DELETE', headers: this.headers() });
      if (r.ok) this.sudo = await r.json();
    },

    async startRun() {
      this.events = []; this.pendingGate = null;
      const r = await fetch(`/api/engagements/${this.selectedEngagement}/run`, {
        method:'POST', headers: { ...this.headers(), 'Content-Type':'application/json' },
        body: JSON.stringify(this.runForm),
      });
      if (!r.ok) { alert('failed to start run'); return; }
      const status = await r.json();
      this.currentRun = status.run_id;
      this.runStatus = status;
      this.openWs(status.run_id);
    },

    openWs(runId) {
      if (this.ws) try { this.ws.close(); } catch {}
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${proto}//${location.host}/api/runs/${runId}/events/ws`);
      ws.onopen = () => ws.send(JSON.stringify({ type:'auth', token: this.auth.token }));
      ws.onmessage = (m) => {
        const ev = JSON.parse(m.data);
        this.events.push(ev);
        if (ev.type === 'approval_required') this.pendingGate = ev;
        if (ev.type === 'done' || ev.type === 'error') {
          this.runStatus = { ...this.runStatus, state: ev.type === 'done' ? 'done' : 'error' };
        }
        const el = document.getElementById('eventlog');
        if (el) el.scrollTop = el.scrollHeight;
      };
      ws.onclose = () => { this.ws = null; };
      this.ws = ws;
    },

    async control(action) {
      if (!this.currentRun) return;
      const r = await fetch(`/api/runs/${this.currentRun}`, {
        method:'PATCH', headers: { ...this.headers(), 'Content-Type':'application/json' },
        body: JSON.stringify({ action }),
      });
      if (r.ok) this.runStatus = await r.json();
    },

    async resolveGate(decision) {
      if (!this.pendingGate) return;
      await fetch(`/api/runs/${this.currentRun}/approve`, {
        method:'POST', headers: { ...this.headers(), 'Content-Type':'application/json' },
        body: JSON.stringify({ gate_id: this.pendingGate.gate_id, decision, reason: '' }),
      });
      this.pendingGate = null;
    },

    async openAuditWs() {
      // Carica storico iniziale via REST poi attacca il WS tail.
      const r = await fetch('/api/audit?limit=200', { headers: this.headers() });
      if (r.ok) this.audit.entries = await r.json();
      if (this.audit.ws) try { this.audit.ws.close(); } catch {}
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${proto}//${location.host}/api/audit/ws`);
      ws.onopen = () => ws.send(JSON.stringify({ type:'auth', token: this.auth.token }));
      ws.onmessage = (m) => {
        try {
          const ev = JSON.parse(m.data);
          // dedup su id se già presente (history overlap)
          if (ev.id && this.audit.entries.some(e => e.id === ev.id)) return;
          this.audit.entries.push(ev);
          if (this.audit.entries.length > 500) this.audit.entries.splice(0, this.audit.entries.length - 500);
          const el = document.getElementById('auditlog');
          if (el) el.scrollTop = el.scrollHeight;
        } catch {}
      };
      ws.onclose = () => { this.audit.ws = null; };
      this.audit.ws = ws;
    },

    auditFiltered() {
      const q = (this.audit.filter || '').toLowerCase();
      if (!q) return this.audit.entries;
      return this.audit.entries.filter(e =>
        (e.engagement_id||'').toLowerCase().includes(q) ||
        (e.actor||'').toLowerCase().includes(q) ||
        (e.action||'').toLowerCase().includes(q) ||
        (e.target||'').toLowerCase().includes(q) ||
        JSON.stringify(e.details||{}).toLowerCase().includes(q)
      );
    },

    async exportEngagement(id, includeSecrets) {
      const url = `/api/engagements/${id}/export?include_secrets=${includeSecrets ? 1 : 0}`;
      const r = await fetch(url, { headers: this.headers() });
      if (!r.ok) { alert('export failed: ' + r.status); return; }
      const blob = await r.blob();
      const cd = r.headers.get('Content-Disposition') || '';
      const m = cd.match(/filename="?([^"]+)"?/);
      const fname = m ? m[1] : `engagement_${id.slice(0,8)}.zip`;
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = fname;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    },

    openResetDialog(eng) {
      this.resetDialog = {
        open: true,
        engagement: eng,
        body: { wipe_findings:false, wipe_hosts:false, wipe_credentials:false, wipe_runs:true, wipe_audit:false, delete_engagement:false },
        result: '',
      };
    },

    async executeReset() {
      const eng = this.resetDialog.engagement;
      if (!eng) return;
      const body = this.resetDialog.body;
      if (body.delete_engagement) {
        if (!confirm(`Eliminare DEFINITIVAMENTE l'engagement "${eng.name}"? Operazione IRREVERSIBILE.`)) return;
      }
      const r = await fetch(`/api/engagements/${eng.id}/reset`, {
        method:'POST', headers: { ...this.headers(), 'Content-Type':'application/json' },
        body: JSON.stringify(body),
      });
      if (!r.ok) { this.resetDialog.result = 'errore: ' + r.status; return; }
      const j = await r.json();
      this.resetDialog.result = 'OK: ' + JSON.stringify(j.counters);
      await this.loadEngagements();
      if (body.delete_engagement) {
        setTimeout(() => { this.resetDialog.open = false; }, 1200);
      }
    },

    async confirmSystemReset() {
      const a = prompt('ATTENZIONE: questo cancella TUTTI gli engagement, run, report e audit log.\n\nDigita WIPE_ALL per confermare.');
      if (a !== 'WIPE_ALL') { alert('Annullato.'); return; }
      const r = await fetch('/api/system/reset', {
        method:'POST', headers: { ...this.headers(), 'Content-Type':'application/json' },
        body: JSON.stringify({ confirm: 'WIPE_ALL' }),
      });
      if (!r.ok) { alert('reset failed: ' + r.status); return; }
      const j = await r.json();
      alert(`Reset completato.\nEngagements: ${j.engagements_deleted}\nRun dirs: ${j.run_dirs_deleted}\nReports: ${j.reports_deleted}\nAudit lines: ${j.audit_lines_removed}`);
      this.engagements = [];
      this.audit.entries = [];
      await this.loadEngagements();
    },
  };
}
