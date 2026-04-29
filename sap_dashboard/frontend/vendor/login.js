/* SigmanexSec — login page Alpine controller (vendored, SRI-pinned). */
function loginPage() {
  return {
    form: { user: '', pass: '' },
    showPw: false,
    loading: false,
    error: '',
    nextUrl: '/',
    _csrf() {
      var m = document.cookie.match(/(?:^|; )sap_csrf=([^;]+)/);
      return m ? decodeURIComponent(m[1]) : '';
    },
    init() {
      // Pick up server-injected next URL from a data attribute on the root.
      try {
        var root = document.querySelector('[data-login-root]');
        if (root && root.dataset.next) this.nextUrl = root.dataset.next;
      } catch (_) {}
      setTimeout(function () {
        var el = document.getElementById('login-user');
        if (el) el.focus();
      }, 80);
    },
    async submit() {
      if (!this.form.user || !this.form.pass) return;
      this.loading = true;
      this.error = '';
      try {
        var fetcher = window._snxOriginalFetch || window.fetch.bind(window);
        var r = await fetcher('/api/auth/login', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: this.form.user, password: this.form.pass }),
        });
        if (r.status === 429) {
          var retry = r.headers.get('Retry-After') || '?';
          this.error = 'Troppi tentativi. Riprova tra ' + retry + ' s.';
          return;
        }
        if (!r.ok) {
          var j = {};
          try { j = await r.json(); } catch (_) {}
          this.error = j.detail || 'Credenziali non valide.';
          return;
        }
        try { window.SAP.lastUser = this.form.user; } catch (_) {}
        try { window.SAP.toast({ type: 'ok', msg: 'Accesso eseguito' }); } catch (_) {}
        var target = this.nextUrl || '/';
        setTimeout(function () { window.location.href = target; }, 120);
      } catch (e) {
        this.error = 'Errore di rete: ' + ((e && e.message) || e);
      } finally {
        this.loading = false;
      }
    },
  };
}
