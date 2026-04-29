/* SigmanexSec — pre-paint theme bootstrap (no inline). */
(function () {
  try {
    var t = localStorage.getItem('sap.theme') || 'dark';
    document.documentElement.classList.remove('dark', 'light');
    document.documentElement.classList.add(t === 'light' ? 'light' : 'dark');
  } catch (_) { /* ignore */ }
})();
