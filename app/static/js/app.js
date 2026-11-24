/* Progressive enhancement: URLs and forms remain functional without JavaScript. */
(() => {
  const body = document.body;
  const toast = (text) => {
    const node = document.querySelector('.toast');
    if (!node) return;
    node.textContent = text; node.hidden = false;
    window.clearTimeout(toast.timer); toast.timer = window.setTimeout(() => { node.hidden = true; }, 3500);
  };
  const resetBusy = () => {
    document.querySelectorAll('[data-busy]').forEach(button => {
      button.disabled = false; button.textContent = button.dataset.originalText;
      button.removeAttribute('data-busy');
    });
    document.querySelectorAll('[aria-busy=true]').forEach(form => form.removeAttribute('aria-busy'));
    const bar = document.querySelector('.loading-bar'); if (bar) bar.hidden = true;
  };
  const menu = document.querySelector('.menu-toggle');
  const closeMenu = () => { body.classList.remove('menu-open'); menu?.setAttribute('aria-expanded', 'false'); };
  menu?.addEventListener('click', () => {
    const expanded = body.classList.toggle('menu-open'); menu.setAttribute('aria-expanded', String(expanded));
    const overlay = document.querySelector('.sidebar-overlay'); if (overlay) overlay.hidden = !expanded;
  });
  document.querySelector('.sidebar-overlay')?.addEventListener('click', closeMenu);
  document.addEventListener('keydown', event => { if (event.key === 'Escape') closeMenu(); });
  document.querySelectorAll('.sidebar a').forEach(link => link.addEventListener('click', closeMenu));
  document.querySelector('[data-project-switch]')?.addEventListener('change', event => event.target.form.requestSubmit());
  document.querySelector('[data-language-switch]')?.addEventListener('change', event => event.target.form.requestSubmit());
  document.querySelectorAll('[data-theme-select]').forEach(select => select.addEventListener('change', () => {
    document.documentElement.dataset.theme = select.value;
  }));
  document.querySelectorAll('form').forEach(form => form.addEventListener('submit', event => {
    if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) { event.preventDefault(); return; }
    if (form.getAttribute('aria-busy') === 'true') { event.preventDefault(); return; }
    const submitter = event.submitter;
    if (submitter) {
      submitter.dataset.originalText = submitter.textContent;
      // Defer disabling: the browser first constructs the native form submission.
      window.setTimeout(() => { submitter.disabled = true; submitter.dataset.busy = 'true'; submitter.textContent = body.dataset.loading; }, 0);
    }
    form.setAttribute('aria-busy', 'true');
    const bar = document.querySelector('.loading-bar'); if (bar) bar.hidden = false;
  }));
  document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
    try {
      const text = button.dataset.copy;
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
      else {
        const field = document.createElement('textarea'); field.value = text;
        field.style.cssText = 'position:fixed;left:0;top:0;width:1px;height:1px;opacity:0';
        document.body.append(field); field.select();
        const copied = document.execCommand('copy'); field.remove();
        if (!copied) throw new Error('copy');
      }
      toast(body.dataset.copySuccess);
    } catch { toast(body.dataset.copyFailed); }
  }));
  document.querySelectorAll('[data-table]').forEach(table => {
    const toggles = [...table.querySelectorAll('[data-column-toggle]')];
    const storageKey = `ptm.columns.${body.dataset.user}.${table.dataset.tableKey}`;
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(storageKey)); } catch { /* Optional storage. */ }
    if (!new URL(location.href).searchParams.has('columns') && Array.isArray(saved)) {
      const valid = toggles.filter(t => saved.includes(t.dataset.columnToggle));
      if (valid.length) toggles.forEach(t => { t.checked = saved.includes(t.dataset.columnToggle); });
    }
    const apply = () => {
      const visible = toggles.filter(t => t.checked).map(t => t.dataset.columnToggle);
      table.querySelectorAll('[data-column]').forEach(cell => { cell.hidden = !visible.includes(cell.dataset.column); });
    };
    apply();
    toggles.forEach(toggle => toggle.addEventListener('change', () => {
      if (!toggles.some(t => t.checked)) { toggle.checked = true; return; }
      apply();
      const visible = toggles.filter(t => t.checked).map(t => t.dataset.columnToggle);
      try { localStorage.setItem(storageKey, JSON.stringify(visible)); } catch { /* Optional storage. */ }
      const address = new URL(location.href); address.searchParams.set('columns', visible.join(','));
      history.replaceState(null, '', address.pathname + address.search + address.hash);
      document.querySelectorAll('a[rel=next],a[rel=prev]').forEach(link => {
        const target = new URL(link.href); target.searchParams.set('columns', visible.join(',')); link.href = target.pathname + target.search;
      });
    }));
  });
  const jobList = document.querySelector('[data-job-list]');
  if (jobList && jobList.querySelector('[data-job-state="queued"],[data-job-state="running"]')) {
    const poll = async () => {
      if (document.hidden) { setTimeout(poll, 2000); return; }
      try {
        const response = await fetch(jobList.dataset.jobsUrl, {headers: {'Accept': 'application/json'}, cache: 'no-store'});
        if (!response.ok) return; // A revoked session must never keep polling.
        const data = await response.json();
        let active = false;
        for (const job of data.jobs) {
          const row = [...jobList.querySelectorAll('[data-job-id]')].find(node => node.dataset.jobId === job.id);
          if (!row) continue;
          if (['queued','running'].includes(job.state)) active = true;
          if (!['queued','running'].includes(job.state) && ['queued','running'].includes(row.dataset.jobState)) {
            document.querySelector('[data-job-completed]').hidden = false;
            row.querySelector('form')?.setAttribute('hidden','');
          }
          row.dataset.jobState = job.state;
          row.querySelector('[data-job-label]').textContent = job.state_label;
          const bar = row.querySelector('progress');
          if (bar) { bar.max = Math.max(job.total_bytes,1); bar.value = job.progress_bytes; }
          const counts = row.querySelector('[data-job-counts]');
          if (counts) counts.textContent = job.progress_files + ' / ' + job.total_files;
        }
        if (active) setTimeout(poll, 1500);
      } catch { /* The refresh link remains available during network loss. */ }
    };
    setTimeout(poll, 500);
  }
  window.addEventListener('pageshow', event => {
    resetBusy();
    // A restored browser cache must re-check login/ACL after logout or revoke.
    if (event.persisted) location.reload();
  });
})();

(() => {
  const measure = () => document.querySelectorAll('[data-visible-limit]').forEach(box => {
    const rows = [...(box.querySelector('tbody')?.children || box.children)];
    const limit = Number(box.dataset.visibleLimit);
    if (rows.length <= limit) { box.style.maxHeight = ''; return; }
    const bottom = rows[limit - 1].getBoundingClientRect().bottom;
    box.style.maxHeight = `${Math.ceil(bottom - box.getBoundingClientRect().top + box.scrollTop)}px`;
  });
  window.addEventListener('resize', measure);
  document.fonts?.ready.then(measure);
  document.querySelectorAll('[data-visible-limit]').forEach(box => new MutationObserver(measure).observe(box, {childList:true,subtree:true}));
  document.querySelectorAll('[data-exact-form]').forEach(form => {
    const field = form.querySelector('[data-exact]');
    const button = form.querySelector('[data-exact-submit]');
    const update = () => { button.disabled = field.value !== field.dataset.exact; };
    field.addEventListener('input', update);update();
  });
  measure();
})();
