/*
 * DriftGuard Embed Collector — drop-in client layer.
 *
 * Add to any website with a single tag:
 *   <script src="/static/driftguard-collector.js"
 *           data-endpoint="https://driftguard-api-mbdj.onrender.com/api/v1/ai-breach/collect"
 *           data-actor-id="user-42"
 *           data-site-id="acme-prod"
 *           data-flush-interval="5000"></script>
 *
 * What it captures, by default:
 *   - page_view (load + SPA pushState/replaceState)
 *   - copy / paste                     (clipboard)
 *   - paste_to_llm                     (paste into a textarea/contenteditable
 *                                       whose host attribute marks it as an LLM input)
 *   - form_submit                      (any form)
 *   - file_download                    (anchor click with download attr)
 *   - login / login_failed             (custom: window.dispatchEvent(new
 *                                       CustomEvent('driftguard:event', {detail:{...}})))
 *
 * Anything else — call window.DriftGuard.track({event_type:'...', ...}).
 *
 * Privacy: the script never sends raw clipboard / form bodies by default.
 * Set data-include-bodies="true" to opt in (use only on consented pages).
 */
(function () {
  'use strict';

  var script = document.currentScript;
  if (!script) return;

  var ENDPOINT = script.getAttribute('data-endpoint');
  if (!ENDPOINT) {
    console.warn('[DriftGuard] data-endpoint missing — collector disabled');
    return;
  }
  var SITE_ID = script.getAttribute('data-site-id') || location.hostname;
  var ACTOR_ID = script.getAttribute('data-actor-id') || 'anonymous';
  var ACTOR_TYPE = script.getAttribute('data-actor-type') || 'human';
  var FLUSH_MS = parseInt(script.getAttribute('data-flush-interval') || '5000', 10);
  var MAX_BATCH = parseInt(script.getAttribute('data-max-batch') || '50', 10);
  var INCLUDE_BODIES = script.getAttribute('data-include-bodies') === 'true';
  var TOKEN = script.getAttribute('data-token') || null;

  var queue = [];
  var lastFlush = 0;

  function nowIso() { return new Date().toISOString(); }

  function track(event) {
    if (!event || typeof event !== 'object') return;
    var enriched = Object.assign({
      timestamp: nowIso(),
      actor_id: ACTOR_ID,
      actor_type: ACTOR_TYPE,
      page_url: location.href,
      page_title: document.title,
    }, event);
    queue.push(enriched);
    if (queue.length >= MAX_BATCH) flush();
  }

  function flush() {
    if (queue.length === 0) return;
    var batch = queue.splice(0, queue.length);
    lastFlush = Date.now();
    var headers = { 'Content-Type': 'application/json' };
    if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
    fetch(ENDPOINT, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ site_id: SITE_ID, events: batch }),
      keepalive: true,
    })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (resp) {
        if (resp && resp.recommendations_pending && resp.recommendations_pending.length) {
          // Surface critical recommendations to the host page via a CustomEvent.
          // Host pages can listen with:
          //   window.addEventListener('driftguard:recommendations', e => …)
          window.dispatchEvent(new CustomEvent('driftguard:recommendations', {
            detail: resp,
          }));
        }
      })
      .catch(function () { /* best-effort — never break the host page */ });
  }

  // ── Default capture wiring ──────────────────────────
  function onPageView() {
    track({ event_type: 'page_view' });
  }
  onPageView();

  // SPA navigations
  ['pushState', 'replaceState'].forEach(function (m) {
    var orig = history[m];
    history[m] = function () {
      var r = orig.apply(this, arguments);
      setTimeout(onPageView, 0);
      return r;
    };
  });
  window.addEventListener('popstate', onPageView);

  document.addEventListener('copy', function () {
    track({ event_type: 'copy' });
  }, true);

  document.addEventListener('paste', function (e) {
    var target = e.target;
    var isLlmInput = target && target.matches && target.matches(
      '[data-driftguard="llm-input"], [data-llm-input], textarea[name*="prompt"], textarea[name*="message"], div[contenteditable="true"][role="textbox"]'
    );
    var body = '';
    try {
      var cd = (e.clipboardData || window.clipboardData);
      if (cd && INCLUDE_BODIES) body = cd.getData('text/plain') || '';
    } catch (_) { /* permission errors — skip */ }
    track({
      event_type: isLlmInput ? 'paste_to_llm' : 'paste',
      destination: isLlmInput ? (target.dataset && target.dataset.llmHost) || 'unknown_llm' : null,
      text: body || undefined,
    });
  }, true);

  document.addEventListener('submit', function (e) {
    var form = e.target;
    track({
      event_type: 'form_submit',
      destination: form && form.action ? form.action : location.href,
      tool_name: form && form.id ? form.id : (form && form.name) || 'form',
    });
  }, true);

  document.addEventListener('click', function (e) {
    var t = e.target;
    if (t && t.tagName === 'A' && t.hasAttribute('download')) {
      track({
        event_type: 'file_download',
        destination: t.href,
        tool_name: t.getAttribute('download') || 'download',
      });
    }
  }, true);

  // Custom events from host pages.
  window.addEventListener('driftguard:event', function (e) {
    if (e && e.detail) track(e.detail);
  });

  // Periodic + on-unload flush.
  setInterval(function () {
    if (queue.length > 0 && Date.now() - lastFlush >= FLUSH_MS) flush();
  }, Math.max(500, Math.floor(FLUSH_MS / 2)));
  window.addEventListener('beforeunload', flush);
  window.addEventListener('pagehide', flush);

  // Public surface for explicit tracking + manual flush.
  window.DriftGuard = {
    track: track,
    flush: flush,
    config: {
      endpoint: ENDPOINT, siteId: SITE_ID, actorId: ACTOR_ID,
      flushMs: FLUSH_MS, maxBatch: MAX_BATCH, includeBodies: INCLUDE_BODIES,
    },
  };
})();
