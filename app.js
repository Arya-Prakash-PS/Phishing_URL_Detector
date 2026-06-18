/**
 * AuthentURL — app.js
 * =====================
 * Handles URL submission, API communication, results rendering,
 * animated gauge/bar, flags table, and theme toggle.
 */

'use strict';

/* ════════════════════════════════════════════════════════════
   1. DOM REFERENCES
   ════════════════════════════════════════════════════════════ */

const urlInput         = document.getElementById('urlInput');
const analyzeBtn       = document.getElementById('analyzeBtn');
const btnText          = analyzeBtn.querySelector('.btn-text');
const btnLoading       = analyzeBtn.querySelector('.btn-loading');

const errorAlert       = document.getElementById('errorAlert');
const errorMsg         = document.getElementById('errorMsg');

const resultsSection   = document.getElementById('resultsSection');
const resultUrlDisplay = document.getElementById('resultUrlDisplay');

// Gauge
const gaugeArc         = document.getElementById('gaugeArc');
const gaugeScore       = document.getElementById('gaugeScore');

// Classification
const classificationBadge = document.getElementById('classificationBadge');
const classificationText  = document.getElementById('classificationText');

// Stats
const flagCount        = document.getElementById('flagCount');
const elapsedMs        = document.getElementById('elapsedMs');

// Risk bar
const riskBarFill      = document.getElementById('riskBarFill');
const riskBarThumb     = document.getElementById('riskBarThumb');

// Flags panel
const trustedMsg       = document.getElementById('trustedMsg');
const noFlags          = document.getElementById('noFlags');
const flagsTableWrapper= document.getElementById('flagsTableWrapper');
const flagsTableBody   = document.getElementById('flagsTableBody');
const flagBadge        = document.getElementById('flagBadge');

// Recommendations
const recommendationsList = document.getElementById('recommendationsList');

// Buttons
const scanAgainBtn     = document.getElementById('scanAgainBtn');
const themeToggle      = document.getElementById('themeToggle');
const themeLabel       = document.getElementById('themeLabel');

// Example chips
const exampleChips     = document.querySelectorAll('.example-chip');

/* ════════════════════════════════════════════════════════════
   2. CONSTANTS
   ════════════════════════════════════════════════════════════ */

const GAUGE_CIRCUMFERENCE = 408; // 2 * π * 65 ≈ 408
const MAX_SCORE_DISPLAY   = 100; // cap for visual purposes
const API_ENDPOINT        = '/api/analyze';

/* ════════════════════════════════════════════════════════════
   3. THEME TOGGLE
   ════════════════════════════════════════════════════════════ */

function getStoredTheme() {
  return localStorage.getItem('authenturl-theme') || 'dark';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('authenturl-theme', theme);

  const isDark = theme === 'dark';
  themeToggle.innerHTML = isDark
    ? '<i class="bi bi-moon-stars-fill me-1"></i><span>Dark</span>'
    : '<i class="bi bi-sun-fill me-1"></i><span>Light</span>';
}

// Apply persisted theme on page load
applyTheme(getStoredTheme());

themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  applyTheme(current === 'dark' ? 'light' : 'dark');
});

/* ════════════════════════════════════════════════════════════
   4. UTILITY HELPERS
   ════════════════════════════════════════════════════════════ */

/**
 * Show the error alert with a given message.
 */
function showError(msg) {
  errorMsg.textContent = msg;
  errorAlert.classList.remove('d-none');
  errorAlert.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/**
 * Hide the error alert.
 */
function hideError() {
  errorAlert.classList.add('d-none');
}

/**
 * Set the analyze button into loading or ready state.
 */
function setLoading(isLoading) {
  analyzeBtn.disabled = isLoading;
  if (isLoading) {
    btnText.classList.add('d-none');
    btnLoading.classList.remove('d-none');
  } else {
    btnText.classList.remove('d-none');
    btnLoading.classList.add('d-none');
  }
}

/**
 * Clamp a value between min and max.
 */
function clamp(val, min, max) {
  return Math.min(Math.max(val, min), max);
}

/**
 * Escape HTML to prevent XSS when injecting into innerHTML.
 */
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ════════════════════════════════════════════════════════════
   5. ANIMATED GAUGE
   ════════════════════════════════════════════════════════════ */

/**
 * Animate the SVG gauge arc to reflect the given score.
 * @param {number} score  - raw risk score
 * @param {string} color  - stroke colour hex/CSS variable
 */
function animateGauge(score, color) {
  const capped  = clamp(score, 0, MAX_SCORE_DISPLAY);
  const ratio   = capped / MAX_SCORE_DISPLAY;
  const offset  = GAUGE_CIRCUMFERENCE * (1 - ratio);

  gaugeArc.style.strokeDashoffset = offset;
  gaugeArc.style.stroke           = color;

  // Count-up animation for the score text
  const duration = 1200;
  const start    = performance.now();
  const fromVal  = 0;

  function tick(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // Ease out cubic
    const ease = 1 - Math.pow(1 - progress, 3);
    gaugeScore.textContent = Math.round(fromVal + (score - fromVal) * ease);
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

/* ════════════════════════════════════════════════════════════
   6. RISK PROGRESS BAR
   ════════════════════════════════════════════════════════════ */

/**
 * Animate the risk bar and thumb to reflect the given score.
 * The bar maps 0–100+ → 0%–100% width.
 */
function animateRiskBar(score) {
  const pct = clamp((score / MAX_SCORE_DISPLAY) * 100, 0, 100);
  // Delay slightly so CSS transition fires after element is visible
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      riskBarFill.style.width = pct + '%';
      riskBarThumb.style.left = pct + '%';
    });
  });
}

/* ════════════════════════════════════════════════════════════
   7. CLASSIFICATION DISPLAY
   ════════════════════════════════════════════════════════════ */

const CLASSIFICATION_CONFIG = {
  Safe: {
    color:      '#10b981',
    badgeClass: 'badge-safe',
    icon:       'bi-shield-fill-check',
    emoji:      '✅',
    desc:       'This URL appears safe. No significant phishing indicators were detected.',
  },
  Suspicious: {
    color:      '#f59e0b',
    badgeClass: 'badge-suspicious',
    icon:       'bi-exclamation-triangle-fill',
    emoji:      '⚠️',
    desc:       'This URL has some suspicious characteristics. Proceed with caution and verify the source.',
  },
  Phishing: {
    color:      '#ef4444',
    badgeClass: 'badge-phishing',
    icon:       'bi-shield-fill-x',
    emoji:      '🚨',
    desc:       'This URL shows strong indicators of a phishing attack. Do NOT visit or share this link.',
  },
};

/**
 * Render the classification badge + description.
 */
function renderClassification(classification) {
  const cfg = CLASSIFICATION_CONFIG[classification] || CLASSIFICATION_CONFIG['Suspicious'];

  classificationBadge.className = `classification-badge ${cfg.badgeClass}`;
  classificationBadge.innerHTML =
    `<i class="bi ${cfg.icon}"></i> ${cfg.emoji} ${escHtml(classification)}`;

  classificationText.textContent = cfg.desc;

  return cfg.color;
}

/* ════════════════════════════════════════════════════════════
   8. SEVERITY BADGE HELPER
   ════════════════════════════════════════════════════════════ */

function severityBadge(sev) {
  const map = {
    critical: ['sev-critical', 'CRITICAL'],
    high:     ['sev-high',     'HIGH'],
    medium:   ['sev-medium',   'MEDIUM'],
    low:      ['sev-low',      'LOW'],
  };
  const [cls, label] = map[sev] || ['sev-low', sev.toUpperCase()];
  return `<span class="sev-badge ${cls}">${label}</span>`;
}

/* ════════════════════════════════════════════════════════════
   9. FLAGS TABLE
   ════════════════════════════════════════════════════════════ */

/**
 * Render triggered rule flags into the table.
 */
function renderFlags(flags, isTrusted) {
  // Reset visibility
  trustedMsg.classList.add('d-none');
  noFlags.classList.add('d-none');
  flagsTableWrapper.classList.add('d-none');

  if (isTrusted) {
    trustedMsg.classList.remove('d-none');
    flagBadge.textContent = '0';
    return;
  }

  if (!flags || flags.length === 0) {
    noFlags.classList.remove('d-none');
    flagBadge.textContent = '0';
    return;
  }

  // Sort by severity weight
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted   = [...flags].sort(
    (a, b) => (sevOrder[a.severity] ?? 99) - (sevOrder[b.severity] ?? 99)
  );

  flagBadge.textContent = sorted.length;
  flagsTableBody.innerHTML = '';

  sorted.forEach((flag, idx) => {
    const descId = `flag-desc-${idx}`;
    const tr     = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <div class="flag-rule-name">${escHtml(flag.rule)}</div>
      </td>
      <td>${severityBadge(flag.severity)}</td>
      <td><span class="flag-score">+${flag.score}</span></td>
      <td>
        <button class="detail-toggle" aria-expanded="false"
                aria-controls="${descId}" data-target="${descId}">
          <i class="bi bi-info-circle"></i> Detail
        </button>
        <div id="${descId}" class="flag-desc mt-1 d-none">
          ${escHtml(flag.description)}
        </div>
      </td>`;
    flagsTableBody.appendChild(tr);
  });

  flagsTableWrapper.classList.remove('d-none');

  // Wire up detail toggles
  flagsTableWrapper.querySelectorAll('.detail-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const target    = document.getElementById(btn.dataset.target);
      const isOpen    = btn.getAttribute('aria-expanded') === 'true';
      btn.setAttribute('aria-expanded', String(!isOpen));
      target.classList.toggle('d-none', isOpen);
      btn.innerHTML = isOpen
        ? '<i class="bi bi-info-circle"></i> Detail'
        : '<i class="bi bi-chevron-up"></i> Hide';
    });
  });
}

/* ════════════════════════════════════════════════════════════
   10. RECOMMENDATIONS
   ════════════════════════════════════════════════════════════ */

function renderRecommendations(recs) {
  recommendationsList.innerHTML = '';
  (recs || []).forEach(rec => {
    const li = document.createElement('li');
    li.textContent = rec;
    recommendationsList.appendChild(li);
  });
}

/* ════════════════════════════════════════════════════════════
   11. MAIN RENDER FUNCTION
   ════════════════════════════════════════════════════════════ */

/**
 * Render the complete analysis report from the API response.
 */
function renderReport(data) {
  const { url, score, classification, flags, recommendations, is_trusted, elapsed_ms } = data;

  // URL display (truncate if very long)
  const displayUrl = url.length > 80 ? url.slice(0, 77) + '…' : url;
  resultUrlDisplay.textContent = displayUrl;
  resultUrlDisplay.title       = url;

  // Classification → get theme colour
  const color = renderClassification(classification);

  // Gauge
  animateGauge(score, color);

  // Risk bar
  animateRiskBar(score);

  // Stats
  flagCount.textContent = (flags || []).length;
  elapsedMs.textContent = elapsed_ms ?? '—';

  // Gauge border glow based on classification
  const gaugeEl = document.querySelector('.score-gauge');
  gaugeEl.style.filter =
    classification === 'Phishing'   ? 'drop-shadow(0 0 16px rgba(239,68,68,.5))'   :
    classification === 'Suspicious' ? 'drop-shadow(0 0 16px rgba(245,158,11,.4))'  :
                                      'drop-shadow(0 0 16px rgba(16,185,129,.4))';

  // Flags table
  renderFlags(flags, is_trusted);

  // Recommendations
  renderRecommendations(recommendations);

  // Show results section
  resultsSection.classList.remove('d-none');

  // Smooth scroll to results
  setTimeout(() => {
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);
}

/* ════════════════════════════════════════════════════════════
   12. API CALL
   ════════════════════════════════════════════════════════════ */

async function analyzeUrl(url) {
  setLoading(true);
  hideError();
  resultsSection.classList.add('d-none');

  // Reset animated elements immediately
  gaugeArc.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
  gaugeScore.textContent = '0';
  riskBarFill.style.width = '0%';
  riskBarThumb.style.left = '0%';

  try {
    const response = await fetch(API_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
    });

    const data = await response.json();

    if (!response.ok) {
      // Server returned an error response
      showError(data.error || `Server error: ${response.status}`);
      return;
    }

    renderReport(data);

  } catch (err) {
    if (err.name === 'TypeError') {
      showError('Could not reach the AuthentURL server. Make sure the Flask app is running.');
    } else {
      showError(`Unexpected error: ${err.message}`);
    }
  } finally {
    setLoading(false);
  }
}

/* ════════════════════════════════════════════════════════════
   13. EVENT LISTENERS
   ════════════════════════════════════════════════════════════ */

// Analyze button click
analyzeBtn.addEventListener('click', () => {
  const url = urlInput.value.trim();
  if (!url) {
    showError('Please enter a URL to analyze.');
    urlInput.focus();
    return;
  }
  analyzeUrl(url);
});

// Enter key in input
urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') analyzeBtn.click();
});

// Paste → auto-strip whitespace
urlInput.addEventListener('paste', e => {
  // Let paste happen, then strip whitespace
  setTimeout(() => {
    urlInput.value = urlInput.value.trim();
  }, 0);
});

// Clear error when user starts typing again
urlInput.addEventListener('input', () => {
  if (urlInput.value.trim()) hideError();
});

// Example chip buttons
exampleChips.forEach(chip => {
  chip.addEventListener('click', () => {
    urlInput.value = chip.dataset.url;
    urlInput.focus();
    hideError();
    // Auto-trigger analysis
    analyzeBtn.click();
  });
});

// Scan Again button — scroll to hero and focus input
scanAgainBtn.addEventListener('click', () => {
  window.scrollTo({ top: 0, behavior: 'smooth' });
  setTimeout(() => {
    urlInput.value = '';
    urlInput.focus();
    resultsSection.classList.add('d-none');
    hideError();
  }, 400);
});

/* ════════════════════════════════════════════════════════════
   14. NAVBAR SCROLL EFFECT
   ════════════════════════════════════════════════════════════ */

const mainNav = document.getElementById('mainNav');
let lastScrollY = window.scrollY;

window.addEventListener('scroll', () => {
  const currentY = window.scrollY;
  if (currentY > 60) {
    mainNav.style.boxShadow = '0 4px 20px rgba(0,0,0,.3)';
  } else {
    mainNav.style.boxShadow = 'none';
  }
  lastScrollY = currentY;
}, { passive: true });

/* ════════════════════════════════════════════════════════════
   15. INTERSECTION OBSERVER — animate on scroll
   ════════════════════════════════════════════════════════════ */

const observerOptions = {
  threshold: 0.12,
  rootMargin: '0px 0px -40px 0px',
};

const fadeObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.style.opacity   = '1';
      entry.target.style.transform = 'translateY(0)';
      fadeObserver.unobserve(entry.target);
    }
  });
}, observerOptions);

// Apply to How cards and Feature items
document.querySelectorAll('.how-card, .feature-item').forEach(el => {
  el.style.opacity   = '0';
  el.style.transform = 'translateY(28px)';
  el.style.transition = 'opacity .5s ease, transform .5s ease';
  fadeObserver.observe(el);
});

/* ════════════════════════════════════════════════════════════
   16. INIT
   ════════════════════════════════════════════════════════════ */

// Auto-focus input on load
window.addEventListener('DOMContentLoaded', () => {
  urlInput.focus();
});
