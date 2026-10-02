// dashboard.js – load stats and recent analyses for dashboard page
import * as api from './api.js';

function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export const dashboard = {
  async loadStats() {
    try {
      const stats = await api.request('GET', '/api/v1/analyze/stats');
      const totalEl = document.getElementById('total-analyses');
      const highEl = document.getElementById('risk-high');
      const medEl = document.getElementById('risk-medium');
      const lowEl = document.getElementById('risk-low');

      if (totalEl) totalEl.textContent = `${stats.total ?? 0}`;
      if (highEl) highEl.textContent = `${stats.high ?? 0}`;
      if (medEl) medEl.textContent = `${stats.medium ?? 0}`;
      if (lowEl) lowEl.textContent = `${stats.low ?? 0}`;
    } catch (e) {
      console.warn('Stats endpoint not available', e);
    }
  },
  async loadRecent() {
    try {
      const recent = await api.request('GET', '/api/v1/analyze/recent');
      const tbody = document.querySelector('#recent-table tbody');
      if (!tbody) return;
      tbody.innerHTML = '';
      if (Array.isArray(recent)) {
        recent.forEach(item => {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${escapeHtml(item.id)}</td><td>${escapeHtml(item.artifact_type)}</td><td>${escapeHtml(item.risk_score)}</td><td>${escapeHtml(item.created_at)}</td>`;
          tbody.appendChild(tr);
        });
      }
    } catch (e) {
      console.warn('Recent analyses endpoint not available', e);
    }
  }
};

export default dashboard;
