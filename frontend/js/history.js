// history.js – load analysis history into table
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

export const history = {
  async load() {
    const msgEl = document.getElementById('no-history-msg');
    const table = document.getElementById('history-table');
    try {
      const data = await api.request('GET', '/api/v1/analyze/history');
      if (!Array.isArray(data) || data.length === 0) {
        msgEl.textContent = 'No analysis history available.';
        table.style.display = 'none';
        return;
      }
      msgEl.style.display = 'none';
      table.style.display = '';
      const tbody = table.querySelector('tbody');
      tbody.innerHTML = '';
      data.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${escapeHtml(item.id)}</td><td>${escapeHtml(item.artifact_type)}</td><td>${escapeHtml(item.risk_score)}</td><td>${escapeHtml(item.risk_level)}</td><td>${escapeHtml(item.created_at)}</td>`;
        tbody.appendChild(tr);
      });
    } catch (e) {
      console.warn('History endpoint not available', e);
      msgEl.textContent = 'Unable to load history.';
    }
  }
};

export default history;
