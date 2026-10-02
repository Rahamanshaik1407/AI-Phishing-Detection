// analysis.js – handles UI actions for each analysis type and AI Security Analyst chat
import * as api from './api.js';

let currentAnalysisData = null;

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function appendChatMessage(container, sender, text) {
  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-msg ${sender}-msg`;
  
  if (sender === 'assistant') {
    msgDiv.innerHTML = `
      <div class="msg-avatar">&#x1F6E1;&#xFE0F;</div>
      <div class="msg-content">
        <div class="msg-author">Security Analyst</div>
        <div class="msg-body">${escapeHtml(text).replace(/\n/g, '<br/>')}</div>
      </div>
    `;
  } else {
    msgDiv.innerHTML = `
      <div class="msg-content">
        <div class="msg-author" style="text-align: right;">You</div>
        <div class="msg-body">${escapeHtml(text).replace(/\n/g, '<br/>')}</div>
      </div>
      <div class="msg-avatar user-avatar">&#x1F464;</div>
    `;
  }
  
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

export function setupAnalystChat(containerId, initialContext = null) {
  const container = document.getElementById(containerId);
  if (!container) return;

  currentAnalysisData = initialContext;

  container.innerHTML = `
    <div class="analyst-card">
      <div class="analyst-header">
        <div class="analyst-title">
          <span class="analyst-badge">&#x1F6E1;&#xFE0F; AI Security Analyst</span>
          <span class="analyst-sub">Ask questions about this analysis evidence</span>
        </div>
      </div>
      
      <div class="prompt-chips">
        <button class="prompt-chip" data-prompt="Why was this classified as risky?">Why is this risky?</button>
        <button class="prompt-chip" data-prompt="What evidence was detected?">What evidence was detected?</button>
        <button class="prompt-chip" data-prompt="Summarize this analysis">Summarize analysis</button>
        <button class="prompt-chip" data-prompt="What should a security analyst investigate next?">Next investigation steps</button>
      </div>

      <div class="chat-messages" id="chat-messages-${containerId}"></div>

      <form class="chat-input-bar" id="chat-form-${containerId}">
        <input type="text" class="chat-input" placeholder="Ask a security question about this artifact..." required />
        <button type="submit" class="btn btn-primary chat-send-btn">Send &rarr;</button>
      </form>
    </div>
  `;

  const messagesBox = document.getElementById(`chat-messages-${containerId}`);
  const form = document.getElementById(`chat-form-${containerId}`);
  const input = form.querySelector('input');

  // Initial greeting
  if (currentAnalysisData) {
    const riskLevel = currentAnalysisData?.risk?.level || currentAnalysisData?.risk_level || 'UNKNOWN';
    const score = currentAnalysisData?.risk?.score ?? currentAnalysisData?.risk_score ?? 'N/A';
    appendChatMessage(
      messagesBox,
      'assistant',
      `Analysis context loaded. Risk Level: ${riskLevel} (${score}/100).\nI am ready to explain the findings, ML indicators, domain signals, or recommended triage steps.`
    );
  } else {
    appendChatMessage(
      messagesBox,
      'assistant',
      'Ready to assist. Submit an artifact above to investigate security findings.'
    );
  }

  // Quick prompt chips
  container.querySelectorAll('.prompt-chip').forEach(chip => {
    chip.addEventListener('click', async () => {
      const query = chip.getAttribute('data-prompt');
      await handleSend(query);
    });
  });

  // Submit handling
  async function handleSend(query) {
    if (!query || !query.trim()) return;
    const userText = query.trim();
    input.value = '';
    
    appendChatMessage(messagesBox, 'user', userText);

    // Show typing state
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'chat-msg assistant-msg typing-msg';
    loadingDiv.innerHTML = `
      <div class="msg-avatar">&#x1F6E1;&#xFE0F;</div>
      <div class="msg-content"><div class="msg-body">Analyzing evidence...</div></div>
    `;
    messagesBox.appendChild(loadingDiv);
    messagesBox.scrollTop = messagesBox.scrollHeight;

    try {
      const response = await api.sendChatMessage(
        userText,
        currentAnalysisData,
        currentAnalysisData?.analysis_id || null
      );
      messagesBox.removeChild(loadingDiv);
      appendChatMessage(messagesBox, 'assistant', response.response);
    } catch (err) {
      if (loadingDiv.parentNode) messagesBox.removeChild(loadingDiv);
      appendChatMessage(messagesBox, 'assistant', `Error: ${err.message}`);
    }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await handleSend(input.value);
  });
}

function renderResult(containerId, data) {
  const container = document.getElementById(containerId);
  if (!container) return;

  currentAnalysisData = data;
  try {
    sessionStorage.setItem('currentAnalysisContext', JSON.stringify(data));
  } catch (e) {
    // Ignore storage quota errors
  }

  const riskScore = data?.risk?.score ?? data?.risk_score ?? 0;
  const riskLevel = (data?.risk?.level ?? data?.risk_level ?? 'UNKNOWN').toUpperCase();
  const summary = data?.summary || data?.explanation?.summary || 'Analysis complete.';
  const signals = data?.signals || [];
  const mlInfo = data?.ml || {};

  let badgeClass = 'badge-low';
  if (riskLevel === 'MEDIUM') badgeClass = 'badge-medium';
  if (riskLevel === 'HIGH') badgeClass = 'badge-high';
  if (riskLevel === 'CRITICAL') badgeClass = 'badge-critical';

  let signalsHtml = '';
  if (signals.length > 0) {
    signalsHtml = `
      <div class="signals-list">
        <h4>Triggered Signals (${signals.length}):</h4>
        <ul>
          ${signals.map(s => {
            if (typeof s === 'object' && s !== null) {
              return `<li><strong>${escapeHtml(s.name || 'Signal')}</strong>: ${escapeHtml(s.description || '')} <span class="badge ${badgeClass} text-sm">weight: ${s.weight || 0}</span></li>`;
            }
            return `<li>${escapeHtml(String(s))}</li>`;
          }).join('')}
        </ul>
      </div>
    `;
  }

  let mlHtml = '';
  if (mlInfo && mlInfo.model_available && mlInfo.probability !== null && mlInfo.probability !== undefined) {
    mlHtml = `
      <div class="ml-badge-box">
        <strong>Machine Learning Prediction:</strong> ${(mlInfo.probability * 100).toFixed(1)}% Phishing Probability
      </div>
    `;
  }

  container.innerHTML = `
    <div class="result-header">
      <div>
        <h3>Analysis Findings</h3>
        <p class="text-muted" style="margin: 0.25rem 0 0.75rem;">${escapeHtml(summary)}</p>
      </div>
      <div class="risk-pill-container">
        <span class="badge ${badgeClass}" style="font-size: 0.9rem; padding: 0.4rem 1rem;">
          ${riskLevel} RISK (${riskScore}/100)
        </span>
      </div>
    </div>
    ${mlHtml}
    ${signalsHtml}

    <details style="margin-top: 1rem;">
      <summary style="cursor: pointer; font-size: 0.85rem; color: var(--text-muted);">View Raw Analysis JSON</summary>
      <pre style="margin-top: 0.5rem;">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
    </details>

    <div id="analyst-embedded-${containerId}" style="margin-top: 1.5rem;"></div>
  `;

  // Attach embedded AI Security Analyst chat panel
  setupAnalystChat(`analyst-embedded-${containerId}`, data);
}

export const analysis = {
  init() {
    // URL
    const urlBtn = document.getElementById('url-analyze-btn');
    if (urlBtn) {
      urlBtn.addEventListener('click', async () => {
        const url = document.getElementById('url-input').value.trim();
        if (!url) { alert('Enter a URL'); return; }
        try {
          const result = await api.analyzeUrl(url);
          renderResult('url-result', result);
        } catch (e) { alert('Error: ' + e.message); }
      });
    }

    // Hash
    const hashBtn = document.getElementById('hash-analyze-btn');
    if (hashBtn) {
      hashBtn.addEventListener('click', async () => {
        const hash = document.getElementById('hash-input').value.trim();
        if (!hash) { alert('Enter a hash'); return; }
        try {
          const result = await api.analyzeHash(hash);
          renderResult('hash-result', result);
        } catch (e) { alert('Error: ' + e.message); }
      });
    }

    // Email
    const emailBtn = document.getElementById('email-analyze-btn');
    if (emailBtn) {
      emailBtn.addEventListener('click', async () => {
        const fileInput = document.getElementById('email-file');
        if (fileInput.files.length === 0) { alert('Select an email file'); return; }
        try {
          const result = await api.analyzeEmail(fileInput.files[0]);
          renderResult('email-result', result);
        } catch (e) { alert('Error: ' + e.message); }
      });
    }

    // QR
    const qrBtn = document.getElementById('qr-analyze-btn');
    if (qrBtn) {
      qrBtn.addEventListener('click', async () => {
        const fileInput = document.getElementById('qr-file');
        if (fileInput.files.length === 0) { alert('Select an image file'); return; }
        try {
          const result = await api.analyzeQr(fileInput.files[0]);
          renderResult('qr-result', result);
        } catch (e) { alert('Error: ' + e.message); }
      });
    }

    // Generic file
    const fileBtn = document.getElementById('file-analyze-btn');
    if (fileBtn) {
      fileBtn.addEventListener('click', async () => {
        const fileInput = document.getElementById('generic-file');
        if (fileInput.files.length === 0) { alert('Select a file'); return; }
        try {
          const result = await api.analyzeFile(fileInput.files[0]);
          renderResult('file-result', result);
        } catch (e) { alert('Error: ' + e.message); }
      });
    }
  }
};

export default analysis;
