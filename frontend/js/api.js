// api.js – central API helper
const API_BASE = '';

export function getAuthHeaders() {
  const token = sessionStorage.getItem('jwt');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function request(method, path, body = null, isMultipart = false) {
  const headers = { ...getAuthHeaders() };
  let fetchOptions = { method, headers };
  if (body) {
    if (isMultipart) {
      // body is FormData; fetch will set appropriate headers
      fetchOptions.body = body;
    } else {
      headers['Content-Type'] = 'application/json';
      fetchOptions.body = JSON.stringify(body);
    }
  }
  const response = await fetch(API_BASE + path, fetchOptions);
  if (response.status === 401) {
    sessionStorage.removeItem('jwt');
    window.location.href = 'login.html';
    throw new Error('Unauthorized');
  }
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`API error ${response.status}: ${errText}`);
  }
  return response.json();
}

// Auth endpoints
export async function register({ username, email, password }) {
  return request('POST', '/api/v1/auth/register', { username, email, password });
}
export async function login(emailOrUsername, password) {
  const data = await request('POST', '/api/v1/auth/login', { email_or_username: emailOrUsername, password });
  return data.access_token; // assuming token field
}
export async function getMe() {
  return request('GET', '/api/v1/auth/me');
}
export async function changePassword({ old_password, new_password }) {
  return request('POST', '/api/v1/auth/change-password', { old_password, new_password });
}

// Analysis endpoints
export async function analyzeUrl(url) {
  return request('POST', '/api/v1/analyze/url', { url });
}
export async function analyzeHash(hash) {
  return request('POST', '/api/v1/analyze/hash', { hash });
}
export async function analyzeEmail(file) {
  const fd = new FormData();
  fd.append('file', file);
  return request('POST', '/api/v1/analyze/email', fd, true);
}
export async function analyzeQr(file) {
  const fd = new FormData();
  fd.append('file', file);
  return request('POST', '/api/v1/analyze/qr', fd, true);
}
export async function analyzeFile(file) {
  const fd = new FormData();
  fd.append('file', file);
  return request('POST', '/api/v1/analyze/file', fd, true);
}

// AI Security Analyst chat endpoint
export async function sendChatMessage(message, analysisContext = null, analysisId = null) {
  return request('POST', '/api/v1/chat', {
    message,
    analysis_context: analysisContext,
    analysis_id: analysisId,
  });
}

