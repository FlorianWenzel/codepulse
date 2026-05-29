// Thin client for the CodePulse HTTP API. The base URL can be overridden with
// VITE_API_BASE; by default it uses the same-origin /api/v1 (proxied in dev).
const BASE = (import.meta?.env?.VITE_API_BASE) || '/api/v1'

async function request(path, opts) {
  const res = await fetch(BASE + path, opts)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status}: ${text}`)
  }
  if (res.status === 204) return null
  return res.json()
}

function postJSON(path, body) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

const q = encodeURIComponent

export const api = {
  listProjects: () => request('/projects'),
  getProject: (key) => request(`/projects/${q(key)}`),
  createProject: (key, name) => postJSON('/projects', { key, name }),
  issues: (key, open = true) => request(`/issues?project=${q(key)}&open=${open}`),
  measures: (key) => request(`/measures?project=${q(key)}`),
  gateStatus: (key) => request(`/quality-gates/status?project=${q(key)}`),
}

export default api
