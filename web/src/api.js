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
  newIssues: (key, base = 'main', branch = 'main') =>
    request(`/issues/new?project=${q(key)}&branch=${q(branch)}&base=${q(base)}`),
  measures: (key) => request(`/measures?project=${q(key)}`),
  gateStatus: (key) => request(`/quality-gates/status?project=${q(key)}`),
  hotspots: (key, status = '') => request(`/hotspots?project=${q(key)}&status=${q(status)}`),

  // Triage actions.
  transitionIssue: (project, key, transition) => postJSON('/issues/transition', { project, key, transition }),
  assignIssue: (project, key, assignee) => postJSON('/issues/assign', { project, key, assignee }),
  resolveHotspot: (project, key, resolution) => postJSON('/hotspots/resolve', { project, key, resolution }),
}

export default api
