import { describe, it, expect, vi, beforeEach } from 'vitest'
import api from '../api.js'

describe('api client', () => {
  beforeEach(() => {
    global.fetch = vi.fn()
  })

  it('lists projects', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => [{ key: 'a', name: 'A' }] })
    const got = await api.listProjects()
    expect(got).toEqual([{ key: 'a', name: 'A' }])
    expect(global.fetch).toHaveBeenCalledWith('/api/v1/projects', undefined)
  })

  it('creates a project with a POST + JSON body', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 201, json: async () => ({ key: 'demo' }) })
    await api.createProject('demo', 'Demo')
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/projects')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({ key: 'demo', name: 'Demo' })
  })

  it('encodes query params for issues', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => [] })
    await api.issues('my proj', true)
    expect(global.fetch).toHaveBeenCalledWith('/api/v1/issues?project=my%20proj&open=true', undefined)
  })

  it('posts a triage transition', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) })
    await api.transitionIssue('demo', 'go:x|a.go|m', 'falsepositive')
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/issues/transition')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({ project: 'demo', key: 'go:x|a.go|m', transition: 'falsepositive' })
  })

  it('resolves a hotspot', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) })
    await api.resolveHotspot('demo', 'k', 'SAFE')
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/hotspots/resolve')
    expect(JSON.parse(opts.body)).toEqual({ project: 'demo', key: 'k', resolution: 'SAFE' })
  })

  it('throws on non-OK responses', async () => {
    global.fetch.mockResolvedValue({ ok: false, status: 404, text: async () => 'nope' })
    await expect(api.getProject('x')).rejects.toThrow('404')
  })
})
