import { describe, it, expect, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

// Mock the API with realistic server-shaped responses.
vi.mock('../api.js', () => ({
  default: {
    measures: vi.fn().mockResolvedValue({
      analysisId: 'a1',
      summary: {
        totalNcloc: 42, totalFindings: 4, duplicatedLinesDensity: 0,
        ratings: { reliability: 'C', security: 'D', maintainability: 'A' },
      },
    }),
    issues: vi.fn().mockResolvedValue([
      { key: 'k1', severity: 'CRITICAL', type: 'VULNERABILITY', ruleId: 'py:exec-eval', message: 'eval', file: 'sample.py', line: 5 },
    ]),
    gateStatus: vi.fn().mockResolvedValue({ status: 'ERROR' }),
    hotspots: vi.fn().mockResolvedValue([
      { key: 'h1', ruleId: 'py:os-system', message: 'os.system', file: 'sample.py', line: 9, status: 'TO_REVIEW' },
    ]),
    measuresHistory: vi.fn().mockResolvedValue({ metric: 'total_findings', points: [{ value: 4 }, { value: 4 }] }),
  },
}))

import ProjectDetail from '../views/ProjectDetail.vue'

describe('ProjectDetail view', () => {
  it('loads measures, gate, and issues and renders them', async () => {
    const w = mount(ProjectDetail, {
      props: { projectKey: 'demo' },
      global: { stubs: { RouterLink: true } },
    })
    await flushPromises()

    expect(w.get('[data-test=gate-badge]').text()).toBe('Failed')
    expect(w.get('[data-test=rating-Security]').text()).toContain('D')
    expect(w.findAll('[data-test=issue-row]')).toHaveLength(1)
    expect(w.text()).toContain('py:exec-eval')
    expect(w.text()).toContain('Open issues (1)')
    // hotspots panel + trend rendered
    expect(w.findAll('[data-test=hotspot-row]')).toHaveLength(1)
    expect(w.text()).toContain('Security hotspots (1)')
    expect(w.findAll('[data-test=trend-bar]').length).toBe(2)
  })
})
