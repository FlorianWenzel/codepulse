import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GateBadge from '../components/GateBadge.vue'
import MeasuresPanel from '../components/MeasuresPanel.vue'
import MeasuresTable from '../components/MeasuresTable.vue'
import IssuesTable from '../components/IssuesTable.vue'

describe('GateBadge', () => {
  it('shows Passed for OK', () => {
    const w = mount(GateBadge, { props: { status: 'OK' } })
    expect(w.text()).toBe('Passed')
    expect(w.get('[data-test=gate-badge]').classes()).toContain('gate-ok')
  })
  it('shows Failed for ERROR', () => {
    const w = mount(GateBadge, { props: { status: 'ERROR' } })
    expect(w.text()).toBe('Failed')
    expect(w.get('[data-test=gate-badge]').classes()).toContain('gate-error')
  })
  it('shows No analysis otherwise', () => {
    expect(mount(GateBadge, { props: { status: '' } }).text()).toBe('No analysis')
  })
})

describe('MeasuresPanel', () => {
  it('renders ratings and coverage card when coverage present', () => {
    const summary = {
      totalNcloc: 100, totalFindings: 3, duplicatedLinesDensity: 2.5,
      linesToCover: 10, coverage: 80,
      ratings: { reliability: 'C', security: 'D', maintainability: 'A' },
    }
    const w = mount(MeasuresPanel, { props: { summary } })
    expect(w.get('[data-test=rating-Security]').text()).toContain('D')
    const cards = w.findAll('[data-test=measure-card]')
    // LOC, Findings, Duplication, Coverage
    expect(cards).toHaveLength(4)
    expect(w.text()).toContain('80.0%')
  })

  it('omits the coverage card when there is no coverage data', () => {
    const w = mount(MeasuresPanel, { props: { summary: { totalNcloc: 1, totalFindings: 0, duplicatedLinesDensity: 0 } } })
    expect(w.findAll('[data-test=measure-card]')).toHaveLength(3)
  })
})

describe('MeasuresTable', () => {
  it('renders one row per file sorted by complexity desc', () => {
    const files = [
      { path: 'a.go', ncloc: 10, complexity: 3, cognitiveComplexity: 1, duplicatedLines: 0 },
      { path: 'b.go', ncloc: 50, complexity: 20, cognitiveComplexity: 12, duplicatedLines: 4, linesToCover: 10, coveredLines: 8 },
    ]
    const w = mount(MeasuresTable, { props: { files } })
    const rows = w.findAll('[data-test=measure-row]')
    expect(rows).toHaveLength(2)
    // highest complexity (b.go) first
    expect(rows[0].text()).toContain('b.go')
    expect(rows[0].text()).toContain('80%') // coverage 8/10
  })
})

describe('IssuesTable', () => {
  it('renders a row per issue', () => {
    const issues = [
      { key: 'k1', severity: 'CRITICAL', type: 'VULNERABILITY', ruleId: 'py:exec-eval', message: 'eval', file: 'a.py', line: 5 },
      { key: 'k2', severity: 'MINOR', type: 'CODE_SMELL', ruleId: 'go:empty-block', message: 'empty', file: 'b.go', line: 3 },
    ]
    const w = mount(IssuesTable, { props: { issues } })
    expect(w.findAll('[data-test=issue-row]')).toHaveLength(2)
    expect(w.text()).toContain('py:exec-eval')
  })
  it('shows an empty state', () => {
    expect(mount(IssuesTable, { props: { issues: [] } }).text()).toContain('No open issues')
  })
})
