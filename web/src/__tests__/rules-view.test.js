import { describe, it, expect, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../api.js', () => ({
  default: {
    listRules: vi.fn().mockResolvedValue([
      { id: 'go:panic-usage', name: 'no panic', language: 'go', type: 'CODE_SMELL', severity: 'MAJOR' },
      { id: 'py:exec-eval', name: 'eval', language: 'python', type: 'VULNERABILITY', severity: 'CRITICAL', cwe: ['CWE-95'], owasp: ['A03:2021-Injection'] },
      { id: 'js:eval-usage', name: 'eval', language: 'javascript', type: 'VULNERABILITY', severity: 'CRITICAL', cwe: ['CWE-95'] },
    ]),
  },
}))

import Rules from '../views/Rules.vue'

const mountRules = () => mount(Rules, { global: { stubs: { RouterLink: true } } })

describe('Rules catalogue view', () => {
  it('renders all rules with security mappings', async () => {
    const w = mountRules()
    await flushPromises()
    expect(w.findAll('[data-test=rule-row]')).toHaveLength(3)
    expect(w.get('[data-test=rule-count]').text()).toBe('3 of 3 rules')
    expect(w.text()).toContain('CWE-95')
    expect(w.text()).toContain('A03:2021-Injection')
  })

  it('filters by language', async () => {
    const w = mountRules()
    await flushPromises()
    await w.get('[data-test=rule-lang]').setValue('python')
    expect(w.findAll('[data-test=rule-row]')).toHaveLength(1)
    expect(w.text()).toContain('py:exec-eval')
  })

  it('filters by free-text search across id and CWE', async () => {
    const w = mountRules()
    await flushPromises()
    await w.get('[data-test=rule-search]').setValue('panic')
    expect(w.findAll('[data-test=rule-row]')).toHaveLength(1)
    await w.get('[data-test=rule-search]').setValue('CWE-95')
    expect(w.findAll('[data-test=rule-row]')).toHaveLength(2)
  })

  it('filters by type', async () => {
    const w = mountRules()
    await flushPromises()
    await w.get('[data-test=rule-type]').setValue('VULNERABILITY')
    expect(w.findAll('[data-test=rule-row]')).toHaveLength(2)
  })
})
