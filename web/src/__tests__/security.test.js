import { describe, it, expect, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../api.js', () => ({
  default: {
    securityReport: vi.fn().mockResolvedValue({
      vulnerabilities: 1,
      hotspots: 2,
      categories: [
        { owasp: 'A03:2021-Injection', count: 1, cwe: ['CWE-95'] },
        { owasp: 'A02:2021-Cryptographic Failures', count: 1, cwe: ['CWE-327'] },
      ],
    }),
  },
}))

import SecurityReport from '../views/SecurityReport.vue'

describe('SecurityReport view', () => {
  it('renders OWASP categories with counts and CWEs', async () => {
    const w = mount(SecurityReport, {
      props: { projectKey: 'demo' },
      global: { stubs: { RouterLink: true } },
    })
    await flushPromises()
    const rows = w.findAll('[data-test=sec-cat]')
    expect(rows).toHaveLength(2)
    expect(rows[0].text()).toContain('A03:2021-Injection')
    expect(rows[0].text()).toContain('CWE-95')
    expect(w.text()).toContain('1') // vulnerabilities
    expect(w.text()).toContain('2') // hotspots
  })
})
