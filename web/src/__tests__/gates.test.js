import { describe, it, expect, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../api.js', () => ({
  default: {
    listGates: vi.fn().mockResolvedValue([
      { id: 'default', name: 'CodePulse Way', conditions: [{ metric: 'vulnerabilities', op: 'GT', threshold: 0 }] },
    ]),
    listProjects: vi.fn().mockResolvedValue([{ key: 'demo', name: 'Demo' }]),
    createGate: vi.fn().mockResolvedValue({}),
    assignGate: vi.fn().mockResolvedValue({}),
  },
}))

import api from '../api.js'
import Gates from '../views/Gates.vue'

const stubs = { RouterLink: true }

describe('Gates view', () => {
  it('lists existing gates', async () => {
    const w = mount(Gates, { global: { stubs } })
    await flushPromises()
    const items = w.findAll('[data-test=gate-item]')
    expect(items).toHaveLength(1)
    expect(items[0].text()).toContain('default')
  })

  it('builds conditions and creates a gate', async () => {
    const w = mount(Gates, { global: { stubs } })
    await flushPromises()
    await w.get('input[aria-label="Gate id"]').setValue('strict')
    await w.get('[data-test=add-cond]').trigger('click')
    expect(w.findAll('[data-test=form-cond]')).toHaveLength(1)
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(api.createGate).toHaveBeenCalled()
    const arg = api.createGate.mock.calls[0][0]
    expect(arg.id).toBe('strict')
    expect(arg.conditions).toHaveLength(1)
  })

  it('assigns a gate to a project', async () => {
    const w = mount(Gates, { global: { stubs } })
    await flushPromises()
    await w.get('select[aria-label="Project"]').setValue('demo')
    await w.get('select[aria-label="Gate"]').setValue('default')
    await w.get('[data-test=assign-gate]').trigger('click')
    await flushPromises()
    expect(api.assignGate).toHaveBeenCalledWith('demo', 'default')
  })
})
