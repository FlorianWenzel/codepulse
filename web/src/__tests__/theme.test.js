import { describe, it, expect, beforeEach } from 'vitest'
import { theme, toggleTheme, applyTheme } from '../theme.js'

describe('theme', () => {
  beforeEach(() => {
    theme.value = 'light'
  })

  it('toggles between light and dark', () => {
    expect(theme.value).toBe('light')
    toggleTheme()
    expect(theme.value).toBe('dark')
    toggleTheme()
    expect(theme.value).toBe('light')
  })

  it('persists and reflects on the document element', () => {
    theme.value = 'dark'
    applyTheme()
    expect(localStorage.getItem('cp_theme')).toBe('dark')
    expect(document.documentElement.dataset.theme).toBe('dark')
  })
})
