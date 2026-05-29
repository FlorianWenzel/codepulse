import { describe, it, expect, beforeEach } from 'vitest'
import { t, setLocale, locale, availableLocales } from '../i18n.js'

describe('i18n', () => {
  beforeEach(() => setLocale('en'))

  it('translates in the active locale', () => {
    expect(t('projects')).toBe('Projects')
    setLocale('de')
    expect(locale.value).toBe('de')
    expect(t('projects')).toBe('Projekte')
  })

  it('falls back to English then to the key', () => {
    setLocale('de')
    // a key only present in en still resolves via fallback
    expect(t('gatePassed')).toBe('Bestanden') // present in de
    expect(t('totally-unknown-key')).toBe('totally-unknown-key')
  })

  it('ignores unknown locales', () => {
    setLocale('xx')
    expect(locale.value).toBe('en')
    expect(availableLocales).toContain('en')
  })
})
