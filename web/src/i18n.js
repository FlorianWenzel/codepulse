// Minimal reactive i18n for the dashboard. Add locales by extending `messages`.
import { ref } from 'vue'

export const messages = {
  en: {
    projects: 'Projects',
    noProjects: 'No projects yet.',
    openIssues: 'Open issues',
    gatePassed: 'Passed',
    gateFailed: 'Failed',
    noAnalysis: 'No analysis',
  },
  de: {
    projects: 'Projekte',
    noProjects: 'Noch keine Projekte.',
    openIssues: 'Offene Probleme',
    gatePassed: 'Bestanden',
    gateFailed: 'Fehlgeschlagen',
    noAnalysis: 'Keine Analyse',
  },
}

export const availableLocales = Object.keys(messages)
export const locale = ref('en')

export function setLocale(l) {
  if (messages[l]) locale.value = l
}

// t looks up a key in the active locale, falling back to English, then the key.
export function t(key) {
  const active = messages[locale.value] || {}
  if (key in active) return active[key]
  if (key in messages.en) return messages.en[key]
  return key
}
