// Light/dark theme with persistence, exposed as a reactive ref.
import { ref, watch } from 'vue'

const KEY = 'cp_theme'

function initial() {
  try {
    return localStorage.getItem(KEY) || 'light'
  } catch {
    return 'light'
  }
}

export const theme = ref(initial())

export function toggleTheme() {
  theme.value = theme.value === 'light' ? 'dark' : 'light'
}

export function applyTheme() {
  try {
    localStorage.setItem(KEY, theme.value)
  } catch {
    /* storage unavailable */
  }
  if (typeof document !== 'undefined' && document.documentElement) {
    document.documentElement.dataset.theme = theme.value
  }
}

watch(theme, applyTheme, { immediate: true })
