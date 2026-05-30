<script setup>
import { theme, toggleTheme } from './theme.js'
import { locale, setLocale, availableLocales, t } from './i18n.js'
</script>

<template>
  <div class="app">
    <header class="topbar">
      <RouterLink to="/" class="brand">CodePulse</RouterLink>
      <nav class="nav">
        <RouterLink to="/" class="navlink">Projects</RouterLink>
        <RouterLink to="/gates" class="navlink">Gates</RouterLink>
        <RouterLink to="/rules" class="navlink">Rules</RouterLink>
      </nav>
      <div class="controls">
        <label class="sr-only" for="locale">Language</label>
        <select id="locale" :value="locale" @change="setLocale($event.target.value)" aria-label="Language">
          <option v-for="l in availableLocales" :key="l" :value="l">{{ l.toUpperCase() }}</option>
        </select>
        <button type="button" class="theme-toggle" :aria-label="`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`" @click="toggleTheme">
          {{ theme === 'light' ? '🌙' : '☀️' }}
        </button>
      </div>
    </header>
    <main class="content">
      <RouterView />
    </main>
  </div>
</template>

<style>
:root { --bg: #fff; --fg: #202124; --muted: #666; --border: #e0e0e0; --bar: #1a1a2e; }
:root[data-theme="dark"] { --bg: #15151f; --fg: #e8e8ea; --muted: #9aa0a6; --border: #2c2c3a; --bar: #0d0d16; }
body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color: var(--fg); background: var(--bg); }
.topbar { background: var(--bar); padding: 0.8rem 1.5rem; display: flex; align-items: center; justify-content: space-between; }
.brand { color: #fff; font-weight: 700; font-size: 1.2rem; text-decoration: none; }
.nav { display: flex; gap: 1rem; margin-left: 1.5rem; flex: 1; }
.navlink { color: #cfd2ff; font-size: 0.95rem; text-decoration: none; }
.navlink:hover { color: #fff; }
.controls { display: flex; gap: 0.5rem; align-items: center; }
.theme-toggle { background: transparent; border: 1px solid #ffffff55; border-radius: 6px; cursor: pointer; font-size: 1rem; padding: 2px 8px; }
.content { max-width: 960px; margin: 1.5rem auto; padding: 0 1rem; }
a { color: #1a73e8; text-decoration: none; }
a:hover { text-decoration: underline; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); border: 0; }
</style>
