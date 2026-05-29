<script setup>
</script>

<template>
  <div class="app">
    <header class="topbar">
      <RouterLink to="/" class="brand">CodePulse</RouterLink>
    </header>
    <main class="content">
      <RouterView />
    </main>
  </div>
</template>

<style>
body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color: #202124; }
.topbar { background: #1a1a2e; padding: 0.8rem 1.5rem; }
.brand { color: #fff; font-weight: 700; font-size: 1.2rem; text-decoration: none; }
.content { max-width: 960px; margin: 1.5rem auto; padding: 0 1rem; }
a { color: #1a73e8; text-decoration: none; }
a:hover { text-decoration: underline; }
</style>
