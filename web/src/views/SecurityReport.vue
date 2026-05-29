<script setup>
import { ref, onMounted } from 'vue'
import api from '../api.js'

const props = defineProps({ projectKey: { type: String, required: true } })

const data = ref({ categories: [], vulnerabilities: 0, hotspots: 0 })
const error = ref('')
const loaded = ref(false)

onMounted(async () => {
  try {
    data.value = (await api.securityReport(props.projectKey)) || {}
  } catch (e) {
    error.value = String(e)
  } finally {
    loaded.value = true
  }
})
</script>

<template>
  <section>
    <RouterLink :to="`/projects/${projectKey}`">← {{ projectKey }}</RouterLink>
    <h1>Security report — {{ projectKey }}</h1>
    <p v-if="error" class="error">{{ error }}</p>
    <template v-else-if="loaded">
      <p class="summary">
        <strong>{{ data.vulnerabilities || 0 }}</strong> open vulnerabilities ·
        <strong>{{ data.hotspots || 0 }}</strong> security hotspots
      </p>
      <table v-if="(data.categories || []).length" class="cats">
        <thead><tr><th>OWASP category</th><th>Findings</th><th>CWE</th></tr></thead>
        <tbody>
          <tr v-for="c in data.categories" :key="c.owasp" data-test="sec-cat">
            <td>{{ c.owasp }}</td>
            <td>{{ c.count }}</td>
            <td class="cwe">{{ (c.cwe || []).join(', ') }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="clean">No security findings 🎉</p>
    </template>
  </section>
</template>

<style scoped>
.summary { margin: 0.75rem 0; }
.cats { width: 100%; border-collapse: collapse; }
.cats th, .cats td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border, #eee); font-size: 0.9rem; }
.cwe { font-family: monospace; color: var(--muted, #555); }
.error { color: #c5221f; }
.clean { color: #137333; }
</style>
