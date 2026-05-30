<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../api.js'

const rules = ref([])
const error = ref('')
const loaded = ref(false)
const search = ref('')
const language = ref('')
const ruleType = ref('')

async function load() {
  try {
    rules.value = (await api.listRules()) || []
  } catch (e) {
    error.value = String(e)
  } finally {
    loaded.value = true
  }
}
onMounted(load)

const languages = computed(() =>
  [...new Set(rules.value.map((r) => r.language))].sort()
)
const types = computed(() =>
  [...new Set(rules.value.map((r) => r.type))].sort()
)

const filtered = computed(() => {
  const term = search.value.trim().toLowerCase()
  return rules.value.filter((r) => {
    if (language.value && r.language !== language.value) return false
    if (ruleType.value && r.type !== ruleType.value) return false
    if (!term) return true
    const hay = `${r.id} ${r.name} ${(r.cwe || []).join(' ')} ${(r.tags || []).join(' ')}`.toLowerCase()
    return hay.includes(term)
  })
})
</script>

<template>
  <section>
    <RouterLink to="/">← Projects</RouterLink>
    <h1>Rule catalogue</h1>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="filters">
      <input v-model="search" placeholder="search id, name, CWE, tag…" aria-label="Search rules" data-test="rule-search" />
      <select v-model="language" aria-label="Language filter" data-test="rule-lang">
        <option value="">All languages</option>
        <option v-for="l in languages" :key="l" :value="l">{{ l }}</option>
      </select>
      <select v-model="ruleType" aria-label="Type filter" data-test="rule-type">
        <option value="">All types</option>
        <option v-for="ty in types" :key="ty" :value="ty">{{ ty }}</option>
      </select>
    </div>

    <p class="count" data-test="rule-count">{{ filtered.length }} of {{ rules.length }} rules</p>

    <table class="rules" v-if="loaded">
      <thead>
        <tr><th>Rule</th><th>Language</th><th>Type</th><th>Severity</th><th>Security</th></tr>
      </thead>
      <tbody>
        <tr v-for="r in filtered" :key="r.id" data-test="rule-row">
          <td>
            <code>{{ r.id }}</code>
            <div class="name">{{ r.name }}</div>
            <div class="desc" v-if="r.description">{{ r.description }}</div>
          </td>
          <td>{{ r.language }}</td>
          <td>{{ r.type }}</td>
          <td><span class="sev" :data-sev="r.severity">{{ r.severity }}</span></td>
          <td class="sec">
            <span v-for="c in r.cwe || []" :key="c" class="cwe">{{ c }}</span>
            <span v-for="o in r.owasp || []" :key="o" class="owasp">{{ o }}</span>
          </td>
        </tr>
      </tbody>
    </table>
  </section>
</template>

<style scoped>
.filters { display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 0.8rem 0; }
.filters input { flex: 1; min-width: 220px; }
.count { color: var(--muted, #666); font-size: 0.85rem; }
table.rules { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
table.rules th, table.rules td { text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--border, #eee); vertical-align: top; }
.name { font-weight: 600; margin-top: 2px; }
.desc { color: var(--muted, #666); font-size: 0.82rem; margin-top: 2px; }
.sev { font-weight: 600; font-size: 0.8rem; }
.sev[data-sev="BLOCKER"], .sev[data-sev="CRITICAL"] { color: #c5221f; }
.sev[data-sev="MAJOR"] { color: #e8710a; }
.sev[data-sev="MINOR"], .sev[data-sev="INFO"] { color: var(--muted, #666); }
.cwe, .owasp { display: inline-block; font-size: 0.72rem; padding: 1px 5px; border-radius: 4px; margin: 1px; background: var(--border, #eee); }
.error { color: #c5221f; }
</style>
