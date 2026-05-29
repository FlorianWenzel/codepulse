<script setup>
import { ref, onMounted } from 'vue'
import api from '../api.js'
import GateBadge from '../components/GateBadge.vue'
import MeasuresPanel from '../components/MeasuresPanel.vue'
import MeasuresTable from '../components/MeasuresTable.vue'
import IssuesTable from '../components/IssuesTable.vue'

const props = defineProps({ projectKey: { type: String, required: true } })

const summary = ref({})
const files = ref([])
const issues = ref([])
const gate = ref('')
const error = ref('')
const loaded = ref(false)

onMounted(async () => {
  try {
    const [m, is, g] = await Promise.all([
      api.measures(props.projectKey),
      api.issues(props.projectKey, true),
      api.gateStatus(props.projectKey).catch(() => ({ status: '' })),
    ])
    summary.value = m.summary || {}
    files.value = m.metrics || []
    issues.value = is || []
    gate.value = g.status || ''
  } catch (e) {
    error.value = String(e)
  } finally {
    loaded.value = true
  }
})

async function onTransition({ key, transition }) {
  try {
    await api.transitionIssue(props.projectKey, key, transition)
    issues.value = (await api.issues(props.projectKey, true)) || []
  } catch (e) {
    error.value = String(e)
  }
}
</script>

<template>
  <section>
    <RouterLink to="/">← Projects</RouterLink>
    <header class="head">
      <h1>{{ projectKey }}</h1>
      <GateBadge :status="gate" />
    </header>
    <p v-if="error" class="error">{{ error }}</p>
    <template v-else-if="loaded">
      <MeasuresPanel :summary="summary" />
      <h2>Files</h2>
      <MeasuresTable :files="files" />
      <h2>Open issues ({{ issues.length }})</h2>
      <IssuesTable :issues="issues" @transition="onTransition" />
    </template>
  </section>
</template>

<style scoped>
.head { display: flex; align-items: center; gap: 1rem; }
.error { color: #c5221f; }
</style>
