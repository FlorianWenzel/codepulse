<script setup>
import { ref, onMounted } from 'vue'
import api from '../api.js'
import GateBadge from '../components/GateBadge.vue'

const projects = ref([])
const gates = ref({})
const error = ref('')

onMounted(async () => {
  try {
    projects.value = await api.listProjects() || []
    // best-effort per-project gate status
    await Promise.all(projects.value.map(async (p) => {
      try { gates.value[p.key] = (await api.gateStatus(p.key)).status } catch { gates.value[p.key] = '' }
    }))
  } catch (e) {
    error.value = String(e)
  }
})
</script>

<template>
  <section>
    <h1>Projects</h1>
    <p v-if="error" class="error">{{ error }}</p>
    <p v-else-if="!projects.length" class="empty">No projects yet.</p>
    <ul class="projects" v-else>
      <li v-for="p in projects" :key="p.key" data-test="project-item">
        <RouterLink :to="`/projects/${p.key}`">{{ p.name }}</RouterLink>
        <GateBadge :status="gates[p.key] || ''" />
      </li>
    </ul>
  </section>
</template>

<style scoped>
.projects { list-style: none; padding: 0; }
.projects li { display: flex; align-items: center; gap: 1rem; padding: 0.6rem 0; border-bottom: 1px solid #eee; }
.error { color: #c5221f; }
.empty { color: #666; }
</style>
