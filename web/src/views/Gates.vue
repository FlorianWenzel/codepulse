<script setup>
import { ref, reactive, onMounted } from 'vue'
import api from '../api.js'

const gates = ref([])
const projects = ref([])
const error = ref('')
const notice = ref('')

const METRICS = [
  'vulnerabilities', 'bugs', 'code_smells', 'blocker_issues', 'critical_issues',
  'coverage', 'duplicated_lines_density', 'new_vulnerabilities', 'new_blocker_issues',
]
const OPS = ['GT', 'LT', 'EQ', 'NE']

const form = reactive({ id: '', name: '', conditions: [] })
const cond = reactive({ metric: 'vulnerabilities', op: 'GT', threshold: 0 })
const assignSel = reactive({ project: '', gateId: '' })

async function load() {
  try {
    gates.value = (await api.listGates()) || []
    projects.value = (await api.listProjects()) || []
  } catch (e) {
    error.value = String(e)
  }
}
onMounted(load)

function addCondition() {
  form.conditions.push({ metric: cond.metric, op: cond.op, threshold: Number(cond.threshold) })
}

async function createGate() {
  error.value = ''
  notice.value = ''
  try {
    await api.createGate({ id: form.id, name: form.name || form.id, conditions: form.conditions })
    notice.value = `Gate "${form.id}" saved`
    form.id = ''
    form.name = ''
    form.conditions = []
    await load()
  } catch (e) {
    error.value = String(e)
  }
}

async function assign() {
  error.value = ''
  notice.value = ''
  try {
    await api.assignGate(assignSel.project, assignSel.gateId)
    notice.value = `Assigned ${assignSel.gateId} to ${assignSel.project}`
  } catch (e) {
    error.value = String(e)
  }
}
</script>

<template>
  <section>
    <RouterLink to="/">← Projects</RouterLink>
    <h1>Quality gates</h1>
    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="notice" class="notice">{{ notice }}</p>

    <ul class="gates">
      <li v-for="g in gates" :key="g.id" data-test="gate-item">
        <strong>{{ g.id }}</strong> — {{ g.name }}
        <span class="conds">{{ (g.conditions || []).map(c => `${c.metric} ${c.op} ${c.threshold}`).join(', ') }}</span>
      </li>
    </ul>

    <h2>Create / update a gate</h2>
    <form @submit.prevent="createGate" class="gate-form">
      <input v-model="form.id" placeholder="id (e.g. strict)" aria-label="Gate id" required />
      <input v-model="form.name" placeholder="name" aria-label="Gate name" />
      <div class="cond-row">
        <select v-model="cond.metric" aria-label="Metric"><option v-for="m in METRICS" :key="m">{{ m }}</option></select>
        <select v-model="cond.op" aria-label="Operator"><option v-for="o in OPS" :key="o">{{ o }}</option></select>
        <input type="number" v-model="cond.threshold" aria-label="Threshold" />
        <button type="button" data-test="add-cond" @click="addCondition">Add condition</button>
      </div>
      <ul><li v-for="(c, i) in form.conditions" :key="i" data-test="form-cond">{{ c.metric }} {{ c.op }} {{ c.threshold }}</li></ul>
      <button type="submit" data-test="save-gate">Save gate</button>
    </form>

    <h2>Assign gate to project</h2>
    <div class="assign">
      <select v-model="assignSel.project" aria-label="Project"><option value="" disabled>project…</option><option v-for="p in projects" :key="p.key" :value="p.key">{{ p.key }}</option></select>
      <select v-model="assignSel.gateId" aria-label="Gate"><option value="" disabled>gate…</option><option v-for="g in gates" :key="g.id" :value="g.id">{{ g.id }}</option></select>
      <button type="button" data-test="assign-gate" @click="assign">Assign</button>
    </div>
  </section>
</template>

<style scoped>
.gates { list-style: none; padding: 0; }
.gates li { padding: 0.4rem 0; border-bottom: 1px solid var(--border, #eee); }
.conds { color: var(--muted, #666); font-size: 0.85rem; margin-left: 0.5rem; }
.gate-form, .assign { display: flex; flex-direction: column; gap: 0.5rem; max-width: 520px; }
.cond-row { display: flex; gap: 0.5rem; align-items: center; }
.assign { flex-direction: row; }
.error { color: #c5221f; }
.notice { color: #137333; }
</style>
