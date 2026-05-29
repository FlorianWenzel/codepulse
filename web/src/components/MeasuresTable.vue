<script setup>
import { computed } from 'vue'

const props = defineProps({ files: { type: Array, default: () => [] } })

// Drilldown: files sorted by cyclomatic complexity (worst first).
const rows = computed(() =>
  [...(props.files || [])].sort((a, b) => (b.complexity || 0) - (a.complexity || 0))
)

function coverage(f) {
  if (!f.linesToCover) return '—'
  return `${((f.coveredLines / f.linesToCover) * 100).toFixed(0)}%`
}
</script>

<template>
  <table class="measures" v-if="rows.length">
    <thead>
      <tr><th>File</th><th>NCLOC</th><th>Complexity</th><th>Cognitive</th><th>Dup. lines</th><th>Coverage</th></tr>
    </thead>
    <tbody>
      <tr v-for="f in rows" :key="f.path" data-test="measure-row">
        <td class="path">{{ f.path }}</td>
        <td>{{ f.ncloc }}</td>
        <td>{{ f.complexity }}</td>
        <td>{{ f.cognitiveComplexity }}</td>
        <td>{{ f.duplicatedLines }}</td>
        <td>{{ coverage(f) }}</td>
      </tr>
    </tbody>
  </table>
</template>

<style scoped>
.measures { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
.measures th, .measures td { text-align: left; padding: 5px 10px; border-bottom: 1px solid var(--border, #eee); font-size: 0.88rem; }
.path { font-family: monospace; }
</style>
