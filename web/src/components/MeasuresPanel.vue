<script setup>
import { computed } from 'vue'
import RatingBadge from './RatingBadge.vue'

const props = defineProps({ summary: { type: Object, default: () => ({}) } })

const cards = computed(() => {
  const s = props.summary || {}
  const out = [
    { label: 'Lines of code', value: s.totalNcloc ?? 0 },
    { label: 'Findings', value: s.totalFindings ?? 0 },
    { label: 'Duplication', value: `${(s.duplicatedLinesDensity ?? 0).toFixed(1)}%` },
  ]
  if (s.linesToCover) out.push({ label: 'Coverage', value: `${(s.coverage ?? 0).toFixed(1)}%` })
  return out
})
const ratings = computed(() => props.summary?.ratings || {})
</script>

<template>
  <div>
    <div class="ratings">
      <RatingBadge label="Reliability" :value="ratings.reliability" />
      <RatingBadge label="Security" :value="ratings.security" />
      <RatingBadge label="Maintainability" :value="ratings.maintainability" />
    </div>
    <div class="cards">
      <div class="card" v-for="c in cards" :key="c.label" data-test="measure-card">
        <div class="card-value">{{ c.value }}</div>
        <div class="card-label">{{ c.label }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ratings { margin: 1rem 0; }
.cards { display: flex; gap: 1rem; flex-wrap: wrap; }
.card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 1rem 1.25rem; min-width: 110px; }
.card-value { font-size: 1.5rem; font-weight: 700; }
.card-label { color: #666; font-size: 0.85rem; }
</style>
