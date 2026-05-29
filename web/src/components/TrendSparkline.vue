<script setup>
import { computed } from 'vue'

const props = defineProps({
  points: { type: Array, default: () => [] }, // [{ value }]
  label: { type: String, default: '' },
})

const max = computed(() => Math.max(1, ...props.points.map((p) => p.value || 0)))
function height(v) {
  return `${Math.round(((v || 0) / max.value) * 100)}%`
}
</script>

<template>
  <div class="trend" v-if="points.length">
    <span class="trend-label">{{ label }}</span>
    <div class="bars" role="img" :aria-label="`${label} trend over ${points.length} analyses`">
      <span v-for="(p, i) in points" :key="i" class="bar" data-test="trend-bar"
            :style="{ height: height(p.value) }" :title="String(p.value)"></span>
    </div>
    <span class="trend-current">{{ points[points.length - 1].value }}</span>
  </div>
</template>

<style scoped>
.trend { display: inline-flex; align-items: flex-end; gap: 0.5rem; margin: 0.5rem 0; }
.trend-label { font-size: 0.8rem; color: var(--muted, #666); }
.bars { display: inline-flex; align-items: flex-end; gap: 2px; height: 32px; }
.bar { width: 6px; background: #1a73e8; min-height: 2px; border-radius: 1px; }
.trend-current { font-weight: 700; }
</style>
