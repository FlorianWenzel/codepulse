<script setup>
import { computed } from 'vue'

const props = defineProps({ status: { type: String, default: '' } })

const label = computed(() => {
  if (props.status === 'OK') return 'Passed'
  if (props.status === 'ERROR') return 'Failed'
  return 'No analysis'
})
const cls = computed(() => ({
  'gate-badge': true,
  'gate-ok': props.status === 'OK',
  'gate-error': props.status === 'ERROR',
  'gate-none': props.status !== 'OK' && props.status !== 'ERROR',
}))
</script>

<template>
  <span :class="cls" data-test="gate-badge">{{ label }}</span>
</template>

<style scoped>
.gate-badge { padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.85rem; }
.gate-ok { background: #e6f4ea; color: #137333; }
.gate-error { background: #fce8e6; color: #c5221f; }
.gate-none { background: #eee; color: #666; }
</style>
