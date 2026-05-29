<script setup>
const props = defineProps({
  label: { type: String, required: true },
  value: { type: String, default: '' },
})
</script>

<template>
  <div class="rating" :data-test="`rating-${label}`">
    <span class="rating-label">{{ label }}</span>
    <span :class="['rating-letter', `r-${value}`]">{{ value || '–' }}</span>
  </div>
</template>

<style scoped>
.rating { display: inline-flex; flex-direction: column; align-items: center; margin-right: 1.5rem; }
.rating-label { font-size: 0.75rem; color: #666; }
.rating-letter { width: 28px; height: 28px; line-height: 28px; text-align: center; border-radius: 50%; color: #fff; font-weight: 700; }
.r-A { background: #137333; }
.r-B { background: #7cb342; }
.r-C { background: #f9a825; }
.r-D { background: #ef6c00; }
.r-E { background: #c5221f; }
</style>
