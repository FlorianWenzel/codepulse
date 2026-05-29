<script setup>
defineProps({ hotspots: { type: Array, default: () => [] } })
const emit = defineEmits(['resolve'])
</script>

<template>
  <table class="hotspots" v-if="hotspots.length">
    <thead>
      <tr><th>Rule</th><th>Message</th><th>Location</th><th>Status</th><th>Actions</th></tr>
    </thead>
    <tbody>
      <tr v-for="h in hotspots" :key="h.key" data-test="hotspot-row">
        <td class="rule">{{ h.ruleId }}</td>
        <td>{{ h.message }}</td>
        <td class="loc">{{ h.file }}:{{ h.line }}</td>
        <td>{{ h.status }}</td>
        <td>
          <button type="button" data-test="safe-btn" :aria-label="`Mark ${h.ruleId} safe`"
                  @click="emit('resolve', { key: h.key, resolution: 'SAFE' })">Mark safe</button>
        </td>
      </tr>
    </tbody>
  </table>
  <p v-else class="empty">No security hotspots to review.</p>
</template>

<style scoped>
.hotspots { width: 100%; border-collapse: collapse; }
.hotspots th, .hotspots td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border, #eee); font-size: 0.9rem; }
.rule, .loc { font-family: monospace; color: var(--muted, #555); }
.empty { color: var(--muted, #666); }
</style>
