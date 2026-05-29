<script setup>
const props = defineProps({
  issues: { type: Array, default: () => [] },
  ruleMeta: { type: Object, default: () => ({}) }, // ruleId -> { description, cwe, ... }
})
const emit = defineEmits(['transition'])

function meta(id) {
  return props.ruleMeta[id] || {}
}
</script>

<template>
  <table class="issues" v-if="issues.length">
    <thead>
      <tr><th>Severity</th><th>Type</th><th>Rule</th><th>Message</th><th>Location</th><th>Actions</th></tr>
    </thead>
    <tbody>
      <tr v-for="is in issues" :key="is.key" data-test="issue-row">
        <td><span :class="['sev', `sev-${is.severity}`]">{{ is.severity }}</span></td>
        <td>{{ is.type }}</td>
        <td class="rule">
          <span :title="meta(is.ruleId).description || ''">{{ is.ruleId }}</span>
          <span v-for="c in (meta(is.ruleId).cwe || [])" :key="c" class="cwe" data-test="cwe-badge">{{ c }}</span>
        </td>
        <td>{{ is.message }}</td>
        <td class="loc">{{ is.file }}:{{ is.line }}</td>
        <td class="actions">
          <button type="button" data-test="resolve-btn"
                  :aria-label="`Resolve ${is.ruleId}`"
                  @click="emit('transition', { key: is.key, transition: 'resolve' })">Resolve</button>
          <button type="button" data-test="fp-btn"
                  :aria-label="`Mark ${is.ruleId} as false positive`"
                  @click="emit('transition', { key: is.key, transition: 'falsepositive' })">False positive</button>
        </td>
      </tr>
    </tbody>
  </table>
  <p v-else class="empty">No open issues 🎉</p>
</template>

<style scoped>
.issues { width: 100%; border-collapse: collapse; }
.issues th, .issues td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border, #eee); font-size: 0.9rem; }
.rule, .loc { font-family: monospace; color: var(--muted, #555); }
.cwe { display: inline-block; margin-left: 6px; padding: 0 6px; border-radius: 8px; background: #fce8e6; color: #c5221f; font-family: sans-serif; font-size: 0.72rem; }
.sev { font-weight: 600; font-size: 0.8rem; }
.sev-BLOCKER, .sev-CRITICAL { color: #c5221f; }
.sev-MAJOR { color: #ef6c00; }
.sev-MINOR { color: #f9a825; }
.sev-INFO { color: #1a73e8; }
.actions button { font-size: 0.78rem; margin-right: 4px; cursor: pointer; }
.empty { color: #137333; }
</style>
