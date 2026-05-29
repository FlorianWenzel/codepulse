<script setup>
defineProps({ issues: { type: Array, default: () => [] } })
</script>

<template>
  <table class="issues" v-if="issues.length">
    <thead>
      <tr><th>Severity</th><th>Type</th><th>Rule</th><th>Message</th><th>Location</th></tr>
    </thead>
    <tbody>
      <tr v-for="is in issues" :key="is.key" data-test="issue-row">
        <td><span :class="['sev', `sev-${is.severity}`]">{{ is.severity }}</span></td>
        <td>{{ is.type }}</td>
        <td class="rule">{{ is.ruleId }}</td>
        <td>{{ is.message }}</td>
        <td class="loc">{{ is.file }}:{{ is.line }}</td>
      </tr>
    </tbody>
  </table>
  <p v-else class="empty">No open issues 🎉</p>
</template>

<style scoped>
.issues { width: 100%; border-collapse: collapse; }
.issues th, .issues td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eee; font-size: 0.9rem; }
.rule, .loc { font-family: monospace; color: #555; }
.sev { font-weight: 600; font-size: 0.8rem; }
.sev-BLOCKER, .sev-CRITICAL { color: #c5221f; }
.sev-MAJOR { color: #ef6c00; }
.sev-MINOR { color: #f9a825; }
.sev-INFO { color: #1a73e8; }
.empty { color: #137333; }
</style>
