<template>
  <div class="auth-row">
    <span class="auth-dot" :class="status"></span>
    <span class="auth-name">{{ name }}</span>
    <span class="auth-label" :class="status">{{ label }}</span>
    <span class="auth-detail dim">{{ detail }}</span>
  </div>
</template>

<script setup>
defineProps({
  name: String,
  status: String,
  label: String,
  detail: String
})
</script>

<style scoped>
.auth-row {
  display: flex;
  align-items: center;
  gap: 9px;
  font-size: 12.5px;
}
.auth-name {
  font-weight: 700;
  min-width: 52px;
}
.auth-label {
  min-width: 78px;
  font-weight: 700;
  font-family: var(--mono);
}
.auth-label.pass,
.auth-label.valid {
  color: var(--safe);
}
.auth-label.fail,
.auth-label.invalid {
  color: var(--critical);
}
.auth-label.softfail {
  color: var(--medium);
}
.auth-label.none,
.auth-label.neutral {
  color: var(--text-faint);
}
.auth-detail {
  font-size: 11.5px;
}
</style>
