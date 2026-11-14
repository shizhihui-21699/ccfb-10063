<template>
  <span class="addr-view">
    <span v-if="addr?.name" class="addr-name">{{ addr.name }}</span>
    <span v-if="addr?.group" class="dim">(地址组 {{ addr.group.length }} 人)</span>
    <span v-if="addr?.address" class="addr-email mono" :class="{ reply: flagReply }">{{ addr.address }}</span>
    <span v-if="!addr?.address && !addr?.group" class="faint">(空)</span>
  </span>
</template>

<script setup>
defineProps({
  addr: { type: Object, default: null },
  flagReply: { type: Boolean, default: false }
})
</script>

<style scoped>
.addr-name {
  margin-right: 6px;
}
.addr-email {
  color: var(--text-dim);
}
.addr-email.reply {
  color: var(--high);
  font-weight: 600;
}
</style>
