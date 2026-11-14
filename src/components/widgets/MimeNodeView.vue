<template>
  <div class="node">
    <div class="node-line" :class="{ multipart: node.isMultipart, leaf: !node.isMultipart }">
      <span class="part-id mono">{{ node.partId }}</span>
      <span class="ctype">{{ node.contentType }}</span>
      <span v-if="node.isMultipart" class="mp-tag">multipart · {{ node.children.length }} 子部件</span>
      <span v-else class="leaf-tag">{{ node.disposition || 'inline' }}</span>
      <span class="meta mono faint">
        {{ node.transferEncoding }}<span v-if="node.charset"> · {{ node.charset }}</span> · {{ node.size }}B
      </span>
      <span v-if="node.filename" class="fname">📎 {{ node.filename }}</span>
    </div>
    <div v-if="node.children.length" class="children">
      <MimeNodeView v-for="c in node.children" :key="c.partId" :node="c" :depth="depth + 1" />
    </div>
  </div>
</template>

<script setup>
defineProps({ node: { type: Object, required: true }, depth: { type: Number, default: 0 } })
</script>

<style scoped>
.node {
  position: relative;
}
.children {
  margin-left: 22px;
  padding-left: 14px;
  border-left: 1px dashed var(--border);
}
.node-line {
  display: flex;
  gap: 10px;
  align-items: center;
  padding: 5px 8px;
  border-radius: 5px;
  font-size: 12px;
  flex-wrap: wrap;
}
.node-line:hover {
  background: var(--bg-elev);
}
.node-line.multipart .ctype {
  color: var(--accent);
  font-weight: 700;
}
.part-id {
  color: var(--medium);
  font-weight: 700;
  min-width: 42px;
}
.mp-tag {
  background: var(--accent-dim);
  color: #fff;
  border-radius: 9px;
  padding: 0 9px;
  font-size: 10.5px;
}
.leaf-tag {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 9px;
  padding: 0 9px;
  font-size: 10.5px;
  color: var(--text-dim);
}
.meta {
  font-size: 10.5px;
}
.fname {
  color: var(--high);
  font-size: 11.5px;
}
</style>
