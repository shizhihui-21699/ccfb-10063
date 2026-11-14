<template>
  <div class="auth-pane">
    <!-- SPF -->
    <div class="card">
      <h3 class="section-title">
        SPF (Sender Policy Framework)
        <span class="badge" :class="spfBadge">{{ report.auth.spf.label }}</span>
      </h3>
      <p class="explain">{{ report.auth.spf.explanation }}</p>
      <div class="meta-line mono">
        客户端 IP {{ report.auth.clientIp || '未知' }} · 评估域 {{ report.auth.mailFromDomain || '—' }} · DNS 查询 {{ report.auth.spf.queryCount }} 次
      </div>
      <TraceBox :trace="report.auth.spf.trace" />
    </div>

    <!-- DKIM -->
    <div class="card">
      <h3 class="section-title">
        DKIM (DomainKeys Identified Mail)
        <span v-if="!report.auth.dkim.signatures.length" class="badge neutral">无签名</span>
        <span
          v-for="(s, i) in report.auth.dkim.signatures"
          :key="i"
          class="badge"
          :class="s.status === 'valid' ? 'safe' : 'critical'"
        >
          {{ s.status === 'valid' ? 'VALID' : 'INVALID' }} d={{ s.domain }}
        </span>
      </h3>

      <div v-if="!report.auth.dkim.signatures.length" class="faint">该邮件未携带 DKIM-Signature 头</div>
      <div v-for="(s, i) in report.auth.dkim.signatures" :key="i" class="dkim-sig">
        <table class="kv">
          <tr><td class="k">签名域 d=</td><td class="mono">{{ s.domain }}</td></tr>
          <tr><td class="k">选择子 s=</td><td class="mono">{{ s.selector }}</td></tr>
          <tr><td class="k">算法 a=</td><td class="mono">{{ s.algorithm }}</td></tr>
          <tr><td class="k">规范化 c=</td><td class="mono">{{ s.headerCanon }}/{{ s.bodyCanon }}</td></tr>
          <tr><td class="k">正文哈希 bh</td><td>
            <span :class="s.bodyHashMatch ? 'ok' : 'bad'">{{ s.bodyHashMatch ? '✓ 匹配' : '✗ 不匹配(正文可能被篡改)' }}</span>
          </td></tr>
          <tr><td class="k">签名 b</td><td>
            <span :class="s.signatureMatch ? 'ok' : 'bad'">{{ s.signatureMatch ? '✓ RSA 验证通过' : '✗ 签名验证失败' }}</span>
          </td></tr>
          <tr><td class="k">域对齐 i/d</td><td>
            <span :class="s.domainAligned ? 'ok' : 'bad'">{{ s.domainAligned ? '✓ 对齐' : '✗ 不对齐' }}</span>
          </td></tr>
          <tr v-if="s.expiration" class="k"><td class="k">过期时间 x=</td><td class="mono">{{ s.expiration }}</td></tr>
          <tr><td class="k">覆盖的头 h=</td><td class="mono">{{ s.signedHeaders.join(' / ') }}</td></tr>
          <tr v-if="s.dnsKey"><td class="k">DNS 公钥</td><td class="mono break-all">{{ s.dnsKey }}</td></tr>
        </table>
        <TraceBox :trace="s.trace" />
      </div>
    </div>

    <!-- DMARC -->
    <div class="card">
      <h3 class="section-title">
        DMARC (Domain-based Message Authentication)
        <span class="badge" :class="dmarcBadge">{{ report.auth.dmarc.result.toUpperCase() }}</span>
        <span class="badge neutral">{{ dispositionText }}</span>
      </h3>
      <p class="explain">{{ report.auth.dmarc.reason }}</p>
      <table class="kv" v-if="report.auth.dmarc.record">
        <tr><td class="k">记录位置</td><td class="mono">{{ report.auth.dmarc.recordDomain }}</td></tr>
        <tr><td class="k">原始记录</td><td class="mono break-all">{{ report.auth.dmarc.record }}</td></tr>
        <tr><td class="k">本域策略 p=</td><td class="mono">{{ report.auth.dmarc.publishedPolicy }}</td></tr>
        <tr><td class="k">子域策略 sp=</td><td class="mono">{{ report.auth.dmarc.subdomainPolicy }}</td></tr>
        <tr><td class="k">对齐模式</td><td class="mono">SPF {{ report.auth.dmarc.alignment.spf === 's' ? '严格' : '宽松' }} / DKIM {{ report.auth.dmarc.alignment.dkim === 's' ? '严格' : '宽松' }}</td></tr>
        <tr><td class="k">SPF 对齐</td><td><span :class="report.auth.dmarc.spfAligned ? 'ok' : 'bad'">{{ report.auth.dmarc.spfAligned ? '✓' : '✗' }}</span></td></tr>
        <tr><td class="k">DKIM 对齐</td><td><span :class="report.auth.dmarc.dkimAligned ? 'ok' : 'bad'">{{ report.auth.dmarc.dkimAligned ? '✓' : '✗' }}</span></td></tr>
        <tr v-if="report.auth.dmarc.rua"><td class="k">汇总报告 rua</td><td class="mono">{{ report.auth.dmarc.rua }}</td></tr>
      </table>
      <div v-else class="faint">该域未发布 DMARC 记录(结果为 none,接收方无策略可依)</div>
      <TraceBox :trace="report.auth.dmarc.trace" />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import TraceBox from '../widgets/TraceBox.vue'

const props = defineProps({ report: { type: Object, required: true } })

const spfBadge = computed(() => ({ pass: 'safe', fail: 'critical', softfail: 'medium', neutral: 'neutral', none: 'neutral', temperror: 'medium', permerror: 'critical' }[props.report.auth.spf.result]))
const dmarcBadge = computed(() => (props.report.auth.dmarc.result === 'pass' ? 'safe' : 'critical'))
const dispositionText = computed(() => ({ none: '处置:监控', quarantine: '处置:隔离', reject: '处置:拒收' }[props.report.auth.dmarc.disposition]))
</script>

<style scoped>
.card {
  margin-bottom: 14px;
}
.explain {
  margin: 4px 0 8px;
}
.meta-line {
  background: var(--bg);
  padding: 7px 10px;
  border-radius: 6px;
  color: var(--text-dim);
  margin-bottom: 10px;
}
.kv .k {
  width: 120px;
  color: var(--text-dim);
}
.break-all {
  word-break: break-all;
}
.ok {
  color: var(--safe);
  font-weight: 600;
}
.bad {
  color: var(--critical);
  font-weight: 600;
}
.dkim-sig {
  border-top: 1px solid var(--border);
  padding-top: 10px;
  margin-top: 10px;
}
h3 .badge {
  margin-left: 6px;
}
</style>
