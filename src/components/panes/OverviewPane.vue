<template>
  <div class="overview">
    <div class="grid-2">
      <div class="card">
        <h3 class="section-title">信封信息</h3>
        <table class="kv">
          <tr><td class="k">From</td><td><AddressView :addr="report.envelope.from" /></td></tr>
          <tr><td class="k">Sender</td><td><AddressView :addr="report.envelope.sender" /></td></tr>
          <tr><td class="k">Reply-To</td>
            <td>
              <template v-if="report.envelope.replyTo?.length">
                <span v-for="(a, i) in report.envelope.replyTo" :key="i">
                  <AddressView :addr="a" :flag-reply="true" /><br v-if="i < report.envelope.replyTo.length - 1" />
                </span>
              </template>
              <span v-else class="faint">(无)</span>
            </td>
          </tr>
          <tr><td class="k">Return-Path</td><td class="mono">{{ report.envelope.returnPath || '(无)' }}</td></tr>
          <tr><td class="k">To</td><td><AddressView v-for="(a, i) in report.envelope.to" :key="i" :addr="a" /><span v-if="!report.envelope.to?.length" class="faint">(无)</span></td></tr>
          <tr><td class="k">Date</td><td>{{ report.envelope.date || '(无)' }}</td></tr>
          <tr><td class="k">Message-ID</td><td class="mono break-all">{{ report.envelope.messageId || '(无)' }}</td></tr>
        </table>
      </div>

      <div class="card">
        <h3 class="section-title">认证结论</h3>
        <div class="auth-summary">
          <AuthRow name="SPF" :status="report.auth.spf.result" :label="report.auth.spf.label" :detail="report.auth.spf.explanation" />
          <AuthRow
            name="DKIM"
            :status="dkimStatus"
            :label="dkimLabel"
            :detail="report.auth.dkim.summary"
          />
          <AuthRow
            name="DMARC"
            :status="report.auth.dmarc.result"
            :label="report.auth.dmarc.result.toUpperCase()"
            :detail="`策略 p=${report.auth.dmarc.publishedPolicy || '无记录'} → 处置 ${dmarcDisp}`"
          />
        </div>
        <div class="id-align mono">
          <div>Header From 域:<b>{{ report.auth.headerFromDomain || '—' }}</b></div>
          <div>MAIL FROM 域:<b>{{ report.auth.mailFromDomain || '—' }}</b></div>
          <div>客户端 IP:<b>{{ report.auth.clientIp || '未知' }}</b></div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3 class="section-title">威胁评分依据 ({{ report.threat.score }}/100 · {{ levelText }})</h3>
      <div v-if="!report.threat.reasons.length" class="faint">未发现威胁特征</div>
      <div v-else class="reasons">
        <div v-for="(x, i) in report.threat.reasons" :key="i" class="reason-row">
          <span class="pts">+{{ x.pts }}</span>
          <span>{{ x.reason }}</span>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <h3 class="section-title">信头异常 ({{ report.headerAnalysis.findings.length }})</h3>
        <div v-if="!report.headerAnalysis.findings.length" class="faint">无异常</div>
        <Finding v-for="(f, i) in report.headerAnalysis.findings" :key="i" :f="f" />
      </div>
      <div class="card">
        <h3 class="section-title">投递异常 ({{ report.chain.anomalies.length }})</h3>
        <div v-if="!report.chain.anomalies.length" class="faint">投递路径无异常</div>
        <div v-for="(a, i) in report.chain.anomalies" :key="i" class="anomaly">⚠️ {{ a }}</div>
      </div>
    </div>

    <div class="card">
      <h3 class="section-title">分析师备注</h3>
      <textarea :value="report.notes" @input="onNotes" rows="3" placeholder="记录研判结论、处置动作、关联工单等(自动保存到本地)"></textarea>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import AddressView from '../widgets/AddressView.vue'
import Finding from '../widgets/Finding.vue'
import AuthRow from '../widgets/AuthRow.vue'
import { setNotes } from '../../lib/store.js'

const props = defineProps({ report: { type: Object, required: true } })

const levelText = computed(() => ({ critical: '严重', high: '高危', medium: '中危', low: '低危', safe: '安全' }[props.report.threat.level]))
const dkimStatus = computed(() => {
  if (!props.report.auth.dkim.signatures.length) return 'none'
  return props.report.auth.dkim.verified ? 'valid' : 'invalid'
})
const dkimLabel = computed(() => (props.report.auth.dkim.signatures.length ? (props.report.auth.dkim.verified ? 'VALID' : 'INVALID') : '无签名'))
const dmarcDisp = computed(() => ({ none: '不处置(仅监控)', quarantine: '隔离', reject: '拒收' }[props.report.auth.dmarc.disposition] || props.report.auth.dmarc.disposition))

function onNotes(e) {
  setNotes(props.report.id, e.target.value)
}
</script>

<style scoped>
.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-bottom: 12px;
}
.card {
  margin-bottom: 12px;
}
.kv .k {
  width: 110px;
  color: var(--text-dim);
  white-space: nowrap;
}
.break-all {
  word-break: break-all;
}
.auth-summary {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 12px;
}
.id-align {
  background: var(--bg);
  border-radius: 6px;
  padding: 9px 11px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  color: var(--text-dim);
}
.id-align b {
  color: var(--text);
}
.reasons {
  display: flex;
  flex-direction: column;
}
.reason-row {
  display: flex;
  gap: 12px;
  padding: 5px 0;
  border-bottom: 1px dashed var(--border);
}
.pts {
  color: var(--high);
  font-weight: 700;
  min-width: 38px;
}
.anomaly {
  color: var(--medium);
  padding: 4px 0;
  font-size: 12px;
}
textarea {
  width: 100%;
  resize: vertical;
}
@media (max-width: 1100px) {
  .grid-2 {
    grid-template-columns: 1fr;
  }
}
</style>
