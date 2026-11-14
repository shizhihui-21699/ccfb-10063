# 钓鱼邮件分析台 · PhishMail Console

一个纯前端、零后端的本地钓鱼邮件分析工作台。员工转发来的 `.eml` / `.mbox` 样本拖进来即可完成
MIME 解析、SPF/DKIM/DMARC 本地校验、投递路径还原、链接去武装和附件静态分析,全程不联网、不执行附件。

技术栈:Vue 3 + Vite + postal-mime,加密验签用浏览器原生 Web Crypto。

## 快速开始

```bash
npm install
npm run gen-samples   # 生成 26 封样例邮件(已随仓库附带,可重复生成)
npm run dev           # 启动 http://127.0.0.1:5173
```

打开后点右上角 **「载入样例」** 即可导入全部演示邮件;也可用 **「导入 eml / mbox」** 分析真实样本。

- `npm run build` 生产构建,产物在 `dist/`
- `npm test` 跑分析引擎的 30 项 Node 断言(SPF/DKIM/DMARC、编码、mbox 切分等)

## 功能清单

### 邮件解析
- **MIME 结构树**:自研字节级解析器保留完整 `multipart` 嵌套(支持 5 层深嵌套、`message/rfc822` 转发),不依赖打平后的附件列表
- **编码还原**:RFC 2047 encoded-word(Base64 / Quoted-Printable)、RFC 2231 续行文件名、多层嵌套 encoded-word;
  字符集覆盖 UTF-8 / GBK / GB2312 / Big5 / Shift_JIS / EUC-KR / ISO-8859-1 等(WHATWG TextDecoder)
- postal-mime 负责正文与附件的稳健解码,两套解析互为补充

### 身份认证(全部本地,DNS 走 Mock)
- **SPF**(RFC 7208 子集):`ip4/ip6/a/mx/include/exists/ptr/redirect/all`,限定符 `+ - ~ ?`,
  10 次查询上限与 include 环路防护,输出完整评估追溯
- **DKIM**(RFC 6376):Web Crypto 做**真实 RSA-SHA256 验签**,relaxed/simple 头部与正文规范化(字节级)、
  `bh=` 正文哈希、`b=` 签名、`x=` 过期、`i/d` 域对齐、公钥撤销等
- **DMARC**(RFC 7489):SPF/DKIM 标识符对齐(严格/宽松)、`p/sp/pct` 策略、`reject/quarantine/none` 处置建议、组织域上溯
- **Mock DNS**:内置 SPF/DKIM/DMARC/MX/PTR 记录,界面里可查看、覆盖、重置,持久化到 localStorage;
  样例 DKIM 公钥启动时自动装载

### 投递路径
- 解析全部 `Received` 头,反转为发件端→收件端的跳转图,标注 HELO / IP / 协议 / 时间
- 每跳做 PTR 反向解析与正向确认、头中声称名比对
- 时间线倒流、无 PTR、rDNS 不符等异常自动提示

### 链接分析
- 提取 HTML `<a>` 与纯文本 URL,**显示文字与真实地址不一致时整行标红**
- **去武装(defang)**:`http→hxxp`、`.→[.]`、`@→[@]`,可一键复制
- IDN/punycode 同形异义(同时展示 Unicode 与 ASCII 形态)、IP 直连、`@` 用户名混淆、
  非标端口、高风险 TLD、敏感查询参数、嵌套编码、`javascript:`/`data:` 伪链接

### 附件静态分析(绝不执行)
- 文件头魔数识别真实类型,与声明扩展名/MIME 比对(类型伪装、双扩展名 `发票.pdf.exe`、RTLO、空格伪装)
- OLE 复合文档 VBA 宏特征(`AutoOpen`/`WScript.Shell`/`_VBA_PROJECT` 等)、OOXML 宏部件
- 脚本/可执行/快捷方式类型、LOLBin 调用特征、LNK 目标
- ZIP 中央目录条目扫描(危险条目、Zip Slip 路径穿越),不解压
- SHA-256 / MD5 哈希、香农熵、可疑文本预览

### 研判与产出
- 0–100 威胁评分与五级定级,逐条给出来源
- 自动标签(伪造发件人、链接欺骗、宏文档、回复劫持等)+ 自定义标签 + 分析师备注,本地持久化
- 导出:**单封** JSON / TXT / 独立 HTML 报告,**批量**汇总 CSV / 合并 JSON

## 目录结构

```
src/
  lib/
    analyzer.js      主编排,串联所有分析模块
    mime-tree.js     字节级 MIME 结构树解析
    encoding.js      encoded-word / RFC2231 / 多字符集 / IDN
    mock-dns.js      本地 DNS 记录与查询
    spf.js dkim.js dmarc.js   三大认证
    received.js      Received 链解析与反查
    urls.js          链接提取、去武装、欺骗识别
    attachment.js    附件静态分析、魔数、宏、哈希
    headers.js       信头伪造检测与威胁评分
    mbox.js          mbox/mboxrd 字节级切分
    store.js         Vue 响应式状态与持久化
    export-report.js 报告导出
  components/        Vue 组件(8 个分析 Tab 面板 + 列表 + DNS 管理)
tools/
  generate-samples.js  样例邮件生成器(Node crypto 真实 DKIM 签名)
  charset-tables.js    多字节字符集编码表(TextDecoder 反查构建)
node-test/
  run-tests.mjs     引擎断言测试
  browser-e2e*.mjs  CDP 浏览器端到端验证(开发用)
public/samples/     26 封 eml + 2 个 mbox + DKIM 公钥
```

## 样例邮件覆盖(26 封)

正常邮件(三认证全过)、伪造发件人、显示名欺骗、Reply-To 劫持(BEC)、punycode 同形异义、
链接文字/地址不符、VBA 宏、双扩展名、GBK/Big5/RFC2231 深层编码嵌套、`message/rfc822` 嵌套、
五层 multipart、DKIM 过期/篡改、SPF softfail/none、DMARC fail/quarantine、无防护域名、
脚本附件、带毒 ZIP 与路径穿越、LNK、IP 直连与 `@` 混淆、群发工具头、Received 时间倒流等。

## 安全说明

- 所有 DNS 数据为本地 Mock,不产生任何真实网络请求
- 附件仅做静态字节分析,不存在任何执行/解压运行路径
- 正文 HTML 安全视图会剥离 `script`、事件属性、外链资源与危险协议
- 分析状态与人工标注只存浏览器 localStorage,不上传
