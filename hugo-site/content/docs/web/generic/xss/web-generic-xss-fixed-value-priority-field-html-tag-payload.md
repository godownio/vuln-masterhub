---
id: web-generic-xss-fixed-value-priority-field-html-tag-payload
title: 「优先级」固定值字段改包注入 HTML 标签型 payload：绕过常规弹窗黑名单实现后台存储型 XSS
type: scenario
domain: web
path: web/generic/xss
technique: fixed-value-field-html-tag-stored-xss
tags:
- web
- xss
- stored-xss
- parameter-tampering
- waf-bypass
- html-tag
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:25:59+08:00'
  notes: 已对照原文核对；原文抓包为 inline_update 接口 Value=High<u onclick=alert(1)>aaa</u>，写入后优先级字段回显 Higha 并成功弹窗，与卡片 PoC 一致；未验证点：原文仅说payload需要绕过一下，抓包中 alert(1) 为明文，卡片对具体拦截关键字/黑名单规则的描述属推断
url: /docs/web/generic/xss/web-generic-xss-fixed-value-priority-field-html-tag-payload/
draft: false
kb_aliases:
- 优先级字段 XSS
- 固定值下拉框改包注入
- HTML 标签型 payload 绕过黑名单
- 后台固定值字段存储型 XSS
---

## 一句话结论

需求/任务管理系统的「优先级」字段在界面上是固定值下拉框（如 `High`），很多人因此认为不可控；抓包后直接把该参数改成 HTML 标签型 payload（如 `High<u>1</u>`，并进一步用 `onclick` 一类事件属性），常规「弹窗关键字」黑名单拦不住，落库后在详情页/列表页被原样渲染，形成后台存储型 XSS。

## 原理

- 前端「固定值」只是 UI 约束：下拉框限制了可选项，但提交时的参数值来自请求体，抓包即可任意改写；服务端若只按「枚举合法性」做校验（甚至完全不校验），就会把攻击者字符串写入数据库。
- 常规 XSS 过滤器针对 `alert(`、`<script>`、`javascript:` 等关键字做黑名单；用**非脚本标签 + 事件属性**（`<u onclick=...>`、`<img onerror=...>`、`<svg onload=...>`）可以避开 `<script>` 关键字，而 `onclick` 里拼 `alert` 字样仍可能被关键字拦，因此常见做法是把函数名/参数拆开或用等价写法（`confirm`、`prompt`、`top['al'+'ert'](1)`、模板字符串拼接）。
- 之所以能弹窗：只有当服务端把该字段直接拼进 HTML（而不是 JSON 转义/前端 `textContent` 渲染）时，标签才会被解析；若前端用富文本框编辑器渲染该字段，更会主动保留 HTML。
- 危害：后台存储型 XSS 打的是管理员会话，可读 CSRF token、代替管理员执行操作（添加账号、导出数据），在管理端与业务端跨站时还能横向扩散。
- 该案例中 payload 需要「绕过一下」才弹窗，说明存在关键字黑名单但不完整，属可复用技巧而非一次性偶然：先探测哪些标签/属性未被拦，再选可用组合。

## 触发条件

- 目标字段（本案例为「优先级」）的取值可被客户端改写，且服务端未做严格枚举校验。
- 该字段在后续页面被拼进 HTML 渲染（详情页、列表、通知、导出 HTML 报表等）。
- WAF/过滤器只做部分关键字黑名单，未对 `<`、事件属性、标签做统一编码。
- 触发渲染的页面会被管理员/其他用户访问（后台列表、任务详情）。

## 利用步骤

1. 在任务/需求详情页找到「优先级」这类固定值字段，记下当前值（如 `High`）。
2. 对该字段做一次编辑提交并抓包，定位请求体中对应的参数名与格式（表单字段或 JSON 键）。
3. 先探测过滤强度：提交 `High<u>1</u>`，查看保存后页面是否显示为带下划线的 `1`（说明 `<u>` 未被编码）。
4. 逐步升级到事件属性：`High<u onclick=alert(1)>a</u>`；若被拦，改用 `confirm`、`prompt`、`<svg onload=...>`、`<img src=x onerror=...>`、大小写混写、属性加引号/不加引号等组合。
5. 确认落库与渲染：保存后刷新详情页/列表页，点击被渲染的标签触发；若只有管理员页面渲染，则用管理员账号访问验证。
6. 记录存储位置（哪张表/哪个字段、哪些页面渲染），评估影响范围；测试 payload 用无害标记（如弹出固定字符串）并随后清理。

## PoC

请求（字段名按实际抓包替换；payload 为最小可用形态）：

```http
POST /api/task/inline_update?r=<时间戳> HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

<字段名>=High<u+onclick=alert(1)>aaa</u>
```

被渲染后的页面中该值显示为带下划线的 `aaa`，点击即执行；若 `alert` 被关键字拦截，可换等价写法：

```html
High<u onclick=top['al'+'ert'](1)>aaa</u>
```

## 变体与关联

- 变体：`<svg onload>`、`<img onerror>`、`<details ontoggle>`、`<marquee onstart>` 等非 `<script>` 标签配合事件属性，是绕 `<script>` 关键字黑名单的常用集合。
- 变体：属性值不加引号、标签名大小写混写（`<SvG OnLoAd=...>`）、`<a href="javas&#99;ript:...">` 实体编码，用于绕弱正则。
- 变体：同一表单的其它「固定值」字段（状态、类型、来源、渠道）往往共用同一保存逻辑，一处可注入后逐个测。
- 关联：[[web-generic-xss-waf-cold-event-comma-operator-truncation]]（同样用冷门 HTML5 事件与表达式隐藏关键字，可与本卡的标签型 payload 互补）。
- 关联：[[web-generic-xss-unauth-stored-xss-hot-question]]（后台存储型 XSS 的另一种入口，未授权新增接口）。

## 检测与防御

- 防御：对所有字段（包括枚举/固定值字段）在服务端做白名单校验，非法值直接拒绝，不依赖前端下拉框。
- 防御：输出编码按上下文处理（HTML 文本用实体编码、属性用引号包裹并编码、JSON 返回后前端用 `textContent` 渲染），不使用 `innerHTML`/`v-html`/`dangerouslySetInnerHTML` 直接渲染用户字段。
- 防御：富文本场景引入成熟 sanitizer（DOMPurify 等）并在服务端二次过滤；CSP 限制 `unsafe-inline`。
- 检测：WAF 规则覆盖事件属性（`onclick`/`onerror`/`onload`/`ontoggle`）与非脚本标签组合，而不仅是 `<script>`/`alert(`。
- 检测：审计「枚举字段」的保存接口是否做了枚举校验；对后台渲染的字段做存储层扫描（入库后定期 grep 标签特征）。
