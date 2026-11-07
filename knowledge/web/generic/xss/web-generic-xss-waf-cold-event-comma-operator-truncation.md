---
id: web-generic-xss-waf-cold-event-comma-operator-truncation
title: WAF 保护下的存储型 XSS：冷门 HTML5 事件 FUZZ、逗号表达式隐藏 alert 特征与长度截断适配
type: scenario
domain: web
path: web/generic/xss
technique: xss-waf-cold-event-comma-operator
aliases:
- WAF 冷门事件绕过 XSS
- ontoggle 存储型 XSS
- 逗号表达式绕过 alert 特征
- a=alert,a(1)
- 32 字符截断 XSS
- 昵称存储型 XSS
tags:
- xss
- stored-xss
- waf
- bypass
- event-handler
- ontoggle
- comma-operator
- truncation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V67
  verified_at: '2026-11-05T11:55:34+08:00'
  notes: 已对照原文与13张图核对：昵称前端限20字符但抓包提交 <s>Test</s> 后渲染为删除线、<svg onmouseover=1> 被断连而纯 <svg> 放行、Intruder FUZZ 出 OnMouseEnter/OnMouseLeave/OnChange/OnToggle 等8个200事件、<dETAILS OnToggle=alert(1)> 被拦、a=alert,a(document.cookie) 提交成功但被系统截断为 '<dETAILS OnToggle=a=alert,a(docu'（32字符）、改用 a=alert,a(1) 保存成功且移动端点开详情弹窗1，均与原文一致。未验证点：未实际执行 PoC；目标应用未披露，无版本信息，未设 affected_versions；卡内'只拦 alert( 字面量'为原文结论的归纳；frontmatter 无 sources/source_url。
---

## 一句话结论

当昵称等用户资料字段被服务端原样渲染为 HTML、前端只做字符限制、WAF 只拦常见高危事件和 `alert(` 字面量时，可以抓包绕过前端校验，FUZZ 出 WAF 未收录的冷门 HTML5 事件（如 `ontoggle`），再用 JS 逗号表达式 `a=alert,a(1)` 消除 `alert(` 特征，并把 payload 压到服务端 32 字符硬截断以内，最终形成可触发的存储型 XSS。

## 原理

- **前端校验不是安全边界**：昵称输入框限制“中文/字母/数字、最多 20 字符”只是客户端 JS 校验；抓包拦截修改请求体即可直接向服务端提交任意字符，服务端若不再校验就会落库。
- **存储型 XSS 的基础**：服务端把昵称原样输出到 HTML，未做上下文编码，`<s>Test</s>` 这类标签会被浏览器解析，说明标签上下文可控。
- **WAF 事件黑名单**：WAF 未拦截纯 HTML 标签，但对 `onmouseover` 等常见高危事件直接断开连接；大小写变形（`OnMouseOver`/`ONMOUSEOVER`）也被忽略大小写匹配，说明规则是事件名黑名单。
- **冷门事件盲区**：`onmouseenter`、`onmouseleave`、`onchange`、`ontoggle` 等 HTML5 交互事件不在 WAF 规则库中，提交后正常返回；`ontoggle` 是 `<details>` 折叠展开事件，配合大小写混淆标签 `<dETAILS>` 可绕过标签名匹配。
- **逗号表达式**：`a=alert,a(1)` 先求值 `a=alert`（把原生 alert 函数赋给变量 a），再求值 `a(1)`（调用 a）。整个表达式按从左到右顺序执行，浏览器最终弹窗；但请求报文里不存在 `alert(` 这个特征串，WAF 的文本匹配失效。
- **32 字符硬截断**：服务端对昵称固定截断 32 个字符，超出部分静默丢弃。`<dETAILS OnToggle=a=alert,a(document.cookie)>` 会被截成 `<dETAILS OnToggle=a=alert,a(docu`，JS 语法残缺无法执行；必须把 payload 压到 32 字符以内，例如改用 `a(1)`。
- 该链成立的本质是三层“字符串层校验”与浏览器“语法/执行层”不一致：前端字符集限制、WAF 事件/函数名黑名单、服务端长度截断，都没有改变浏览器最终解析出的 HTML 与 JS 语义。

## 触发条件

- 存在用户可控的存储字段（昵称、签名、个人资料等），服务端原样输出到 HTML 且未做上下文编码；
- 前端仅做字符/长度校验，服务端接受直接构造的请求；
- WAF 使用事件名/函数名黑名单，未覆盖冷门 HTML5 事件，且未对 `alert(` 之外的等价写法做语义检测；
- 服务端存在固定长度硬截断（本案例 32 字符），payload 必须控制在限制内；
- 存储型场景需要受害者查看资料页并触发交互事件（本案例点击 `<details>` 展开）。

## 利用步骤

1. 抓取昵称修改请求，修改 `nickname` 参数，绕过前端字符限制。
2. 提交 `<s>Test</s>`，确认页面把标签解析为删除线，证明服务端未转义、存在 HTML 注入基础。
3. 提交 `<svg onmouseover=1>`，观察 WAF 是否断开连接；再提交纯标签 `<svg>`，确认 WAF 只拦事件不拦标签。
4. 对事件名做大小写与冷门事件 FUZZ：`OnMouseEnter`、`onmouseenter`、`OnMouseLeave`、`onmouseleave`、`OnChange`、`onchange`、`OnToggle`、`ontoggle`，筛选返回 200 的事件。
5. 选择 `ontoggle` 搭配 `<dETAILS>`，先试 `<dETAILS OnToggle=alert(1)>`，确认 `alert(` 被拦。
6. 改用逗号表达式：`<dETAILS OnToggle=a=alert,a(1)>`；若长度允许可用 `a=alert,a(document.cookie)`。
7. 检查服务端截断长度：若响应或回显显示 payload 被截断，缩短标签名/表达式，确保完整闭合。
8. 保存后访问资料页，点击“详情”展开 `<details>`，验证弹窗。

## PoC

```html
<!-- 1. 确认 HTML 解析 -->
<s>Test</s>

<!-- 2. 常见事件被 WAF 拦截 -->
<svg onmouseover=1>

<!-- 3. 冷门事件放行 -->
<dETAILS OnToggle=alert(1)>

<!-- 4. 逗号表达式消除 alert( 特征；长度需 ≤ 32 字符 -->
<dETAILS OnToggle=a=alert,a(1)>

<!-- 5. 长度允许时窃取 Cookie -->
<dETAILS OnToggle=a=alert,a(document.cookie)>
```

## 变体与关联

- 变体：其他冷门事件 `onmouseenter`、`onmouseleave`、`onchange`、`onpointerenter`、`onanimationstart`；自动触发可尝试 `<details open ontoggle=...>`，但 `open` 属性和 `ontoggle` 可能被更严格的规则拦截，需实测。
- 变体：逗号表达式可换成 `a=eval,a('...')`、`a=top['al'+'ert'],a(1)`、`a=window['alert'],a(1)`，核心是避免出现完整危险函数名加括号的特征。
- 变体：长度受限时优先压缩标签名大小写（`<dETAILS>` 与 `<details>` 同长）、去掉空格、把 `document.cookie` 换成 `1`，或改用更短的事件与变量名。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（无 script 标签时的事件处理器与 `<details ontoggle>` 载体）。
- 关联：[[web-generic-xss-filter-bypass-encoding-obfuscation]]（字符替换/黑名单的通用绕过；本卡补充 WAF 事件 FUZZ、逗号表达式与长度截断）。
- 关联：[[web-generic-xss-unauth-stored-xss-hot-question]]、[[web-generic-xss-admin-blind-stored-registration]]（其他存储型 XSS 场景）。
- 影响边界：`ontoggle` 需要受害者点击展开，属于交互依赖的存储型 XSS；若目标有 HttpOnly/CSP，Cookie 窃取会受限，但仍可执行页面内操作。

## 检测与防御

- 检测：请求体中出现 `ontoggle`、`onmouseenter`、`onmouseleave`、`onchange`、`<details`、`<dETAILS` 等事件/标签组合；出现 `=alert,`、`=eval,` 这类“赋值后逗号调用”的写法；昵称等短字段中出现 `<`、`>`、`=`、`,` 等非预期字符。
- 检测：WAF 对纯标签放行但对事件拦截的差异可作为规则缺口线索；对大小写混淆、HTML 实体、逗号表达式做规范化后再匹配。
- 防御：服务端对昵称等字段做输出上下文编码（HTML 实体编码），不要原样拼接；富文本使用白名单 sanitizer，禁止事件处理器属性。
- 防御：不要依赖前端字符校验和固定长度截断；服务端同时做类型、字符集、长度校验，但长度限制不能当作 XSS 防护。
- 防御：WAF 改为事件属性/标签白名单而非黑名单，覆盖冷门 HTML5 事件；部署 CSP 禁止内联事件处理器与 `unsafe-inline`，降低 XSS 成功后的危害。
