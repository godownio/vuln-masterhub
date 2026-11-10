---
id: code-analysis-dynamic-debugging-devtools-websocket-cdp-traffic-reverse
title: 抓包 DevTools 自身 WebSocket 反推 Chrome DevTools Protocol 调用：id/method/params 与 result 逐条复现 UI 操作
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: devtools-websocket-cdp-traffic-reverse
aliases:
- CDP 抓包
- DevTools WebSocket 分析
- chrome 远程调试协议
- remote-debugging-port 抓包
- id method params
- 复现 DevTools 操作
tags:
- chrome
- devtools
- cdp
- websocket
- wireshark
- debugging
- automation
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V435
  verified_at: '2026-11-09T20:18:07+08:00'
  notes: 已对照原文与图04-19核对：Wireshark 先抓 \Device\NPF_Loopback（websocket 过滤器）再建连、chrome://inspect Configure localhost:9222、方向判定（Dst 9222 为客户端请求、Src 9222 为 result/事件）、line-based text data 中 id/method/params 与 id 配对 result、Debugger.paused 无 id 事件，以及 Network.enable/Debugger.enable(maxScriptsCacheSize)/setPauseOnExceptions/setBlackboxPatterns/DOMDebugger.setXHRBreakpoint 序列均与抓包图一致；原文未给组件版本，affected_versions 留空正确；PoC 为抓包帧记录未逐条重放。与 proxy 改包绕反调试卡（改响应而非读协议）不同链，dedup 首位为自身自比对 exact，非姐妹卡重复。dup-scan.json 早于建卡且无本篇 pair。
---

## 一句话结论

当 Chrome DevTools Protocol 文档没有说明某个 DevTools 功能对应哪些调用/参数时，用 Wireshark 抓回环网卡上 DevTools 前端与远程调试端口之间的 WebSocket 文本帧，按 `id` 对齐请求/响应、读 `method`/`params`/`result`，就能得到在 chrome://inspect 里执行该操作时实际发送的 CDP 调用序列，再在 pychrome 等客户端里逐条复现。

## 原理

- Chrome 的远程调试通过 WebSocket 传输 JSON-RPC 帧：客户端发送 `{"id":N,"method":"Domain.method","params":{...}}`，浏览器回 `{"id":N,"result":{...}}`（或 `error`）。DevTools 前端本身就是一个 CDP 客户端，它在 UI 上的每个操作都会翻译成确定的 CDP 调用。
- 只要抓取“DevTools 与浏览器之间的回环流量”，就能看到未文档化/未说明的调用顺序与参数。关键点：必须**先启动抓包再建立 WebSocket 连接**，否则抓不到握手（含 Sec-WebSocket-Key），Wireshark 无法解密后续帧；过滤条件用 `websocket`。
- 方向判定：远程调试服务监听 9222/9229，TCP 目标端口为服务端的是客户端→浏览器（method 请求），源端口为服务端的是浏览器→客户端（result/事件）。
- 帧内容里的 `line-based text data` 就是 JSON 文本；`id` 用于把响应和请求配对，事件（如 `Debugger.paused`）没有 id，但带 `method` 与 `params`。
- 典型观察：DevTools 打开面板时会先发对应域的 `*.enable`（如 `Network.enable`、`Debugger.enable`），再做配置（`Debugger.setPauseOnExceptions`、`Debugger.setBlackboxPatterns`、`Debugger.setAsyncCallStackDepth`、`DOMDebugger.setXHRBreakpoint`），最后才是在用户操作下触发的 `Debugger.paused` 等事件。
- 这个方法的价值：无需猜测文档，也无需读 DevTools 源码，用真实流量即可确定“UI 操作 → CDP 调用”的映射，适合为自动化脚本补齐配置项。

## 触发条件

- 已用 `--remote-debugging-port` 启动 Chrome/Chromium，并能通过 chrome://inspect 或其 DevTools 前端连接。
- 能在同一台机器上抓回环（loopback）流量（Wireshark/Npcap），且抓包在 WebSocket 握手之前开始。
- 调试流量未使用额外加密层（CDP over WebSocket 默认明文 JSON，TLS 远程目标除外）。

## 利用步骤

1. `chrome.exe --remote-debugging-port=9222` 启动浏览器，打开目标页面。
2. 先启动 Wireshark 抓 `\Device\NPF_Loopback`（或 lo），过滤 `websocket`。
3. 在 chrome://inspect 的 Devices → Configure 中填 `localhost:9222`，对目标页点 inspect 打开 DevTools，连接建立。
4. 在 DevTools 中执行要复现的操作（示例：Sources → XHR/fetch Breakpoints 勾选 Any XHR or fetch，刷新页面，点击几个调用栈帧）。
5. 停止抓包，在 Wireshark 搜索 `Debugger.paused`，逐帧查看 `line-based text data`；按 `id` 找到对应 `result`。
6. 记录调用序列与参数（domain enable 顺序、配置方法、断点参数），在 pychrome/CDP 客户端中复现。

## PoC

```text
Wireshark 显示过滤器: websocket

# 示例抓到的 CDP 请求（方向：客户端 -> 9222）
{"id":2,"method":"Network.enable","params":{"maxPostDataSize":65536}}
{"id":9,"method":"Debugger.enable","params":{"maxScriptsCacheSize":10000000}}
{"id":10,"method":"Debugger.setPauseOnExceptions","params":{"state":"none"}}
{"id":27,"method":"Debugger.setBlackboxPatterns","params":{"patterns":["/node_modules/","/bower_components/"]}}
{"id":28,"method":"DOMDebugger.setXHRBreakpoint","params":{"url":""}}
# 事件（无 id）：{"method":"Debugger.paused","params":{"callFrames":[...],"reason":"XHR",...}}
```

## 变体与关联

- 关联 [[code-analysis-reverse-obfuscation-ai-mcp-chrome-devtools-js-encryption-reverse]]：用 Chrome DevTools MCP/AI 驱动浏览器做 JS 逆向；本卡是更底层的协议抓包与调用复现方法，可用来补全 MCP 不暴露的配置。
- 关联 [[code-analysis-dynamic-debugging-cdp-callframe-scope-local-variables]]：抓包得到的关键用例——用 `Debugger.paused` 的 callFrames/scopeChain 提取局部变量。
- 变体：抓 `wss://` 远程目标时需处理 TLS；用 CDP 的 `Tracing`/`Log` 域或 `Target.setAutoAttach` 观察多会话流量；用 mitmproxy 代替 Wireshark 解 WebSocket 帧。
- 边界：Chrome 版本更新会改变 DevTools 发送的调用序列，需以实测为准；部分帧为 binary/压缩格式，需按 WebSocket 帧解析而不是直接看 text。

## 检测与防御

- 远程调试端口等于对浏览器进程的完全控制，禁止在生产/办公环境暴露 `--remote-debugging-port`（尤其绑定 0.0.0.0）。
- 检测：主机出现 `--remote-debugging-port` 启动参数、9222/9229 端口监听、异常进程连接本机调试端口；DevTools 自动化会伴随大量 CDP 方法调用与页面控制行为。
- 防御：仅在本机受控环境启用；用临时 user-data-dir 隔离；对敏感页面禁用远程调试；监控 chrome://inspect 的使用。
