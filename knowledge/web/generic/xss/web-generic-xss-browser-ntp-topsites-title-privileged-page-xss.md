---
id: web-generic-xss-browser-ntp-topsites-title-privileged-page-xss
title: 浏览器新标签页 top sites 标题未转义存储型 XSS：网页 <title> 的 HTML 进入高权限 NTP 上下文（chrome.* EoP）
type: scenario
domain: web
path: web/generic/xss
technique: browser-ntp-topsites-title-html-stored-xss-privileged-page
aliases:
- Edge NTP title XSS
- 新标签页 top sites XSS
- 网页标题 HTML 注入
- chrome.qbox.navigate 崩溃
- 浏览器内置页存储型 XSS
- Edge 79 XSS EoP
tags:
- xss
- browser
- edge
- ntp
- top-sites
- title-injection
- privileged-page
- eop
- client-side
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T13:48:55+08:00'
  notes: 已对照原文与全部15图核对；title HTML 注入与加粗渲染（02/03）、普通站chrome对象对比（04）一致；已把崩溃寄存器值订正为小端ASCII texture2；qbox.navigate崩溃仅DoS按规则未单独立卡，本卡仅作特权页EoP入口并如实注明未完成RCE；PoC未本机复跑
---

## 一句话结论

Edge（Chromium 内核）的新标签页 top sites 卡片把用户访问过的网页 `<title>` 直接当作 HTML 渲染且不转义：攻击者在自己的页面里写 `<title>test<b>a</b></title>`，用户访问后该标题进入新标签页 top sites，浏览器就把标签“渲染”出来；把 title 换成带 `<iframe onload=...>` 的注入即可在 NTP 这个高权限内置页执行任意 JS，从普通 Web 内容跨入可访问 `chrome.*` 特权 API 的上下文（EoP）。原文进一步在未文档化的 `chrome.qbox.navigate` 上找到了 native 层内存破坏（仅崩溃/DoS，未完成 RCE，不属本卡利用链）。

## 原理

- **不可信元数据进入可信 UI**：NTP 的 top sites 展示用户最常访问的站点，卡片标题取自各站点 HTML 的 `<title>`。测试页 `<title>test<b>a</b></title>` 在新标签页显示为加粗的 **a**，说明浏览器把 title 当作 HTML 拼接进内置页 DOM，而不是当作纯文本。
- **存储型、跨会话触发**：title 保存在浏览历史/top sites 数据里，用户访问攻击者页面后，不必停留在该页面；下一次打开新标签页时 payload 才执行。攻击者可通过恶意广告、论坛帖子、任意必须让受害者点开的链接投递。
- **为什么是 EoP**：NTP 是浏览器内置页，其 `chrome` 对象比普通网页多出大量特权成员（原文对比：普通站点只有 `chrome.app/csi/loadTimes` 等少量成员，而 `edge://settings` 这类内置页暴露 `chrome.autofillPrivate`、`chrome.ntpSettingsPrivate`、`chrome.passwordsPrivate`、`chrome.usersPrivate` 等）。因此 NTP 里的 XSS 等价于越权进入浏览器可信 UI 上下文，可调用普通网页无法触及的 API。
- **特权桥接的另一面**：原文在 NTP 中发现未文档化对象 `chrome.qbox`，其 `chrome.qbox.navigate({id,url})` 接受 JSON（最少 `id`、`url` 两个字段，类型 `qbox.NavigationItem`）。传入 `{id:999999,url:null}` 后 Edge 崩溃，故障转储显示 `msedge!ChromeMain+0x9253e` 执行 `mov rax,qword ptr [rdx]`，`rdx=0x3265727574786574`（小端解码为 ASCII "texture2"，原文未分析该值来源），崩溃点把该值当指针解引用，属于 native 内存破坏，但原文明确表示“只造成 Crash，RCE 是完全不同的范围”，故本卡只把 XSS 进入特权上下文记为 EoP 原语，崩溃链不展开。
- **与“NTP 接管”链的关系**：两者都是 NTP 高权限页 XSS；本卡入口是浏览历史中的站点标题（存储型、无需要子域 XSS/cookie），接管链入口是跨子域 cookie + 同源 localStorage 投毒（持久化）。两条链最终能力相同（`chrome.*` 特权 API），但触发条件与 PoC 不同。

## 触发条件

- 目标浏览器为存在该缺陷的 Edge Chromium 版本（原文测试版本 79.0.287.3 dev）。
- 攻击者能让受害者访问一个 `<title>` 内含 HTML/JS payload 的页面（任何 web 页面均可，不要求同域）。
- 该访问记录进入 NTP 的 top sites（可能需要多次访问/等待同步；默认 NTP 展示常访问站点）。
- 用户使用默认新标签页并允许远程 NTP 内容，未禁用 top sites。
- 仅验证到“在特权页执行 JS / 造成浏览器崩溃”；若要求实际 RCE 或令牌窃取，需要另找可用的 chrome API 或 native 利用。

## 利用步骤

1. 构造验证页：`<title>test<b>a</b></title>`，访问后打开新标签页，确认 top sites 卡片标题被渲染为 HTML（加粗）。
2. 构造注入页：在 `<title>` 中放入能在 NTP DOM 中执行的事件处理器，例如 `<title>test<iframe/src=1/ onload=chrome.qbox.navigate(...)></title>`；也可用 `<img src=x onerror=...>`、`<svg onload=...>` 等。
3. 投递链接让受害者访问（恶意广告/水坑/社工）；等待其出现在受害者 NTP top sites。
4. 受害者打开新标签页时，payload 在 `ntp.msn.com` 高权限页面执行；可在控制台/外带通道验证 `chrome.authPrivate`、`chrome.ntpSettingsPrivate` 等特权对象存在。
5. 若目标是验证内存破坏（DoS）：`chrome.qbox.navigate({id:999999,url:null})` 可使 Edge 崩溃（原文故障转储 `mov rax,[rdx]`、`rdx=0x3265727574786574`）；该结果不能作为 RCE 证据。

## PoC

原文 PoC（造成崩溃的版本，未在本机复跑）：

```html
<html>
<head>
<title>test<iframe/src=1/ onload=chrome.qbox.navigate(JSON.parse(unescape("%7B%22id%22%3A999999%2C%22url%22%3Anull%7D")))></title>
<body>
q
</body>
</html>
```

其中 `unescape` 后的参数为 `{"id":999999,"url":null}`。崩溃信息（原文）：

```text
msedge!ChromeMain+0x9253e:
mov rax,qword ptr [rdx]   ds:3265727574786574=????????????????
```

## 变体与关联

- **同源 NTP 持久接管链**：[[web-generic-xss-browser-ntp-cookie-localstorage-privileged-page-takeover]] 从 cookie 反射 + localStorage 投毒进入同一高权限页面，可窃取 `chrome.authPrivate` token；本卡是更简单的“浏览历史标题存储型 XSS”入口。
- **同类面**：任何把网页元数据（title、favicon、manifest name、OG 标签、下载文件名）渲染进浏览器内置 UI（新标签页、书签栏、历史页、扩展管理页）而未转义的地方，都可能构成从 Web 到内置页的 XSS/EoP；审计时把“浏览器 UI + 网页可控字符串”作为注入点。
- **后续利用**：原文的 `chrome.qbox.navigate` 崩溃证明 JS→native 的数据通路存在内存破坏，但未完成控制流劫持；若在其他内置页/桥接 API 上找到同样模式，可作为浏览器沙箱内 EoP 或 RCE 的起点（需另行验证）。

## 检测与防御

- **浏览器侧**：对 title、站点名、favicon 等网页元数据一律按纯文本渲染（`textContent`/转义），不要拼 HTML；NTP/top sites 等内置页施加严格 CSP（禁止内联事件处理器与 javascript: URL），并把远程内容与 `chrome.*` 特权绑定隔离到不同源。
- **功能策略**：企业环境可禁用 NTP 远程内容/新闻推送（策略模板），减少此类攻击面；浏览器及时更新修复版本。
- **检测**：检查浏览历史/top sites 数据中标题包含 `<`、`onload`、`onerror`、`javascript:` 等标记的可疑条目；监控 `msedge.exe` 在 NTP 页面触发时的异常崩溃（`ChromeMain+0x9253e` 一类签名）并排查是否伴随恶意标题。
