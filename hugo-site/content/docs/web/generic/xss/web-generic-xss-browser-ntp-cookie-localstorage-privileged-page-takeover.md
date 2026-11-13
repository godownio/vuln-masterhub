---
id: web-generic-xss-browser-ntp-cookie-localstorage-privileged-page-takeover
title: 浏览器新标签页（NTP）接管链：跨子域 cookie 注入 + 同源错误页 localStorage 投毒，持久控制高权限内置页并窃取账户令牌
type: scenario
domain: web
path: web/generic/xss
technique: browser-ntp-cookie-xss-localstorage-cache-poison-privileged-page-takeover
tags:
- xss
- browser
- edge
- ntph
- new-tab-page
- cookie
- localstorage
- cache-poisoning
- privileged-page
- eop
- token-theft
- client-side
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T13:48:53+08:00'
  notes: 已对照原文与全部15图核对（01 NTP远程页、02/03 title注入、04 chrome对象对比、05-07 qbox/authPrivate、08 版本79.0.287.3、10-15 WebNote/file链）；cookie反射+localStorage投毒与chrome.authPrivate利用与原文一致；原文未显式标注受影响版本区间，未设affected_versions；PoC未本机复跑
url: /docs/web/generic/xss/web-generic-xss-browser-ntp-cookie-localstorage-privileged-page-takeover/
draft: false
kb_aliases:
- Microsoft Edge NTP 接管
- 新标签页 XSS 提权
- ntp.msn.com domainId XSS
- localStorage 缓存投毒 XSS
- chrome.authPrivate token 泄露
- 浏览器内置页持久 XSS
- NTP takeover
---

## 一句话结论

浏览器的新标签页（NTP）本质上是一个远程网页（如 `ntp.msn.com`），却运行在高权限的内置页上下文里（可访问 `chrome.*` 特权 API）。当它存在“cookie 值被无转义反射进页面”的 XSS 时，攻击者可以先在任意 `msn.com` 子域上用一个低危 XSS 设置 `domain=.msn.com` 的 `domainId` cookie，把 payload 带进 NTP 的错误页；再利用错误页与正常 NTP **同源**，遍历并篡改 NTP 在 `localStorage` 中缓存的页面数据（`lastKnown*` 键），把恶意 `onload` 注入缓存 DOM。之后用户每次打开新标签页都会在 NTP 高权限页面执行攻击者 JS，可静默获取 Microsoft 账户 access token、邮箱/账户 ID，修改 NTP 设置与自定义站点，实现持久接管。

## 原理

- **NTP 是“特权网页”**：Edge（Chromium 内核）默认新标签页加载 `https://ntp.msn.com/edge/ntp?...`，它是远程站点，却运行在与 `edge://settings` 类似的浏览器内置页环境，`chrome` 对象上暴露 `chrome.authPrivate`、`chrome.ntpSettingsPrivate`、`chrome.embeddedSearch`、`chrome.qbox` 等普通网页没有的特权 API。远程内容与高权限绑定同处一个上下文，是整条链的价值前提。
- **跨子域 cookie 注入**：cookie 的 `domain=.msn.com` 作用域意味着**任意** `*.msn.com` 子域上的 XSS 都能为 `ntp.msn.com` 设置 cookie。原文在 `technology.za.msn.com` 的老旧 `pebble.asp` 错误页找到反射 XSS（POST `startnum=90'<b>xss</b>` 被原样回显、无 `X-Frame-Options`），仅用它执行 `document.cookie="domainId=<payload>;domain=.msn.com;path=/"`。
- **NTP 错误页反射 cookie**：存在一个降级/错误 NTP 页面（原文 `ntp.msn.com/compass/antp?locale=qab&dsp=1&sp=qabzz`），当请求带 `domainId` cookie 时会把其值渲染进页面的 `<script>` 区域，且没有引号/转义过滤，攻击者可以在 cookie 值里闭合上下文并注入 JS。该错误页响应约 42 秒后返回，可放进隐藏 iframe 静默触发。
- **同源 localStorage 缓存投毒（持久化关键）**：正常 NTP 页面把渲染所需数据缓存在 `localStorage`（`lastKnown*` 等键），错误页与正常页同属 `ntp.msn.com`，可直接读取/改写这些键。注入的 JS 遍历 `localStorage`，对 `lastKnown*` 做 `JSON.parse`，在 `dom` 字段前拼接 `<SvG/OnLoAd=...>` 恶意 HTML 后写回；正常 NTP 从 localStorage 恢复页面时执行该 onload 代码，于是攻击者 JS 在**每次打开新标签页**时自动执行，不再依赖初始 XSS 页面。
- **权限提升的危害**：在 NTP 上下文可调用：
  - `chrome.authPrivate.acquireAccessTokenSilently` —— 静默获取用户 Microsoft 账户 access token；
  - `chrome.authPrivate.getPrimaryAccountInfo(e=>{console.dir(e)})` —— 读取账户 email、account id 等身份信息；
  - `chrome.embeddedSearch.newTabPage.updateCustomLink(i, url, url)` —— 篡改新标签页自定义站点（可指向钓鱼站）；
  - `chrome.ntpSettingsPrivate.setPref` —— 修改 NTP 设置；
  - 持续跟踪用户行为、伪造 MSN 内容、注入恶意广告（类似恶意扩展的持久化能力）。
- **为什么成立**：特权页面信任“同源”数据，把 localStorage 当作可信缓存；把用户可控 cookie 直接拼进脚本上下文；cookie 的域作用域让任意子域 XSS 都能污染主站 cookie；三者叠加使低危子域 XSS 升级为持久化高权限页面接管。

## 触发条件

- 目标浏览器（原文为 2019 年 Edge Chromium，版本示例 79.0.287.3 dev）的 NTP 使用远程站点且暴露 `chrome.*` 特权 API。
- `ntp.msn.com` 存在把 `domainId` cookie 无转义反射进页面的降级页，且该页与正常 NTP 同源。
- 任意 `*.msn.com` 子域存在可执行 JS 的 XSS（用于设置跨域 cookie），且目标 NTP 错误页允许被 iframe 嵌入（无 `X-Frame-Options`）。
- 受害者使用默认新标签页、未禁用 NTP 远程内容或相关功能。
- 攻击者页面可等待约 42 秒的错误页加载（隐藏 iframe，用户无感）。

## 利用步骤

1. **找子域 XSS**：在任意 `msn.com` 子域找反射/存储 XSS（原文为 `technology.za.msn.com/pebble.asp` 的 `startnum` 参数），只要能执行 JS 即可。
2. **设置跨域 cookie**：在该子域执行 `document.cookie = "domainId=" + payload + ";expires=...;domain=.msn.com;path=/"`，payload 为注入到 NTP 错误页 `<script>` 上下文中的代码。
3. **加载错误页**：用隐藏 iframe 请求 `ntp.msn.com/compass/antp?locale=qab&dsp=1&sp=qabzz`；cookie 被反射，payload 在 `ntp.msn.com` 源执行。
4. **投毒 localStorage**：payload 遍历 `localStorage` 的 `lastKnown*` 键，把 `<SvG/OnLoAd=...>` 之类的事件处理器拼进缓存 DOM 的 `dom` 字段并写回。
5. **等待持久化触发**：用户打开新标签页，正常 NTP 从 localStorage 恢复被污染的数据并执行 onload 代码，攻击者 JS 在 NTP 高权限上下文运行，此后每次开新标签页都会触发。
6. **收割**：调用 `chrome.authPrivate.acquireAccessTokenSilently` / `getPrimaryAccountInfo` 窃取 token 与账户信息，或用 `chrome.ntpSettingsPrivate.setPref`、`chrome.embeddedSearch.newTabPage.updateCustomLink` 修改设置/植入钓鱼站点。

## PoC

原文攻击页骨架（编码后的完整 payload 较长，这里给最小结构；未在本机复跑）：

```html
<iframe src="about:blank" id="qframe" name="msn" style="opacity:0.001"></iframe>
<form id="qform" target="msn" action="http://technology.za.msn.com/pebble.asp?relid=172" method="post">
  <input type="hidden" name="startnum"
         value="90'<SvG/onLoAd=eval(unescape('...'))>">
</form>
<script>
qframe.onload = e => setTimeout(() => {
  location = "https://ntp.msn.com/compass/antp?locale=qab&dsp=1&sp=qabzz";
}, 1000);
qform.submit();   // 子域 XSS 设置 domainId cookie（.msn.com）
</script>
```

在 `technology.za.msn.com` 执行的 cookie 设置（解码后核心）：

```javascript
document.cookie = "domainId=" +
  'q"*' +
  encodeURIComponent(function () {
    for (q in localStorage) {
      if (q.indexOf('lastKnown') > -1) {
        qntpobj = JSON.parse(localStorage[q]);
        qntpobj.dom = "<SvG/OnLoAd='document.write(/@qab/.source)'>" + qntpobj.dom;
        localStorage[q] = JSON.stringify(qntpobj);
      }
    }
  }()) +
  '*"q' +
  ";expires=" + qd + ";domain=.msn.com;path=/";
```

说明：`domainId` 值先被 NTP 错误页反射进脚本上下文执行（闭合引号的 `q"* ... *"q` 包装），再把恶意 onload 写进同源 localStorage，由正常 NTP 页面恢复时执行。

## 变体与关联

- **另一条 NTP 入口（top sites 标题 XSS）**：同一高权限 NTP 页面还可被“浏览过的网页 `<title>` 未转义渲染为 top sites 卡片”注入（见 [[web-generic-xss-browser-ntp-topsites-title-privileged-page-xss]]）；两条链最终都落在 NTP 的 `chrome.*` 特权上下文，但入口与持久化方式不同。
- **缓存投毒类**：[[web-generic-cache-poisoning-chromium-cn-cache-key-xss]] 是服务端/浏览器缓存键问题导致顶层文档 XSS，本卡是客户端 localStorage 投毒持久化，二者机制不同。
- **同源策略弱点的推广**：任何“高权限内置页 + 远程内容 + 同源缓存/存储”的组合（浏览器 NTP、设置页、扩展页面、桌面客户端 WebView 内置页）都可能复制该链；关键是找到低权限源到高权限源的 cookie/存储注入点。
- **前提限制**：需要目标站点存在错误页反射与子域 XSS；NTP 版本更新或 cookie 转义/CSP 修复后失效。原文利用的是具体 MSN/Edge 实现。

## 检测与防御

- **浏览器侧**：内置页不要加载远程内容，或把远程内容放进无 `chrome.*` 绑定的隔离源；对 NTP 等特权页面施加严格 CSP，禁止内联脚本与事件处理器；不要把 cookie 值直接拼进 HTML/JS，必须按上下文编码。
- **站点侧**：对 `domainId` 等 cookie 输出做 HTML/JS 上下文转义；错误页同样执行模板转义，不因“异常路径”放松；设置 `X-Frame-Options`/CSP `frame-ancestors` 防止隐藏 iframe 触发；限制 cookie 的 `Domain` 作用范围，敏感 cookie 不设宽域。
- **持久化面**：把 localStorage 中的缓存数据视为不可信输入，渲染前重新编码/校验；NTP 缓存增加完整性校验（如签名/版本）。
- **检测**：监控 `*.msn.com` 子域上设置 `domainId` 的可疑请求与 42 秒延迟的错误页请求；检测 NTP 页面 localStorage `lastKnown*` 中注入的 `<SvG`/`onload` 等异常标记；对浏览器内置页控制台出现的 `chrome.authPrivate` 调用做审计（企业环境）。
