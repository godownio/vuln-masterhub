---
id: web-generic-clickjacking-transparent-iframe-ui-redress
title: 点击劫持：透明 iframe 覆盖目标页面诱导用户点击执行敏感操作
type: scenario
domain: web
path: web/generic/clickjacking
technique: clickjacking-ui-redress
tags:
- web
- clickjacking
- ui-redress
- iframe
- x-frame-options
- csp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:50:27+08:00'
  notes: 已对照原文与图01核对：iframe+CSS opacity覆盖、诱导点击、X-Frame-Options/CSP frame-ancestors防御均一致；原文为概念与demo，未复跑。路径web/generic/clickjacking已存在且path-check=exists。
url: /docs/web/generic/clickjacking/web-generic-clickjacking-transparent-iframe-ui-redress/
draft: false
kb_aliases:
- ClickJacking
- UI Redress
- 点击劫持
- 透明 iframe 覆盖
- 界面伪装攻击
- iframe overlay
---

## 一句话结论

目标页面没有禁止被其他站点框架嵌入时，攻击者用 iframe 把目标页叠在恶意页面上，并通过 CSS 把 iframe 透明度降到接近 0、精确对齐目标按钮，受害者以为在点诱饵按钮，实际点击事件落入目标页，以已登录身份完成删除、转账、授权等敏感操作。

## 原理

- iframe 允许跨域嵌入任意页面；是否允许由目标响应头决定。若既无 `X-Frame-Options` 也无 CSP `frame-ancestors`，浏览器不会阻止恶意站点嵌入目标页。
- 同源策略限制的是脚本读取 iframe 内容，不限制用户输入事件落入 iframe。iframe 内的元素照样参与命中测试（hit testing），鼠标点击会直接派发给 iframe 文档中对应坐标的元素。
- CSS `opacity: 0.001`（或 `opacity: 0` 配合裁剪、负边距、缩放）可以让目标页不可见但保持可交互；`position: fixed/absolute`、`z-index`、`width/height` 用来把目标页面中的敏感按钮精确移动到诱饵按钮下方。
- 因为触发的是真实用户点击，CSRF Token、Origin/Referer 校验都照常通过，点击劫持常被用来绕过只防自动提交的 CSRF 防御。
- 目标站点若只用 JavaScript frame-busting（如 `top !== self` 时跳转），攻击者可用 `<iframe sandbox="allow-forms allow-scripts">` 让 frame-busting 脚本失效；`X-Frame-Options`/`frame-ancestors` 是浏览器层强制，sandbox 无法绕过。

## 触发条件

- 目标敏感操作页面可被跨站 iframe 嵌入（无 `X-Frame-Options`，或 CSP 未设置 `frame-ancestors`，或允许了攻击者来源）。
- 受害者已登录目标站点，且目标操作只需一次点击即可完成，没有二次确认、密码重输或独立弹窗。
- 攻击者能把诱饵页面投递给受害者（钓鱼链接、恶意广告、第三方页面等）。
- 目标操作对应的按钮/链接位置可预测，或攻击者能通过页面布局差异反复调整对齐。

## 利用步骤

1. 抓取目标操作页响应头，确认没有 `X-Frame-Options: DENY/SAMEORIGIN` 与 `Content-Security-Policy: frame-ancestors` 限制。
2. 在恶意页中放一个全屏 iframe 指向目标操作页，用 CSS 设置 `opacity: 0.001`、固定定位、宽高铺满，并置于最上层。
3. 在 iframe 下方放一个诱导性按钮（“领取奖励”“继续”等），通过调整 iframe 的 `top/left` 或 `transform: translate()` 使目标页的敏感按钮与诱饵按钮重合。
4. 诱导受害者点击；点击坐标命中 iframe 内的目标按钮，请求以受害者会话发出。
5. 可结合鼠标跟随（cursorjacking）或多步点击，把多个操作串起来。

## PoC

最小透明覆盖页面：

```html
<style>
  #decoy {
    position: fixed; left: 40px; top: 300px;
    width: 240px; height: 48px; z-index: 1;
  }
  #target {
    position: fixed; left: 0; top: 0;
    width: 100vw; height: 100vh;
    border: 0; opacity: 0.001; z-index: 2;
  }
</style>
<button id="decoy">点击领取奖励</button>
<iframe id="target" src="https://victim.example/account/delete"></iframe>
```

说明：示例中假设目标页的“确认删除”按钮位于页面坐标约 (40, 300)；实际利用时按目标页面布局调整偏移与尺寸，使两个按钮重合。也可把 iframe 缩小后用 `transform: scale()` 放大，减少对齐难度。

用于压制 JS frame-busting 的变体：

```html
<iframe sandbox="allow-forms allow-scripts" src="https://victim.example/account/delete"></iframe>
```

## 变体与关联

- 变体：cursorjacking，让目标页跟随受害者鼠标移动，使任意位置的点击都落在目标按钮上。
- 变体：double-clickjacking，诱导用户双击，第一次点击用于把诱饵切换到敏感按钮，第二次完成操作。
- 变体：likejacking/表单劫持，把 iframe 覆盖在点赞、关注、发帖、OAuth 授权、文件上传等操作上。
- 变体：用 `sandbox` 去掉 `allow-top-navigation` 等权限，压制基于 `top.location` 的 frame-busting。
- 关联：[[web-generic-csrf-missing-token-state-changing-endpoint]]（点击劫持绕过 CSRF Token，因为请求由真实点击触发）。
- 边界：目标设置 `X-Frame-Options: DENY` 或 CSP `frame-ancestors 'none'` 时，现代浏览器直接拒绝加载，该手法不成立；敏感操作有二次确认或需重输密码时，单次点击不足以完成利用。

## 检测与防御

- 检测：页面被异常来源框架化时，服务端可见 `Sec-Fetch-Dest: iframe` 与 `Sec-Fetch-Site: cross-site`；可记录 CSP `frame-ancestors` 违规报告；前端可检测 `window.top !== window.self`，但仅作为辅助信号。
- 防御：对不允许被嵌入的页面返回 `X-Frame-Options: DENY`（或 `SAMEORIGIN`），并同时设置 `Content-Security-Policy: frame-ancestors 'none'`（或 `'self'`/明确白名单）。`X-Frame-Options: ALLOW-FROM` 已被多数现代浏览器废弃，白名单应使用 CSP `frame-ancestors`。
- 加固：对删除、转账、授权、改密等敏感操作增加二次确认、重认证或短时 Token；不要仅依赖 JavaScript frame-busting；对 `Sec-Fetch-Site: cross-site` 的框架化请求直接拒绝。
