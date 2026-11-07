---
id: web-generic-xs-leaks-cache-probing
title: XS-Leaks 缓存探测：用缓存命中与加载时间判断跨站状态相关资源
type: scenario
domain: web
path: web/generic/xs-leaks
technique: xs-leaks-cache-probing
aliases:
- cache probing
- 缓存探测
- 缓存命中侧信道
- cache and error events
- 缓存分区绕过
- history.replaceState 长 Referer
tags:
- web
- xs-leaks
- side-channel
- cache
- cache-partitioning
- timing
- onerror
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:52:17+08:00'
  notes: 已对照原文核对：history.replaceState超长URL、fetch cache:'reload'清缓存、img onload/onerror判断缓存命中、cache partitioning按site分区、4xx/5xx清缓存均一致；未复跑。dup-scan均为related，保留。
---

## 一句话结论

浏览器缓存默认按资源 URL 共享且命中缓存时不发网络请求；攻击页先让目标页面在某种状态下加载某资源（如登录后才出现的 `welcome.png`），再在自己的页面加载同一 URL，通过加载时间明显变短或“本应失败的请求却成功加载”判断缓存命中，从而推断受害者在目标站的状态或数据。

## 原理

- 缓存命中时浏览器直接从本地缓存读取，不发起网络请求，因此加载时间显著短于未命中；当网络本身很快、时间差不够稳定时，可以用错误事件放大差异。
- 文章给出的放大方法：先用 `history.replaceState(1, 1, Array(16e3))` 把当前页面 URL 替换成超长字符串，使后续请求的 `Referer` 头过长；再请求目标资源。若资源未命中缓存，浏览器会带上超长 Referer 发请求，服务器/WAF 返回 4xx 或连接被拒，`<img>` 触发 `onerror`；若资源命中缓存，浏览器根本不发请求，直接解码缓存图片并触发 `onload`。
- 目标页只有在特定状态下才会加载某张图片/脚本/样式，攻击者先让目标页在该状态加载一次，把资源写入缓存；再用上述 oracle 检查该资源是否在缓存中，即可还原状态位。
- 缓存键在未分区时就是资源 URL；Chrome 的 cache partitioning 把键扩展为 `(top-level site, current-frame site, resource URL)`。注意其中的 site 是 eTLD+1，不是 origin：攻击者若在 `https://test.huli.tw` 发起，目标资源属于 `https://app.huli.tw`，二者同 site（`huli.tw`），分区键一致，仍可命中；若攻击者在 `http://localhost:5555`，则跨 site，无法共享缓存。
- 文章还提到：已缓存所有资源后，可以用 4xx/5xx 响应或 WAF 报错让浏览器删除/失效缓存，便于重复执行探测（该描述较简略，具体失效行为依浏览器与缓存策略而定）。

## 触发条件

- 目标页面在某种状态下会加载一个可缓存的资源（图片/脚本/样式），且该资源 URL 可被攻击者预测并在自己页面加载。
- 资源响应允许缓存（没有 `Cache-Control: no-store`，未被 `Vary` 等条件隔离），且跨站加载不被 `Cross-Origin-Resource-Policy` 阻止。
- 缓存是共享的，或攻击者与目标处于同一 site 以适配 cache partitioning；攻击页能先诱导受害者打开目标页完成缓存填充。
- 跨站请求能携带目标 Cookie（若资源本身需要鉴权），即 Cookie 未设置 `SameSite=Lax/Strict` 或为 `SameSite=None`；若资源是公开的静态图片，则不需要 Cookie。
- 攻击页可执行脚本并能修改自己的 URL（`history.replaceState`）以构造超长 Referer。

## 利用步骤

1. 确定目标在状态 A 下会加载、状态 B 下不会加载的资源 URL（如登录后的 `welcome.png`）。
2. 清除缓存：在攻击页把 URL 替换为超长字符串（`history.replaceState(1,1,Array(16e3))`），并用 `fetch(url, {cache: 'reload', mode: 'no-cors'})` 强制从网络重新取一次该资源，确保缓存状态可控。
3. 诱导受害者在状态 A 下打开目标页，让目标页把该资源写入缓存。
4. 回到攻击页，保持超长 Referer，创建 `<img>` 加载同一个资源 URL：
   - 缓存命中：不发请求，图片解码成功，触发 `onload`；
   - 未命中：发请求时 Referer 过长导致服务器报错，触发 `onerror`。
5. 把 `onload/onerror` 映射为状态位并回传；对多个资源或多个状态重复探测。

## PoC

清除缓存：

```javascript
// 代码思路来自 xsleaks wiki 的 Cache and Error Events
let url = 'https://app.huli.tw/found.png';

// 把当前页面 URL 换成超长字符串，让后续请求 Referer 过大
history.replaceState(1, 1, Array(16e3));

// 绕过缓存强制从网络获取，重置该资源的缓存状态
await fetch(url, { cache: 'reload', mode: 'no-cors' });
```

缓存探测：

```javascript
let url = 'https://app.huli.tw/found.png';

history.replaceState(1, 1, Array(16e3));
let img = new Image();
img.src = url;
try {
  await new Promise((resolve, reject) => { img.onerror = reject; img.onload = resolve; });
  alert('Resource was cached');     // 命中缓存：未发请求，正常解码
} catch (e) {
  alert('Resource was not cached'); // 未命中：超长 Referer 导致请求失败
}
```

## 变体与关联

- 变体：不使用 error 事件，直接用 `performance`/时间差判断缓存命中；适合网络较慢或资源较大的场景。
- 变体：把 `<img>` 换成 `<script>`、`<link rel=stylesheet>` 等可缓存资源，观察对应 `load/error`。
- 变体：利用同一 site 下的子域（如 `test.huli.tw` 与 `app.huli.tw`）绕过 cache partitioning 的 site 边界。
- 变体：用不同查询参数、不同路径的资源区分更多状态位。
- 关联：[[web-generic-xs-leaks-img-onload-onerror-login-detect]]（用重定向终点是否为图片判断登录态，不依赖缓存）。
- 关联：[[web-generic-xs-leaks-script-onload-status-code-oracle]]（用状态码差异判断状态）。
- 边界：`Cache-Control: no-store`、资源 URL 随机化、`Cross-Origin-Resource-Policy: same-origin`、跨 site 的 cache partitioning、SameSite Cookie（对需鉴权资源）都会使该手法失效或受限。

## 检测与防御

- 检测：同一静态资源在短时间内被多个跨站来源加载；请求伴随超长 `Referer`；目标页被打开后立刻出现对状态相关资源的再次请求。
- 防御：对状态相关资源返回 `Cache-Control: no-store`；对敏感资源设置 `Cross-Origin-Resource-Policy: same-origin`；Cookie 使用 `SameSite=Lax/Strict`。
- 加固：避免用“是否加载某资源”表达业务状态；资源 URL 加入不可预测的一次性参数；利用 Fetch Metadata 拒绝跨站子资源请求；CDN/网关对异常超长 Referer 统一处理，避免形成明显 onload/onerror 差异。
