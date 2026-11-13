---
id: mobile-android-uniapp-traffic-capture-okhttp-hook-encryption-locate
title: uni-app 应用抓包：WWW 资源识别框架，Frida Hook OkHttp RequestBody/RealCall 打印明文报文，JS 侧定位 app-config/app-service 加密或 Chrome USB 调试 H5
type: scenario
domain: mobile
path: mobile/android
technique: uniapp-traffic-capture-okhttp-hook-js-encryption-locate
tags:
- android
- uniapp
- frida
- okhttp
- traffic-capture
- hook
- encryption
- reverse
- mobile
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V671
  verified_at: '2026-11-13T10:19:47+08:00'
  notes: 已对照原文与6图核对：WWW 目录（assets/apps/__UNI__71C411E/www，含 app-config.js/app-config-service.js/app-service.js/app-view.js/manifest.json）、Frida RequestBody.create 脚本与输出 {"data":"bwmZtecx..."}、jadx p473dc.squareup.okhttp3 包、uni.request sslVerify 文档（App安卓/HBuilderX 2.3.3+/不支持离线打包）、chrome://inspect 调试 __uniappview/__uniappservice/login 均一致；已将'jadx 中类名为 dc.squareup.okhttp3'修正为脚本类名与该截图混淆前缀并存。原文未标受影响版本；未连接设备执行 Frida
url: /docs/mobile/android/mobile-android-uniapp-traffic-capture-okhttp-hook-encryption-locate/
draft: false
kb_aliases:
- uni-app 抓包
- uni-app 加密定位
- Frida hook OkHttp RequestBody
- RealCall.getResponseWithInterceptorChain
- __UNI__ www app-service.js
- uni.request sslVerify
- Chrome USB 调试 uni-app H5
---

## 一句话结论

面对 proxy 抓不到包或流量被加密的 Android uni-app 应用，可先从 APK 的 `assets/apps/__UNI__*/www/`（含 `app-config.js`/`app-service.js`/`app-view.js`/`manifest.json`）确认 uni-app 框架；再用 Frida 绕过 SSL Pinning，转而 Hook OkHttp 的 `RequestBody.create(MediaType, String)` 或 `RealCall.getResponseWithInterceptorChain` 直接打印请求/响应明文；加密逻辑按文章经验去 `app-config.js`/`app-server.js` 等 JS 中定位，或把页面当 H5 用 Chrome USB 远程调试。

## 原理

- **uni-app 的运行结构**：uni-app 用 Vue.js 写一套代码发布到 App/H5/小程序；App 侧业务 JS 直接调用 Android/iOS 原生 API（HTML5Plus/nvue、native.js、uni SDK），所以真正的网络请求最终落在原生网络库（Android 常见 OkHttp）。判断依据是 APK 资源里的 `assets/apps/__UNI__<ID>/www/` 目录与 `app-config.js`、`app-service.js`、`app-view.js`、`manifest.json` 等文件（文章案例截图）。
- **为什么 Hook 网络库**：代理抓包依赖客户端信任代理 CA；当应用做了 SSL Pinning、代理检测或流量在 JS/native 层另行加密时，Charles/Postern 可能完全抓不到。此时把观测点下移到 OkHttp 调用层，绕过 TLS 与代理问题，直接拿到"即将发出/已经收到"的对象。
- **OkHttp 关键 Hook 点**：同步/异步请求最终都会走到 `RealCall`（`OkHttpClient.newCall(Request)` → `RealCall.newRealCall`，异步 `enqueue` 最终也回到 `execute`）。文章建议 Hook `RealCall.getResponseWithInterceptorChain`：通过反射取 `originalRequest` 得到 `Request`，并从返回值取 `Response`，从而打印请求与响应报文。
- **RequestBody Hook（文章案例）**：目标应用使用被重打包的 OkHttp，文章 Frida 脚本按 `dc.squareup.okhttp3.RequestBody` 类名 Hook（jadx 截图中该包显示为带混淆前缀的 `p473dc.squareup.okhttp3`），Hook `RequestBody.create(MediaType, String)` 即可打印出每次请求的字符串 body；案例输出即为一段加密后的 `{"data":"bwmZtecx..."}`，证明该点能看到最终发出的内容。类名前缀可能被改（如 `okhttp3` → `dc.squareup.okhttp3`、`p473dc.squareup.okhttp3`），需按目标包内实际类名替换。
- **加密位置的定位**：文章指出按 MVC 习惯，数据加密方法一般在 `app-config.js` 或 `app-server.js` 中；对 uni-app 打包目录，应重点看 `app-service.js`（逻辑层业务代码）与 `app-config.js`。若 JS 混淆严重，可把 uni-app 页面当 H5 调试：`adb` 连接设备后用 Chrome `chrome://inspect` 调试 WebView（案例调试的是 `file:///android_asset/apps/__UNI__.../__uniappview.html`、`__uniappservice.html`、`login.html`），在 Sources/Network 中直接观察 JS 加密前后的数据。
- **框架自身的校验开关**：uni-app 的 `uni.request` 支持 `sslVerify` 参数控制是否校验 SSL 证书（文档标注仅 App 安卓支持、HBuilderX 2.3.3+、离线打包不支持）。这是应用侧开关：若能改 JS 包（重打包/动态注入）把它置为 false，可省去 Frida Pinning 绕过；否则按常规 Frida Hook 方案处理。
- **为什么成立**：hook 发生在业务与网络库之间，处于加密完成之后、TLS 之前（请求）或 TLS 之后、业务解密之前（响应），因此既不受代理证书问题影响，也能拿到 JS/native 处理后的真实报文；再结合 JS 侧加密函数即可还原明文协议。

## 触发条件

- 目标为 Android 应用且确认使用 uni-app（资源目录 `assets/apps/__UNI__*/www`）。
- 设备已 Root/可运行 Frida Server，或应用可调试/可重打包。
- 目标使用 OkHttp（含 Retrofit）或可定位到等价网络库；应用未启用强反调试/RASP，或已被绕过。
- 需要打印响应时，Hook 点需能取到 `Response`（`getResponseWithInterceptorChain`）或拦截器链。

## 利用步骤

1. 解包 APK 或 jadx 查看 `assets/apps/__UNI__*/www/`，确认 uni-app 及 JS 文件清单（`app-config.js`、`app-service.js`、`app-view.js`、`manifest.json`）。
2. 若代理抓不到包：先按 SSL Pinning 绕过思路处理（见关联卡），或直接进入第 3 步 Hook 网络库。
3. Frida 附加目标进程，按实际类名 Hook `RequestBody.create(MediaType, String)` 打印请求 body；需要响应时 Hook `RealCall.getResponseWithInterceptorChain`，反射 `originalRequest` 取请求、从返回值取 `Response` 打印。
4. 发送一次业务请求，观察 Frida 输出（案例得到 `{"data":"bwmZtecx..."}` 形式的加密 body）。
5. 到 `app-config.js`/`app-service.js`（文章写作 `app-config.js`/`app-server.js`）中搜索加密函数、密钥与请求封装；或 `adb` 连接后用 Chrome `chrome://inspect` 调试 `__uniappview.html`/`__uniappservice.html`，在 JS 里动态断点观察加密前明文与加密后参数。
6. 还原加密/签名算法后可改包、重放或构造请求，进入业务漏洞测试。

## PoC

```javascript
// 文章案例：Hook 重打包后的 OkHttp RequestBody.create，打印请求 body（类名前缀按目标实际包名替换）
function main() {
  Java.perform(function () {
    var RequestBody = Java.use("dc.squareup.okhttp3.RequestBody");
    RequestBody["create"].overload('dc.squareup.okhttp3.MediaType', 'java.lang.String').implementation = function (mediaType, str) {
      console.log(str);
      var ret2 = this.create(mediaType, str);
      return ret2;
    };
  });
}
setImmediate(main);
```

```javascript
// 文章思路：Hook RealCall.getResponseWithInterceptorChain，打印请求与响应
Java.perform(function () {
  var RealCall = Java.use("okhttp3.RealCall"); // 重打包时换成实际类名
  RealCall.getResponseWithInterceptorChain.implementation = function () {
    var reqField = RealCall.class.getDeclaredField("originalRequest");
    reqField.setAccessible(true);
    console.log("[request] " + reqField.get(this).toString());
    var resp = this.getResponseWithInterceptorChain();
    console.log("[response] " + resp.toString());
    return resp;
  };
});
```

## 变体与关联

- 变体：不需要响应时只 Hook `RequestBody.create` 即可打印请求；需要请求头/签名时改 Hook `Request$Builder.addHeader`（见关联卡）。
- 变体：`uni.request` 的 `sslVerify=false`（App 安卓、HBuilderX 2.3.3+，离线打包不支持）可在可改 JS 包时关闭证书校验。
- 变体：加密定位除 JS 静态搜索外，可用 Chrome USB 调试 H5 视图（`__uniappview.html`/`__uniappservice.html`）动态观察。
- 关联：[[mobile-android-ssl-pinning-bypass-cert-frida]]（证书 Pinning 绕过）、[[mobile-android-okhttp-addheader-stack-native-sign-locate]]（OkHttp 请求头/签名定位）、[[mobile-miniprogram-charles-burp-upstream-proxy-capture]]（小程序抓包对照）、[[mobile-android-aes-random-key-hook-fixed-iv-decrypt]]（JS/native 加密算法 Hook 还原）。
- 边界：iOS uni-app、离线打包（sslVerify 不生效）、非 OkHttp 网络栈、强混淆/native 加密需换对应 Hook 点；文章为单案例验证。

## 检测与防御

- 检测（测试视角）：确认 `assets/apps/__UNI__*/www` 与 `app-service.js`/`app-config.js` 特征；运行时检查 Frida 特征与 OkHttp 方法 Hook（RASP）。
- 防御：不要把密钥/加密算法只放前端 JS（应服务端签发与校验）；启用 SSL Pinning 与代理/调试检测；对 `uni.request` 的 `sslVerify` 不依赖客户端设置，服务端强制双向 TLS 或应用层签名；加固/混淆 JS 与 native 网络层，检测 Frida/Root。
