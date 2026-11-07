---
id: mobile-android-frida-local-http-uri-check-recover
title: Frida 还原 APK 本地 HTTP 二阶段校验：精确 URI 与尾部 0x0a
type: scenario
domain: mobile
path: mobile/android
technique: frida-local-http-uri-check-recover
tags:
- mobile
- android
- frida
- hook
- http
- uri
- ctf
- dynamic-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:30:35+08:00'
  notes: 已对照原文与图47-51核对：getVer=4.56.23、getApkHash=983f8a605d16530190c09b0884d7cef1、readFileFromAssets(version.txt)=K0pQvBZ38ykL26OzfshqYTHC2f7RUJYIgrmIF6GcORU=、ts原始串1727899789\n、hex末字节0a、len=11、URI模板与Host startsWith localhost均一致；无CVE、无sources/source_url；未对真实APK执行hook。
url: /docs/mobile/android/mobile-android-frida-local-http-uri-check-recover/
draft: false
kb_aliases:
- Frida hook getVer
- 本地 HTTP 校验
- SecondActivity 入口
- 尾部换行 %0A
- APK 二阶段入口还原
---

## 一句话结论

当 APK 用一个本地 HTTP 服务作为进入第二界面的门禁时，可以用 Frida hook 应用自身的静态方法，直接打印它参与校验的 `path/hash/ver/ts` 返回值，再按 `String.format("/%s?hash=%s&ver=%s&ts=%s")` 拼出精确 URI；本例的 `ts` 末尾带一个换行符 `0x0a`，请求时必须写成 `%0A` 才能通过字符串相等比较。

## 原理

- 应用在 `MainActivity` 内启动本地 HTTP 服务（NanoHTTPD 风格，端口 60723），请求处理逻辑大致是：
  - 若 `Host` 头不以 `localhost` 开头，返回 `error`；
  - 否则把 `Uri.decode(request.getUri())` 与 `String.format("/%s?hash=%s&ver=%s&ts=%s", path, apkHash, getVer(), ts)` 做完整字符串相等比较；
  - 相等则 `startActivity(SecondActivity)`，否则返回 `error`。
- 参与比较的值来自应用自身：
  - `path`：`readFileFromAssets(ctx, "version.txt")` 的返回值（案例 `K0pQvBZ38ykL26OzfshqYTHC2f7RUJYIgrmIF6GcORU=`）；
  - `apkHash`：`getApkHash(ctx)`（案例 `983f8a605d16530190c09b0884d7cef1`）；
  - `ver`：`getVer()`（案例 `4.56.23`）；
  - `ts`：时间戳字符串（案例 `1727899789\n`，长度 11，最后字节 `0a`）。
- 为什么容易卡住：如果只按日志/静态分析拼出 `ts=1727899789`，URI 与期望值差一个换行符，字符串相等判断失败，界面不会跳转；`Uri.decode` 会把 `%0A` 还原成 `\n`，所以请求侧应发送 `%0A`。
- Frida 的价值：这些方法可能被加固（案例有 QVM 保护），直接静态读字符串不一定可靠；hook 返回值或主动调用可以拿到运行时真实值，并观察 `ts` 的十六进制，避免漏掉不可见字符。

## 触发条件

- APK 启动本地 HTTP 服务，第二界面由请求 URI 的精确匹配触发。
- 校验参数由应用内方法生成，且方法可在 Frida 中调用或 hook。
- 请求需要满足额外的 Host/Header 条件（案例为 `Host` 以 `localhost` 开头）。
- 参数中可能包含换行、空格、URL 特殊字符等需要编码的不可见字符。

## 利用步骤

1. 反编译 APK，定位本地 HTTP 服务的端口、Handler 与跳转条件；记录 `String.format` 的模板与各参数来源。
2. 写 Frida 脚本 hook 参与校验的方法（如 `getVer`、`getApkHash`、`readFileFromAssets`），打印返回值；对关键字符串同时打印 hex 和长度。
3. 主动调用静态方法补齐未触发的方法返回值；确认 `path/apkHash/ver/ts` 的运行时值。
4. 检查 `ts` 等字符串的尾部字节：案例 `31 37 32 37 38 39 39 37 38 39 0a`，长度 11，末尾 `0a`。
5. 按模板拼 URI，对 `\n` 做百分号编码（`%0A`），必要时对 `=`、`?`、`&` 保持原样；用 `curl` 或本地 HTTP 客户端请求。
6. 观察响应与界面跳转；若失败，逐项对比 `Uri.decode` 后的完整字符串，尤其检查尾部不可见字符与 Host 头。

## PoC

```javascript
// hook.js
Java.perform(function () {
    var Main = Java.use('net.net.MainActivity');

    Main.getVer.implementation = function () {
        var ret = this.getVer();
        console.log('[getVer] =>', ret);
        return ret;
    };
    Main.getApkHash.implementation = function (ctx) {
        var ret = this.getApkHash(ctx);
        console.log('[apkHash] =>', ret);
        return ret;
    };
    Main.readFileFromAssets.implementation = function (ctx, name) {
        var ret = this.readFileFromAssets(ctx, name);
        console.log('[asset]', name, '=>', ret);
        return ret;
    };
    // 主动调用一次，便于在脚本加载后立即看到值
    try { console.log('[direct getVer] =>', Main.getVer()); } catch (e) {}
});
```

```bash
frida -U -f net.net -l hook.js
# 观察 ts 原始值与 hex 后，构造请求：
curl "localhost:60723/K0pQvBZ38ykL26OzfshqYTHC2f7RUJYIgrmIF6GcORU=?hash=983f8a605d16530190c09b0884d7cef1&ver=4.56.23&ts=1727899789%0A"
```

案例中该请求成功进入 SecondActivity。本卡不针对真实应用执行。

## 变体与关联

- 校验可能是前缀/包含匹配、正则、HMAC 或 native 方法；先用 Frida 打印真实输入输出，再决定是否需要逆算法。
- 不可见字符可能是 `\n`、`\r\n`、空格、NUL；统一打印 hex 与长度。
- 本地服务可能绑定 `127.0.0.1` 或仅监听应用内；需要 `adb forward` 或直接在设备上请求。
- `Host` 使用 `startsWith("localhost")` 是弱校验，但案例只需访问本地服务；若服务暴露到局域网，可进一步研究 Host 绕过。
- 关联：[[mobile-android-ssl-pinning-bypass-cert-frida]]（Frida hook 通用方法）、[[ctf-reverse-android-multicomponent-fragment-chain-native-verify]]（Android 多阶段入口）、[[ctf-reverse-java-string-hash-8digit-bruteforce]]（同一 APK 第二阶段的 8 位授权码爆破）。
- 边界：若方法被 anti-Frida 保护或返回值由服务端下发，需要先绕过检测或抓包；若 URI 比较使用 native 实现，hook Java 层可能看不到真实值。

## 检测与防御

- 开发侧：不要用本地 HTTP 精确 URI 作为唯一门禁；使用服务端签名/短期 token；对入口参数做结构化校验而不是整串相等。
- 加固侧：对关键方法做反调试/反 hook；校验参数不要以可预测的明文形式存在 assets。
- 检测：监控应用启动本地监听端口、Frida server、异常 `curl`/本地 HTTP 请求；对 `%0A`、超长 URI 做日志。
- 取证/分析：保留 hook 日志与请求原文；记录不可见字符的 hex，避免复现时丢失。
