---
id: mobile-android-okhttp-addheader-stack-native-sign-locate
title: Android OkHttp 自定义请求头定位：hook addHeader 堆栈 + native calSign 的路径/时间戳/JSON/key 拼接 MD5
type: scenario
domain: mobile
path: mobile/android
technique: android-okhttp-addheader-stack-native-sign-locate
aliases:
- OkHttp addHeader hook
- X-Client-Sign 定位
- calSign native
- Android 请求签名逆向
- 自定义请求头堆栈
- libscan.so MD5
tags:
- android
- okhttp
- frida
- hook
- request-signature
- native
- md5
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:07:44+08:00'
  notes: 已对照原文核对：hook okhttp3.Request$Builder.addHeader 打印堆栈定位 X-Client-Sign/X-Auth-Token、calSign(defaultID, 秒级时间戳, Gson JSON, defaultKey=m9HplCStJFZMaWng) 拼接后 MD5、libscan.so 运行时存在于 /data/data/包名 并 pull 分析为标准 MD5，均与原文一致；原文示例拼接串佐证无分隔符顺序。未验证点：未复跑 hook/未取得样本 so；原文只说 libscan.so 不在初始安装包、运行时在 data 目录，卡片“释放/下载”为推断；JSON 示例仅 baseAppletAlias 系 Gson 省略 null 的合理推断。frontmatter 无 sources/source_url。
---

## 一句话结论

App 用 OkHttp 的 `Request.Builder.addHeader` 添加 `X-Client-Sign`/`X-Auth-Token` 时，hook `addHeader` 并打印 Java 堆栈即可从调用链定位到签名方法；本例签名是 native `calSign(path, timestamp, JSON, key)`，把四个参数拼接后交给 `libscan.so` 做标准 MD5，复刻拼接顺序即可离线生成签名。

## 原理

- **为什么 hook addHeader**：OkHttp 的请求头最终都经过 `okhttp3.Request$Builder.addHeader(name, value)`（或 `header`/`Headers.Builder`）；hook 它并打印 `Thread.currentThread().getStackTrace()`，可以直接看到业务代码/拦截器/网络层的调用链，比在混淆后的 dex 里盲搜字段名快得多。
- **定位签名入口**：堆栈里出现 `X-Client-Sign` 的赋值点后，跟到 `calSign` 声明：`public static native String calSign(String str, String str2, String str3, String str4)`。native 方法本身在 `libscan.so`（不在原始 APK 中，运行时释放/下载到 `/data/data/<pkg>/`），pull 出来用 IDA 分析可见标准 MD5。
- **参数语义**（样本）：
  1. `defaultID()`：接口路径（如 `/api/app/applet/applet/queryAppletV2/ISO8859-1`）；
  2. `time = date.getTime() / 1000`：秒级时间戳，与 `X-Client-Timestamp` 一致；
  3. JSON：`{"appletAlias": appID, "baseAppletAlias": "io.base.v8"}`（Gson 序列化，键顺序/空格会影响结果）；
  4. `defaultKey()`：固定字符串（样本 `m9HplCStJFZMaWng`）。
- **拼接与哈希**：按 `path + timestamp + json + key` 直接拼接（无分隔符），整体 MD5；服务端用同样规则校验。因为 key 在客户端，签名只能防篡改/防重放，不能防逆向。
- **动态验证**：hook `addHeader` 时同时打印 `value` 与堆栈，抓到一次正常请求后，用 Frida 调用 `calSign` 或 Python 复刻 MD5，对比抓包值即可确认参数顺序与 JSON 序列化细节。

## 触发条件

- App 使用 OkHttp（或基于 OkHttp 的 Retrofit）发起请求，自定义签名头通过 `addHeader`/`header` 添加。
- 签名逻辑在 Java/Kotlin 或 native，参数可从堆栈/字段/常量中还原。
- 有 Frida/可调试环境；目标未启用强反调试/证书固定（或已绕过）。
- 服务端签名只校验客户端计算结果，没有额外设备绑定/一次性 nonce。

## 利用步骤

1. 启动 Frida，hook `okhttp3.Request$Builder.addHeader`，对目标头名（如 `X-Client-Sign`）打印 `name`、`value` 和 Java 堆栈。
2. 触发一次正常请求，从堆栈定位业务类/拦截器与签名方法（`calSign`）。
3. 反编译该方法所在类，确认参数来源：路径、时间戳、JSON 对象、固定 key；记录 JSON 的字段顺序与序列化方式。
4. 若签名在 native，pull `libscan.so`（或从 `/data/data/<pkg>/` 找运行时释放的 so），IDA 确认哈希算法与拼接顺序。
5. 用 Python/Frida 复刻：`md5(path + str(timestamp) + json + key)`，与抓包 `X-Client-Sign` 对比。
6. 之后可修改请求参数并重新签名，做接口测试/越权验证；注意时间戳有效期与重放限制。

## PoC

```javascript
// Frida：hook addHeader 并打印堆栈
let Builder = Java.use("okhttp3.Request$Builder");
Builder["addHeader"].implementation = function (name, value) {
    if (name.indexOf("X-Client-Sign") !== -1 || name.indexOf("X-Auth-Token") !== -1) {
        console.log("[addHeader] " + name + " = " + value);
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()));
    }
    return this.addHeader(name, value);
};
```

```python
import hashlib, json, time

path = "/api/app/applet/applet/queryAppletV2/ISO8859-1"
ts = int(time.time())
payload = json.dumps({"appletAlias": "APP_ID", "baseAppletAlias": "io.base.v8"},
                     separators=(",", ":"))
key = "m9HplCStJFZMaWng"
sign = hashlib.md5((path + str(ts) + payload + key).encode()).hexdigest()
print(sign)
```

## 变体与关联

- **Hook 点变体**：`Request.Builder.header`、`Headers.Builder.add`、`Interceptor.intercept`、Retrofit `@Header` 注解；不同库/版本选择不同。
- **签名算法变体**：MD5/SHA1/SHA256/HMAC、加盐、参数排序、URL 编码、大小写；以 native/Java 实现为准。
- **密钥来源变体**：硬编码、`defaultKey()` native 返回、从 so 字符串解密、服务端下发；可在 Frida 中直接调用返回函数。
- **反调试变体**：Frida 检测、ptrace、SSL Pinning；需先绕过（见关联卡）。
- **关联卡片**：[[mobile-android-ssl-pinning-bypass-cert-frida]]（抓包/证书固定绕过）、[[mobile-android-apk-xor-string-batch-deobfuscation]]（字符串还原）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（native 常量提取）。
- **边界**：签名含一次性 nonce/设备指纹/服务端时间窗时，离线复刻只能用于短时重放；native 强混淆/白盒时需动态调用。

## 检测与防御

- **检测特征**：请求头含 `X-Client-Sign`/`X-Client-Timestamp` 等自定义字段；OkHttp 拦截器/`addHeader` 调用；native `calSign`/MD5 常量。
- **修复**：签名密钥不要硬编码在客户端；使用服务端下发的短时密钥/设备绑定 + 一次性 nonce；关键接口加 TLS Pinning 与完整性校验；服务端校验时间窗与重放。
- **分析建议**：先 hook 头添加点拿堆栈，再定位签名函数；不要从混淆字符串盲搜。
