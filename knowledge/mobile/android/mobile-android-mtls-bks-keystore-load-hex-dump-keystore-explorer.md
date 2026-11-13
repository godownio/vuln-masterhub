---
id: mobile-android-mtls-bks-keystore-load-hex-dump-keystore-explorer
title: Android mTLS BKS 客户端证书抓包：Hook KeyStore.load 导出密码与真实密钥流十六进制，BKS 转 PKCS#12 导入 Burp
type: scenario
domain: mobile
path: mobile/android
technique: android-mtls-bks-keystore-load-runtime-dump
aliases:
- BKS 双向认证抓包
- KeyStore.load Hook
- tracer-keystore.js
- readStreamToHex
- getClientBksPassword
- keystore-explorer 转 p12
- client.bks 诱饵
- 400 No required SSL certificate was sent
tags:
- android
- mtls
- bks
- keystore
- frida
- client-certificate
- p12
- burp
- traffic-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V660
  verified_at: '2026-11-13T06:56:18+08:00'
  notes: 已对照12439原文与全部9图核对：图01 Burp 400 No required SSL certificate was sent、图02 KayakSC native 方法（getCerEncoding/getClientBksPassword）、图03 代码以 getCerEncoding() 字节构造 InputStream 并配合 getAssets().open("ssl/client.bks")/getClientBksPassword() 初始化、图04 修改后的 hookKeystoreLoadStream（readStreamToHex）、图05 Frida 输出 BKS 口令与 inputSteam 十六进制、图06 client.bks 十六进制与 APK 内文件对不上、图07 KeyStore Explorer Change KeyStore Type→PKCS#12、图08 Burp Client TLS Certificate (File PKCS#12)、图09 200 响应，均与卡片一致。与既有 r0capture（SSL/KeyManager 层导出 p12）与 conscrypt（native EVP_parse_private_key）卡的 Hook 层差异已在变体与关联中写明。原文未标注 App/系统版本，未设 affected_versions。留意点：图03 代码片段中 assets/ssl/client.bks 作为第二参数（trustStore）传入，卡片按原文结论概括为“APK 内 .bks 为诱饵、真实材料来自 native”，属对原文叙述的合理归纳，未发现与原文矛盾。PoC 未复跑。
---

## 一句话结论

代理抓包返回 `400 No required SSL certificate was sent` 说明目标做了 mTLS；当 App 用 BKS keystore 持有客户端证书时，APK 里的 `.bks` 可能只是诱饵（真实 keystore 由 native 在运行时生成），正确做法是用 Frida Hook `java.security.KeyStore.load(InputStream, char[])`，在真实加载点同时截获口令与密钥流十六进制，把十六进制保存为 BKS，再用 KeyStore Explorer 按口令转成 PKCS#12 导入 Burp，即可完成双向认证抓包。

## 原理

- **mTLS 与代理**：单向 TLS 只校验证书链/服务端；mTLS 还要求客户端在握手时出示证书与私钥。Burp/Charles 默认没有 App 的客户端证书，服务端直接返回 `400 No required SSL certificate was sent`（nginx 常见），此时 JustTrustMe/objection 等 pinning 绕过模块无效——它们不提供客户端证书。
- **BKS 是什么**：BKS（Bouncy Castle KeyStore）是 Java/Android 常用的密钥库格式，内含私钥+证书链，加载需要口令；与 PKCS#12 只是容器格式不同，可相互转换。
- **为什么不能直接用 APK 里的 .bks**：本文 App 的 `ssl/client.bks` 文件内容与运行时真正加载的 keystore 十六进制对不上——代码实际用 `KayakSC.getCerEncoding()` 返回的字节构造 `InputStream`，再配合 `KayakSC.getClientBksPassword()` 的口令调用 `KeyStore.load`。也就是说文件是诱饵/混淆，真实证书材料来自 native 运行时；只在 assets 里找到文件并尝试破解会一直失败。
- **Hook 点选择**：所有 Java keystore（BKS/PKCS12/JKS）最终都调用 `KeyStore.load(InputStream, char[])`。Hook 该重载可在参数进入 Java KeyStore 实现前拿到：`this.getType()`（BKS）、`char[]` 口令（转字符串）、`InputStream` 的完整字节（转十六进制）。这样既拿到密码，也拿到真实密钥库字节，绕开文件诱饵与 native 实现细节。
- **转换与导入**：把十六进制写入文件（扩展名 .bks），用 KeyStore Explorer 打开（输入 Hook 到的口令），`Change KeyStore Type → PKCS#12` 保存；Burp 在 `Settings → Network → TLS → Client TLS certificates` 添加 File (PKCS#12) 与口令，之后代理握手会携带客户端证书，服务端返回 200，流量可解密。

## 触发条件

- App 及其 API 使用 mTLS：代理下出现 `400 No required SSL certificate was sent` 或 TLS 客户端证书缺失错误。
- 设备已 root、Frida Server 可运行，App 未检测/已绕过 Frida。
- App 的 keystore 在 Java 层通过 `KeyStore.load` 加载（BKS/PKCS12 均可），口令为静态或可由 native 函数取得。
- 客户端私钥可导出（软件 keystore；硬件 Keystore/TEE 不可导出时需改用进程内 Hook 签名/握手）。

## 利用步骤

1. 确认 mTLS：配置 Burp/Charles 代理，观察响应 `400 No required SSL certificate was sent`；确认 pinning 绕过模块无法解决。
2. 静态定位：在 APK 中搜索 `.bks`、`KeyStore`、`getClientBksPassword`/`getCerEncoding` 等符号；注意 assets 中的文件可能只是诱饵，以代码中实际传入 `KeyStore.load` 的流为准。
3. 使用 `tracer-keystore.js`，修改 `hookKeystoreLoadStream`：Hook `java.security.KeyStore.load(InputStream, [C)`，打印 `this.getType()`、`charArrayToString(charArray)` 以及 `readStreamToHex(stream)` 的十六进制，并继续调用原 `load`。
4. 启动 frida-server，`frida -U -f <package> -l tracer-keystore.js`，触发 App 网络请求；日志中得到 `keystoreType: BKS, password: '...', inputSteam: 00000002...`。
5. 把十六进制粘贴进 WinHex/xxd 保存为 `client.bks`；用 KeyStore Explorer 打开（输入 Hook 口令），确认别名/证书链存在。
6. `Tools → Change KeyStore Type → PKCS #12` 另存为 `.p12`（口令可与原口令相同）。
7. Burp：`Settings → Network → TLS → Client TLS certificates → Add → File (PKCS#12)`，选择 p12 并输入口令；重新抓包，服务端返回 200 且可看到明文请求/响应。

## PoC

```javascript
// tracer-keystore.js 关键修改：Hook KeyStore.load(InputStream, char[])
function hookKeystoreLoadStream(dump) {
    var keyStoreLoadStream = Java.use('java.security.KeyStore')['load']
        .overload('java.io.InputStream', '[C');
    keyStoreLoadStream.implementation = function (stream, charArray) {
        var hexString = readStreamToHex(stream);
        console.log("[Keystore.load] type: " + this.getType()
            + ", password: '" + charArrayToString(charArray)
            + "', stream: " + hexString);
        this.load(stream, charArray);
        if (dump) console.log("aliases: " + ListAliasesObj(this));
    }
}
```

```text
# 将日志中的 inputSteam 十六进制保存为 client.bks，然后：
# KeyStore Explorer 打开 client.bks（输入 Hook 口令）
# Tools -> Change KeyStore Type -> PKCS #12 -> 保存 client.p12
# Burp: Settings -> Network -> TLS -> Client TLS certificates -> Add -> File (PKCS#12)
GET /rest/base/version HTTP/1.1
Host: <api-host>
...
HTTP/1.1 200 OK
```

## 变体与关联

- 变体：证书为 PKCS#12/PFX 时同样可 Hook `KeyStore.load` 拿到口令与字节，直接导入 Burp；BKS 只是需要 KeyStore Explorer 额外转一次格式。
- 变体：keystore 由 native 生成（如本例 `getCerEncoding()`）时，Hook `KeyStore.load` 比静态找文件可靠；也可 Hook native 的 `getClientBksPassword` 只拿口令再配合文件（文件真实时）。
- 变体：`r0capture` 可直接在 SSL/KeyManager 层导出 p12，适合不关心 keystore 格式的场景；Conscrypt 场景可 Hook `EVP_parse_private_key` 拿私钥 DER。
- 变体：若私钥在 AndroidKeyStore/TEE 中不可导出，Java 层拿不到明文私钥，需要在进程内 Hook 签名/握手或使用 r0capture 的 SSL 层方案。
- 关联：[[mobile-android-mtls-r0capture-client-cert-export]]（r0capture 直接导出 p12）、[[mobile-android-conscrypt-native-client-key-extract]]（native 私钥提取）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（pinning 绕过）、[[mobile-android-android16-certificate-trust-alwaystrustusercerts]]（系统证书信任）。
- 边界：App 检测 Frida/root、keystore 口令动态且无法 Hook、私钥硬件保护不可导出、服务端还校验证书与设备绑定关系时，仅导入证书可能仍被拒绝。

## 检测与防御

- 检测：客户端完整性/Frida 检测与 mTLS 绑定；服务端对同一账号的客户端证书指纹异常变化、证书被多个来源使用；TLS 日志中客户端证书与设备指纹不匹配。
- 防御：客户端私钥放入 AndroidKeyStore/TEE 且不可导出、使用 attestation 绑定设备；mTLS 之外叠加应用层签名/DPoP；检测 Hook 框架与调试器；服务端对客户端证书做吊销与指纹白名单。
