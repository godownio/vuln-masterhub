---
id: mobile-android-conscrypt-native-client-key-extract
title: Conscrypt 客户端私钥内存提取：Hook libconscrypt_jni.so 的 EVP_parse_private_key 与 Java 证书读取，导出 mTLS p12
type: scenario
domain: mobile
path: mobile/android
technique: conscrypt-native-client-key-extract
aliases:
- Conscrypt 私钥提取
- EVP_parse_private_key Hook
- libconscrypt_jni.so
- AndroidKeyStore 客户端证书导出
- mTLS 客户端私钥
- r0capture 失败后的私钥提取
- X509Certificate getEncoded dump
tags:
- android
- conscrypt
- mtls
- client-certificate
- private-key
- frida
- jni
- native-hook
- p12
- burp
- ssl
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T05:19:10+08:00'
  notes: 已对照原文与全部23图（01代理/02指定APP/03-05 mTLS 400/06-08 assets与trusted.crt证书链/09 FridaServer16.2.1/10 KeyStore自吐无果/11 clientBootstrapCertInfo堆栈/12 r0capture org.conscrypt且加密/13 AndroidKeyStore别名源码/14-15客户端证书EKU与DER/17 NativeCrypto_EVP_parse_private_key源码/18 Java层调用点/19 导出EVP_parse_private_key及私钥hexdump 30 82 04 be/20 RSA2048私钥/21证书配对/22导出p12/23 Burp客户端证书/24 200且可解密）核对一致。已修正参数索引说明：原文图17的JNI函数为(JNIEnv*,jclass,jbyteArray)，jbyteArray应为args[2]；图19 enumerateExports实际打印符号名为BoringSSL EVP_parse_private_key(CBS*)，原文脚本args[1]读DER，已在原理/步骤/PoC注明复现时按命中符号取参。dedup 除自身外 top 为 mobile-android-mtls-r0capture-client-cert-export（related，同目标不同Hook层，非同一链），dup-scan无涉及pair。未验证点：未复跑Frida脚本；原文未标组件版本，未设affected_versions；frontmatter无sources/source_url。
---

## 一句话结论

当 App 使用 `org.conscrypt` 且 r0capture/KeyStore 自吐脚本拿不到 mTLS 客户端私钥时，可在 Java 层 Hook 应用的证书读取方法导出 `X509Certificate`，再在 native 层拦截 `libconscrypt_jni.so` 导出的 `EVP_parse_private_key`，直接 dump 其 `jbyteArray` 参数中的 DER 私钥；用 XCA 把证书与私钥合成 PKCS#12 导入 Burp，即可作为客户端证书完成双向认证抓包，服务端从 `400 No required SSL certificate was sent` 变为正常 200。

## 原理

- **mTLS 需要客户端私钥**：服务端要求客户端证书时，代理只有自己的 CA 证书，没有 App 持有的客户端证书与私钥，握手被拒并返回 `400 No required SSL certificate was sent`；JustTrustMe/TrustMe 等只解决“客户端不信任代理 CA/服务端证书 pinning”，不提供客户端证书。
- **Conscrypt 的私钥解析路径**：`org.conscrypt` 是基于 OpenSSL/BoringSSL 的 TLS Provider。Java 层 `OpenSSLKey.fromPrivateKey`/`OpenSSLEngineSocket` 等在需要把私钥交给 native 时，会调用 `NativeCrypto.EVP_parse_private_key(byte[])`；JNI 侧对应 `NativeCrypto_EVP_parse_private_key(JNIEnv*, jclass, jbyteArray keyJavaBytes)`，函数内部用 `ScopedByteArrayRO` 取字节并交给 `EVP_parse_private_key(CBS*)`。因此私钥的原始字节会以 JNI `byte[]` 形式出现在该函数入口，Hook 导出函数即可读出。注意：JNI 版函数的 `jbyteArray` 是第 3 个参数（`args[2]`）；而原文图 19 的 `Module.enumerateExports` 实际打印的符号名是 BoringSSL 的 `EVP_parse_private_key`（签名 `EVP_parse_private_key(CBS*)`），此时密钥在 `CBS{data,len}` 中，原文脚本用 `args[1]` 读出 DER，复现时应按实际命中的符号确认取参方式。
- **为什么常规脚本会失败**：r0capture 与 KeyStore 自吐脚本主要 Hook Java 层 `SSLContext`/`TrustManager`/`KeyManager`/`KeyStore` 等 API；该 App 的客户端证书由 `AndroidKeyStore` 别名读取（示例 `clientBootstrapCertInfo()` 遍历别名 `AkeyChatAndroidBootstrapCertificate` 并 `getCertificate`），私钥则直接以字节数组传入 native 解析。Java 层 Hook 可能不触发或返回 `null`，所以需要下沉到 native。
- **证书与私钥匹配**：Hook 证书读取方法得到 `X509Certificate`，`getEncoded()` 得到 DER 证书；native Hook dump 出的 DER 私钥（示例以 `30 82 04 be 02 01 00 ...` 开头，RSA 2048）导入 XCA 后与证书公钥指纹一致（`EE:DE:49:20...`），可绑定为同一密钥对。
- **为什么能导出**：私钥在应用进程内以可读字节数组形式存在（从 KeyStore/文件/内存取出后交给 OpenSSL 解析），Frida 在进程内 Hook 即可读取；若私钥始终留在 TEE/StrongBox 内且不可导出，则不会以 byte[] 形式出现，该方法失效。
- **Hook 点定位**：先 Hook `android_dlopen_ext` 捕获 `libconscrypt_jni.so` 加载，取得模块 base 后 `Module.enumerateExports` 找到 `EVP_parse_private_key` 的地址，再 `Interceptor.attach`；原文脚本把 `args[1]` 当作 `jbyteArray` 用 `Memory.readByteArray(args[1], 0x1000)` 读取（若命中 JNI 版 `NativeCrypto_EVP_parse_private_key`，`jbyteArray` 应为 `args[2]`；若命中 BoringSSL `EVP_parse_private_key`，应取 `CBS*` 的 `data/len`），复现时需按命中符号核对。文章尝试 `GetArrayLength` 会闪退，故采用固定长度 0x1000 预读，按实际密钥长度截取。

## 触发条件

- 代理抓包时服务端返回 `400 No required SSL certificate was sent`，确认是 mTLS；单/双向 pinning 绕过脚本无效。
- App 使用 `org.conscrypt`，私钥在进程内以 `byte[]`/`CBS` 缓冲区形式传给 `NativeCrypto_EVP_parse_private_key`/`EVP_parse_private_key` 解析（非 TEE 内不可导出密钥）。
- 设备已 root，FridaServer 可运行（示例 JsHook + FridaServer 16.2.1），App 未检测/未被绕过 Frida。
- 能在 Java 层找到返回客户端证书的方法（可通过抛异常打印调用栈定位，例如 `android.util.Log.getStackTraceString(new Throwable())`）。
- 目标 `libconscrypt_jni.so` 已随 App 加载，且 `EVP_parse_private_key` 在导出表中可见。

## 利用步骤

1. 确认 mTLS：配置 Burp 代理后请求返回 `400 No required SSL certificate was sent`；卸载/关闭 pinning 绕过模块后仍失败。
2. 启动 frida-server 并端口转发，以 spawn 模式启动 App：
   ```bash
   adb forward tcp:28042 tcp:28042
   frida -H 127.0.0.1:28042 -f <包名> -l hook.js
   ```
3. 在 Java 层定位证书读取方法：用 `console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()))` 在关键调用处打印堆栈，找到与证书相关的类/方法（示例 `ak.im.module.AkeyChatX509PrivateCA.clientBootstrapCertInfo`）。
4. Hook 该方法，调用原方法取得 `X509Certificate`，用 `getEncoded()` 取 DER 并写入 `/sdcard/Download/private.pem`（示例实际写的是证书 DER）。
5. 若 Java 层私钥 Hook 无结果，转入 native：Hook `android_dlopen_ext`，匹配 `libconscrypt_jni.so`；在 `onLeave` 取模块 base 并遍历导出表，找到 `EVP_parse_private_key`；`Interceptor.attach` 后按命中符号读取私钥字节（原文脚本直接读 `args[1]` 的 0x1000 字节；JNI 版 jbyteArray 为 `args[2]`，BoringSSL 版取 `CBS*` 的 `data/len`），写入 `/sdcard/Download/private.pem`。
6. `adb pull` 取出证书与私钥，用 XCA 导入证书、导入 RSA 私钥，确认公钥指纹一致；导出为 PKCS#12（`.pfx`/`.p12`）。
7. Burp `Settings -> TLS -> Client TLS certificates -> Add`，Host 填 `*`（或目标主机），选择 p12 并输入密码；重放请求，确认返回 200 且能解密业务流量。

## PoC

Java 层证书导出（示例，类名按目标调整）：

```javascript
function hookCert() {
    Java.perform(function () {
        let C = Java.use("ak.im.module.AkeyChatX509PrivateCA");
        C["clientBootstrapCertInfo"].implementation = function () {
            let result = this["clientBootstrapCertInfo"]();
            console.log("cert:", result);
            let der = result.getEncoded();
            let bytes = Memory.readByteArray(der, der.length);
            const f = new File("/sdcard/Download/client_cert.der", "wb");
            f.write(bytes);
            return result;
        };
    });
}
hookCert();
```

Native 私钥导出（Hook `libconscrypt_jni.so` 的 `EVP_parse_private_key`）：

```javascript
function dumpArgs(funcAddr, name) {
    Interceptor.attach(funcAddr, {
        onEnter: function (args) {
            const key = args[1]; // 原文如此；JNI 版 jbyteArray 应为 args[2]，BoringSSL 版应取 CBS->data
            console.log(name + " enter: " + key);
            const bytes = Memory.readByteArray(key, 0x1000); // 固定长度预读
            const f = new File("/sdcard/Download/private.der", "wb");
            f.write(bytes);
        },
        onLeave: function (retval) {}
    });
}

function hook() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            const p = args[0];
            if (p !== null) {
                const path = ptr(p).readCString();
                if (path && path.indexOf("libconscrypt_jni.so") !== -1) this.path = path;
            }
        },
        onLeave: function () {
            if (this.path === undefined) return;
            const base = Module.findBaseAddress(this.path);
            if (base === null) return;
            console.log("base:", base);
            Module.enumerateExports(this.path, {
                onMatch: function (sym) {
                    if (sym.name.indexOf("EVP_parse_private_key") !== -1) {
                        console.log(sym.name + " @ " + sym.address);
                        dumpArgs(sym.address, sym.name);
                    }
                },
                onComplete: function () {}
            });
        }
    });
}
hook();
```

说明：文章环境中对 `jbyteArray` 调用 JNI `GetArrayLength` 会闪退，因此用固定 0x1000 字节预读，再按 DER 长度截断；实际密钥长度不足 0x1000 时尾部为多余内存数据，导入 XCA 时按 DER 结构解析即可。

## 变体与关联

- [[mobile-android-mtls-r0capture-client-cert-export]]：标准的 r0capture 应用层导出路径；本卡是它失败时的 fallback，Hook 点从 Java SSL/KeyManager 下沉到 `libconscrypt_jni.so` 的 `EVP_parse_private_key`，触发条件（Conscrypt 原生解析、r0capture 无输出）与 PoC 均不同。
- 变体：Hook `SSLContext.init`/`KeyManager.chooseClientAlias` 或 `OpenSSLKey.fromPrivateKey`，在 Java 层直接拿 `PrivateKey`；若 `getEncoded()` 返回 null（硬件 KeyStore），改用本卡 native 内存 dump。
- 变体：若私钥以 PEM 字符串/文件形式存在，可直接从 assets/内存/文件中提取，不需要 Hook `EVP_parse_private_key`。
- 关联：[[mobile-android-ssl-pinning-bypass-cert-frida]]（单向 pinning/系统证书迁移）；[[mobile-android-anti-detection-root-emulator-proxy]]（Frida/root 隐藏）；[[tools-frida-source-patch-anti-detection]]（Frida 自身特征消除）。
- 边界：私钥在 TEE/StrongBox 不可导出、App 检测 Frida/调试、服务端绑定设备证书/attestation 时，本方法可能只拿到证书而没有私钥或仍被服务端拒绝。

## 检测与防御

- 检测（App/服务端）：Frida 注入与 Hook 痕迹（`frida` 线程/模块、inline hook、`/proc/self/maps` 异常）；mTLS 场景下出现 `400 No required SSL certificate was sent` 后的异常重试；客户端证书被导出为 p12/在代理中被复用。
- 防御（密钥保护）：客户端私钥放 AndroidKeyStore/TEE/StrongBox 并设置不可导出；不要先把私钥字节取到 Java 层再交给 OpenSSL 解析；使用 KeyStore 提供的 `Signature`/`Cipher` 完成认证，避免私钥明文材料出现在进程内。
- 防御（抗分析）：检测 Frida/root/调试器，校验 `libconscrypt_jni.so` 完整性；对证书读取方法与 native 解析函数做混淆/完整性校验；服务端启用证书绑定、设备指纹与 attestation，减小私钥泄露后的重放价值。
- 取证建议：若 r0capture 无输出但服务端要求客户端证书，优先检查 `org.conscrypt` 与 `NativeCrypto_EVP_parse_private_key` 调用链，再决定 Java 层还是 native 层 Hook。
