---
id: mobile-android-ssl-pinning-bypass-cert-frida
title: Android SSL Pinning 绕过：系统证书迁移 + TrustMe/objection/自定义 Frida 脚本
type: scenario
domain: mobile
path: mobile/android
technique: android-ssl-pinning-bypass
aliases:
- Android 抓包
- SSL Pinning 绕过
- MoveCertificate
- TrustMe 模块
- objection sslpinning disable
- Frida SSL bypass
- OkHttp CertificatePinner
tags:
- android
- ssl-pinning
- frida
- objection
- trustme
- magisk
- certificate
- mitm
- https
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V64
  verified_at: '2026-11-05T12:22:55+08:00'
  notes: 已对照原文与本地图01-61核对：Android Studio/SDK/Pixel 9 Pro API36 模拟器（图12-16）、rootAVD/Magisk 30.7（图18-22）、ZygiskNext 1.3.4/Vector 2.0（图25-29）、frida 17.11.0 server 6789（图30-36）；Charles 证书用户安装（图58-59）、MoveCertificate v1.5.7（图61）、证书出现在用户凭据（图60）；抓包失败为 certificate_unknown（图57），objection sslpinning disable 与自定义 Frida/WebView/QUIC 处理方法与正文一致。未验证点：文章为环境搭建教程，未绑定具体目标 APK；PoC 未本机复跑；mTLS 提取被作者跳过；无版本/CVE。
---

## 一句话结论

Android 7.0+ 默认只信任系统 CA，APP 还会用 OkHttp `CertificatePinner`、Conscrypt `TrustManagerImpl` 等做 SSL Pinning；在已 Root 的模拟器上把代理 CA 迁入系统证书目录，再按目标加固情况选择 TrustMe（Xposed）、objection 或自定义 Frida 脚本 Hook 校验入口，即可让 Charles/Burp 正常解密 HTTPS 流量。

## 原理

- Android 7.0 起，APP 默认只信任系统 CA（`/system/etc/security/cacerts`），用户安装的 CA 不再被大多数 APP 信任；抓包工具的动态证书因此被拒绝。
- 把代理 CA 安装为用户证书后，用 Magisk 模块 MoveCertificate 将其迁移/复制到 `/etc/security/cacerts/`，使 APP 将其视为系统证书；若模块未自动迁移，可用 MT 管理器手动从 `/data/misc/user/0/cacerts-added/` 复制。
- SSL Pinning 在代码层校验服务器证书/公钥：OkHttp 的 `CertificatePinner.check`、Conscrypt 的 `TrustManagerImpl.verifyChain`、自定义 `X509TrustManager.checkServerTrusted` 是常见 Hook 点。
- TrustMe 是 Xposed/Vector 模块，覆盖 37+ 种 pinning 实现；objection 把 Frida 的常见逆向操作封装为命令，`android sslpinning disable` 自动注入绕过脚本；两者失效时可用自定义 Frida 脚本逐个 Hook。
- WebView 有独立的 `onReceivedSslError` 回调，需单独 Hook；QUIC/HTTP3 走 UDP 443，不经过 TCP 代理，需要额外阻断或处理。

## 触发条件

- 测试设备已 Root（模拟器刷 Magisk）并安装 Frida Server/Vector（Xposed）环境。
- 代理工具（Charles/Burp/Yakit）已生成 CA 证书，设备与代理网络可达。
- 目标 APP 未使用 native 层 pinning 或更强的 RASP；若使用，需要额外逆向 .so。
- Frida 版本 PC 端与设备端完全一致，且目标 APP 未检测 Frida/Root。

## 利用步骤

1. 导出代理 CA（Charles：Help → SSL Proxying → Save Charles Root Certificate），`adb push` 到 `/sdcard/Download/`。
2. 模拟器设置 → 安全 → 加密与凭据 → 从 SD 卡安装证书 → CA 证书，导入后确认出现在“用户”凭据。
3. 安装 MoveCertificate 模块并重启，确认证书出现在“系统”凭据；未自动迁移则用 MT 管理器手动复制到 `/etc/security/cacerts/`。
4. 优先安装 TrustMe（Vector 中启用并勾选目标 APP），重启 APP 测试抓包。
5. TrustMe 失效时，启动 frida-server，使用 objection：`objection -N -h 127.0.0.1 -P 6789 -n <包名> start`，执行 `android sslpinning disable`。
6. 仍失败时加载自定义 Frida 脚本，Hook OkHttp `CertificatePinner.check`、`TrustManagerImpl.verifyChain`、`X509TrustManager`；WebView 页面另 Hook `onReceivedSslError` 并 `handler.proceed()`。
7. 若代理中完全看不到目标域名但 APP 正常，检查 QUIC：阻断 UDP 443 强制回退 TCP HTTPS。

## PoC

```bash
# 1. 推送并安装代理 CA
adb push charles-ssl-proxying-certificate.pem /sdcard/Download/
# 设置 → 安全 → 加密与凭据 → 从 SD 卡安装证书 → CA 证书

# 2. MoveCertificate 迁移到系统证书目录（Magisk 模块安装后重启）
# 未自动迁移时：
adb shell su -c "cp /data/misc/user/0/cacerts-added/* /etc/security/cacerts/"

# 3. Frida Server
adb push frida-server-17.11.0-android-arm64 /data/local/tmp/sf
adb shell "su -c 'chmod 755 /data/local/tmp/sf'"
adb shell "su -c '/data/local/tmp/sf -l 0.0.0.0:6789 &'"
adb forward tcp:6789 tcp:6789

# 4. objection 一键绕过
objection -N -h 127.0.0.1 -P 6789 -n <包名> start
# objection shell 内：
android sslpinning disable

# 5. 自定义 Frida 脚本
frida -H 127.0.0.1:6789 -f <包名> -l universal_ssl_bypass.js
```

```javascript
// universal_ssl_bypass.js（核心 Hook 点）
Java.perform(function() {
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    } catch(e) {}
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain) {
            return untrustedChain;
        };
    } catch(e) {}
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManager = Java.registerClass({
            name: "com.bypass.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function() {},
                checkServerTrusted: function() {},
                getAcceptedIssuers: function() { return []; }
            }
        });
    } catch(e) {}
});
```

## 变体与关联

- **WebView 独立校验**：Hook 实际 `WebViewClient` 子类的 `onReceivedSslError`，调用 `handler.proceed()`；类名需在 jadx 中搜索确认。
- **QUIC/HTTP3**：`adb shell su -c "iptables -A OUTPUT -p udp --dport 443 -j REJECT"` 强制回退 TCP HTTPS。
- **双向认证 mTLS**：除客户端信任代理外，还需把 APP 内置客户端证书导入代理；证书可能加密，需逆向提取（见 mTLS 提取卡）。
- **native pinning**：BoringSSL/自定义 .so 校验无法用 Java Hook 覆盖，需要 IDA/Ghidra 分析或 Frida native Hook。
- **关联**：[[mobile-android-anti-detection-root-emulator-proxy]]（Root/代理检测绕过）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加固 APP 脱壳后定位 pinning 实现）。

## 检测与防御

- APP 侧使用 native 层证书 pinning（BoringSSL/自定义校验）、证书透明/公钥固定，避免仅依赖 Java 层 `CertificatePinner`。
- 启用 Play Integrity/设备完整性校验与 Root/Frida 检测，服务端做风险评分，不信任客户端环境。
- 使用 mTLS 或请求签名，降低中间人抓包价值；敏感接口做证书绑定与请求时效校验。
- 检测：设备出现 Magisk/Shamiko/TrustMe/Vector 模块；`/system/etc/security/cacerts` 被修改；Frida 端口/进程；代理 CA 被安装为系统证书。
