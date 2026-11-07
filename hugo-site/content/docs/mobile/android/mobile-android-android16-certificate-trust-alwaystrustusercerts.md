---
id: mobile-android-android16-certificate-trust-alwaystrustusercerts
title: Android 16 证书信任绕过：AlwaysTrustUserCerts 模块 + 重启生效
type: scenario
domain: mobile
path: mobile/android
technique: android16-certificate-trust-alwaystrustusercerts
tags:
- android
- certificate
- ssl
- mitm
- apatch
- lsposed
- android16
cve: []
severity: medium
confidence: high
status: verified
affected_versions: Android 16（原文测试）；Android 15 及以下可用 MoveCertificate
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:20:06+08:00'
  notes: 已对照原文核对：AlwaysTrustUserCerts 覆盖 Android 16、MoveCertificate 适用于 Android 15 及以下、安装证书后需重启，与原文明确描述一致；affected_versions 与原文一致。未验证点：未在 Android 16 真机实测证书信任。
url: /docs/mobile/android/mobile-android-android16-certificate-trust-alwaystrustusercerts/
draft: false
kb_aliases:
- AlwaysTrustUserCerts
- MoveCertificate
- Android 16 证书
- 用户证书信任
- 系统证书
---

## 一句话结论

Android 14 之后把代理 CA 放进系统证书目录已不足以让应用信任；在已 root（APatch/KernelPatch）的 Android 16 设备上安装 `AlwaysTrustUserCerts` 模块并重启，可让用户安装的 CA 被应用信任；Android 15 及以下可用 `MoveCertificate` 把用户证书迁移到系统目录。

## 原理

- **Android 证书信任变化**：Android 7 起应用默认只信任系统 CA；Android 14/15/16 又收紧了用户 CA 的信任与系统证书分区（APEX/只读分区），简单 `cp` 到 `/system/etc/security/cacerts` 可能不生效或被 AVB 阻止。
- **AlwaysTrustUserCerts**：LSPosed/Xposed 模块，在应用进程内 Hook 证书信任链，把用户 CA 视为可信；作者实测可覆盖 Android 16 的证书校验问题。安装模块后需要重启（或重启目标应用）让 Hook 生效。
- **MoveCertificate**：Magisk/KernelSU/APatch 模块，把用户安装的 CA 从 `/data/misc/user/0/cacerts-added/` 迁移/绑定到系统证书目录；适用于 Android 15 及以下。
- **前置条件**：设备已 root 且安装 LSPosed（或兼容的 Xposed 框架）；代理 CA 已安装为用户证书；目标应用没有更强的 native pinning/RASP。
- **坑**：每次安装/更新证书后要重启；模块作用域要包含目标应用；Android 16 上 MoveCertificate 可能不生效，优先 AlwaysTrustUserCerts。

## 触发条件

- Android 14/15/16 设备已 root（APatch/Magisk/KernelSU）并启用 LSPosed/Vector。
- 已安装 Burp/Charles 等代理 CA 到用户证书。
- 目标应用使用系统 TrustManager/OkHttp 等标准校验，未使用 native pinning 或 RASP。
- 能重启设备/目标应用使模块生效。

## 利用步骤

1. 在已 root 设备上安装 LSPosed（或 Vector）并确认模块框架可用。
2. 安装 `AlwaysTrustUserCerts` 模块，在 LSPosed 中勾选目标应用（或全局）。
3. 把代理 CA 安装为用户证书（设置 → 安全 → 加密与凭据 → 安装 CA 证书）。
4. 重启设备/目标应用；用浏览器访问代理并检查 Burp/Charles 是否能看到 HTTPS 明文。
5. Android 15 及以下若 AlwaysTrustUserCerts 不适用，改用 `MoveCertificate` 迁移到系统证书目录并重启。
6. 若仍失败，检查应用是否使用 OkHttp CertificatePinner/Conscrypt/native pinning，转 Frida/objection 或逆向 .so。

## PoC

```text
1) 安装 LSPosed/Vector + AlwaysTrustUserCerts 模块
2) LSPosed 作用域勾选目标 APP
3) 设置 → 安全 → 加密与凭据 → 安装 CA 证书（Burp/Charles）
4) 重启设备/目标 APP
5) 代理抓包验证 HTTPS 明文
```

Android 15 及以下 MoveCertificate：

```text
安装 MoveCertificate 模块 → 重启 → 确认证书出现在系统凭据
```

## 变体与关联

- **模块变体**：AlwaysTrustUserCerts、MoveCertificate、TrustMe、JustTrustMe、objection/Frida Hook。
- **版本变体**：Android 14/15/16 的证书分区/APEX 差异；Android 16 优先 AlwaysTrustUserCerts。
- **Pinning 变体**：OkHttp `CertificatePinner`、Conscrypt `TrustManagerImpl`、WebView `onReceivedSslError`、native pinning；需要额外 Hook/逆向。
- **关联卡片**：[[mobile-android-ssl-pinning-bypass-cert-frida]]（系统证书迁移 + Frida/objection）、[[mobile-android-pixel-apatch-root-boot-img-slot]]（APatch root）、[[mobile-android-anti-detection-root-emulator-proxy]]（root/代理检测绕过）。
- **边界**：模块只解决“信任用户 CA”，不解决应用层 pinning；Android 16 的 APEX/只读分区可能让传统系统证书复制失效；银行/支付应用可能检测 root/模块。

## 检测与防御

- **防御**：应用使用证书 pinning/公钥固定、Play Integrity/硬件 attestation、检测 root/LSPosed/模块；敏感接口加 mTLS。
- **检测信号**：设备存在 LSPosed/AlwaysTrustUserCerts/MoveCertificate 模块；系统/用户证书目录异常；代理 CA 被信任。
- **测试建议**：每次装证书后重启；先验证浏览器/普通应用，再测目标应用；失败时区分“证书不信任”和“pinning”。
