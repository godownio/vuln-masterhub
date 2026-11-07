---
id: mobile-android-mtls-r0capture-client-cert-export
title: Android mTLS 双向认证抓包：r0capture 从应用层导出客户端 p12 并导入 Burp/Reqable
type: scenario
domain: mobile
path: mobile/android
technique: android-mtls-r0capture-client-cert-export
aliases:
- Android 双向证书抓包
- mTLS 客户端证书导出
- r0capture 导出 p12
- 400 No required SSL certificate was sent
- 双向认证绕过
- 客户端证书导入 Burp
tags:
- android
- mtls
- ssl
- r0capture
- frida
- client-certificate
- p12
- burp
- reqable
- traffic-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V121
  verified_at: '2026-11-06T04:16:53+08:00'
  notes: 已对照原文及60张本地图核对：400 No required SSL certificate was sent 判 mTLS、单/双向 pinning 模块无效、r0capture 2.1 + Frida 16.1.0、p12 导出到 /sdcard/Download/<包名>.p12、默认密码 r0ysue、Burp/Reqable 客户端证书导入均与原文一致；r0capture 段图片为外链未落盘，依据原文文字核对；应用无版本标记，affected_versions 已清空；PoC 未本机执行
---

## 一句话结论

代理抓包时服务端返回 `400 No required SSL certificate was sent`，说明是 mTLS（服务端要求客户端证书），单/双向 pinning 绕过模块都无效；用 r0capture 在应用层 Hook SSL，把 App 的客户端证书/私钥导出为 `/sdcard/Download/<包名>.p12`（默认密码 `r0ysue`），再导入 Burp/Reqable 作为客户端证书，即可完成双向认证抓包。

## 原理

- **mTLS 与单向 TLS 的区别**：单向 TLS 只校验服务端证书；mTLS 在握手时还要求客户端出示证书并由服务端验证。代理工具默认只有自己的 CA，没有 App 的客户端证书/私钥，因此服务端直接返回 `400 No required SSL certificate was sent`。
- **为什么 pinning 绕过模块无效**：JustTrustMe/TrustMe/objection 等解决的是“客户端不信任代理 CA”或“客户端 pinning 服务端证书”，不提供客户端证书；mTLS 需要的是 App 持有的 `KeyStore` 私钥 + 证书链。
- **r0capture 的思路**：它基于 Frida Hook Android 应用层 SSL 实现（`SSLContext`、`TrustManager`、`KeyManager`、OkHttp/HttpURLConnection/Retrofit 等），在 App 与服务器握手时截获客户端证书和私钥材料，导出为 PKCS#12（`.p12`），默认密码 `r0ysue`；同时无视证书 pinning/加固，因此对 mTLS App 也能拿到证书。
- **导入代理**：Burp 的 `Settings → TLS → Client TLS certificates` 添加目标 host（`*`）并加载 p12；Reqable 在 `SSL → 客户端证书` 导入 p12。代理在 TLS 握手时把该证书发给服务端，服务端校验通过后即可解密流量。
- **前提**：App 的客户端私钥可被应用层 Hook 捕获（软件 KeyStore/文件/内存）；若使用硬件 Keystore/TEE 且私钥不可导出，r0capture 可能只能拿到证书链而拿不到私钥，需要在进程内 Hook 签名/握手。

## 触发条件

- App 正常使用，但经 Burp/Reqable/Charles 代理时无网络；响应含 `400 No required SSL certificate was sent` 或 TLS 握手失败。
- 单/双向 SSL pinning 绕过模块（JustTrustMe/TrustMeAlready/objection/Frida）无效。
- 设备已 root，Frida Server 可运行；App 未检测 Frida/root 或已绕过。
- App 的客户端证书/私钥可在应用层被 Hook 捕获（非硬件不可导出密钥）。
- 使用 r0capture 2.1 + Frida 16.x（高版本 Frida 可能不兼容）。

## 利用步骤

1. 先确认是 mTLS：代理下 App 报错，响应出现 `400 No required SSL certificate was sent`；开启单/双向 pinning 绕过模块仍无效。
2. 安装并启动 frida-server（建议 Frida 16.1.0 / frida-tools 12.1.3），`adb push` 到 `/data/local/tmp`，`chmod 777` 后运行。
3. 给目标 App 开启存储读写权限（r0capture 需要写 `/sdcard/Download`）。
4. 运行 r0capture：`python r0capture.py -U -f <包名> -v`；脚本会自动启动 App 并输出日志。
5. 在 App 内触发一次正常请求；脚本导出客户端证书到 `/sdcard/Download/<包名>.p12`，默认密码 `r0ysue`。
6. `adb pull` 把 p12 拉到电脑；Burp 中 `Settings → TLS → Client TLS certificates → Add`，host 填 `*`，选择 p12，输入密码；Reqable 在 SSL 客户端证书中导入。
7. 重新配置代理（可加二级代理到 Burp），访问 App 登录/业务接口，确认能正常抓包。

## PoC

```bash
# 1. 启动 frida-server（设备已 root）
adb push frida-server-16.1.0-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod 777 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"

# 2. 运行 r0capture（2.1 版本，Frida 16.x）
python r0capture.py -U -f com.example.app -v

# 3. 触发 App 请求后导出 p12
adb pull /sdcard/Download/com.example.app.p12 ./
# 默认密码：r0ysue
```

Burp 导入：

```text
Settings → TLS → Client TLS certificates → Add
  Destination host: *
  Certificate file: com.example.app.p12
  Password: r0ysue
```

Reqable 导入：

```text
SSL → 客户端证书 → 导入 p12（密码 r0ysue）
```

## 变体与关联

- **导出方式变体**：r0capture、Frida Hook `KeyManager.chooseClientAlias`/`SSLContext.init`、从 App 的 `KeyStore`/文件/内存提取；硬件 Keystore 不可导出时，在进程内 Hook 握手签名。
- **代理变体**：Burp、Reqable、Charles、mitmproxy 都支持客户端证书；二级代理链（Reqable → Burp）时只需在其中一层配置客户端证书。
- **证书格式变体**：p12/PFX、PEM + KEY、JKS；导入前用 `openssl pkcs12 -info` 确认密码/链。
- **关联卡片**：[[mobile-android-ssl-pinning-bypass-cert-frida]]（单向 pinning/系统证书迁移）、[[mobile-android-anti-detection-root-emulator-proxy]]（root/模拟器/Frida 隐藏）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加固/脱壳）。
- **边界**：客户端私钥在 TEE/StrongBox 且不可导出、App 检测 Frida/root、服务端还校验设备指纹/证书绑定（mTLS + attestation）时，单纯导出 p12 可能不够。

## 检测与防御

- **检测特征**：代理下出现 `400 No required SSL certificate was sent`；App 使用 `KeyChain`/`KeyStore` 客户端证书；r0capture/Frida 注入痕迹；p12 文件被导出。
- **防御**：客户端私钥放硬件 Keystore/TEE 并设置不可导出；启用证书绑定/attestation；检测 Frida/root/调试；服务端校验客户端证书 + 设备指纹；对异常 TLS 客户端做风控。
- **取证建议**：先区分单向 pinning 与 mTLS；mTLS 场景优先找客户端证书，而不是反复换 pinning 绕过脚本。
