---
title: Android
weight: 1
---

# Android

## 这层是什么

Android 应用与逆向：APK/DEX/SO、加固、Hook、动态分析与漏洞。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [360 加固 APK 脱壳：PKID 查壳 + FunDex/LSPosed dump（frida-dexdump 被检测时的替代）](mobile-android-360-hardening-fundex-lsposed-dump/) | verified | high | 2026-11-06 |
| [Android 16 证书信任绕过：AlwaysTrustUserCerts 模块 + 重启生效](mobile-android-android16-certificate-trust-alwaystrustusercerts/) | verified | high | 2026-11-06 |
| [Android allowBackup=true + adb backup/restore：导出应用数据并恢复登录态](mobile-android-allowbackup-adb-backup-restore-account-takeover/) | verified | high | 2026-11-06 |
| [Android API sign 逆向：SHA-256 hex 重排 + AES-CBC 生成请求头签名](mobile-android-aes-cbc-sign-header-hash-rotate/) | verified | high | 2026-11-06 |
| [Android APK 字符串异或混淆批量还原：JADX 反编译 + 同构解密脚本正则替换](mobile-android-apk-xor-string-batch-deobfuscation/) | verified | high | 2026-11-05 |
| [Android APP 反检测环境：Shamiko/HideMyApplist/PlayIntegrityFork 与 iptables 透明代理绕过](mobile-android-anti-detection-root-emulator-proxy/) | verified | high | 2026-11-05 |
| [Android JNI native 校验链模拟执行：ARM64 机器码常量提取 + Unicorn hook 调用](mobile-android-jni-native-unicorn-emulation-constant-extraction/) | verified | high | 2026-11-06 |
| [Android JNI 多层自定义加密逆向：运行时提取 XXTEA key + Block-TEA 变体 + AES S-box 8 轮白化](mobile-android-jni-xxtea-blocktea-aes-sbox-multilayer/) | verified | medium | 2026-11-07 |
| [Android libnesec.so Frida 反调试定位与线程替换绕过：dlopen/路径监控 + pthread_create 精准替换第一条线程](mobile-android-native-frida-antidebug-thread-bypass/) | verified | high | 2026-11-06 |
| [Android mTLS 双向认证抓包：r0capture 从应用层导出客户端 p12 并导入 Burp/Reqable](mobile-android-mtls-r0capture-client-cert-export/) | verified | high | 2026-11-06 |
| [Android OkHttp 自定义请求头定位：hook addHeader 堆栈 + native calSign 的路径/时间戳/JSON/key 拼接 MD5](mobile-android-okhttp-addheader-stack-native-sign-locate/) | verified | high | 2026-11-06 |
| [Android SSL Pinning 绕过：系统证书迁移 + TrustMe/objection/自定义 Frida 脚本](mobile-android-ssl-pinning-bypass-cert-frida/) | verified | high | 2026-11-05 |
| [Android WebView JSBridge 任意页面凭证窃取：exported ProxyActivity 路由 + 无域名校验 WebView + 全局 handler 注册表](mobile-android-webview-jsbridge-arbitrary-origin-credential-theft/) | verified | high | 2026-11-06 |
| [Android WebView 开启 file 协议通用访问：恶意 file:// 页面跨域读取私有目录与本地文件](mobile-android-webview-file-universal-access-local-read/) | verified | medium | 2026-11-06 |
| [Android Zygote ptrace 注入：ARM32 shellcode dlopen SO，fork 后全应用继承](mobile-android-zygote-ptrace-dlopen-injection/) | verified | high | 2026-11-06 |
| [Android 二代壳静态脱壳：从 libshell.so 按偏移 carve 内嵌 ELF，恢复 JNI setData/ihk/test 实现](mobile-android-shell-so-embedded-elf-carve-extract-dat/) | verified | medium | 2026-11-07 |
| [Android 免费影视应用借 bandwidth monetizer SDK 将设备变为住宅代理节点](mobile-android-bandwidth-monetizer-sdk-residential-proxy/) | verified | high | 2026-11-05 |
| [Android 加固 APK 查壳与脱壳：APKiD 识别 + frida-dexdump 内存 dump + jadx/apktool 审计](mobile-android-packer-apkid-frida-dexdump-jadx/) | verified | high | 2026-11-05 |
| [Android 加密 so 运行时解密/dlopen：从 /data/data 提取解密后的 .so 逆向 TEA 校验](mobile-android-encrypted-so-runtime-dlopen-extraction/) | verified | high | 2026-11-06 |
| [Android 多关卡校验逆向：Frida dump 8 关 target + 逐关自定义变换/流水线逆运算](mobile-android-multilevel-checker-frida-transform-chain/) | verified | high | 2026-11-07 |
| [Android 应用 SQLCipher 数据库静态密钥还原：逆向 keyBase（MD5 前 6 位）解密应用数据库](mobile-android-sqlcipher-static-key-derivation/) | verified | high | 2026-11-06 |
| [Android 登录 codeSign 签名逆向与 Burp 自动重签：MD5(body+nonce+固定串+timestamp) 支撑账号爆破](mobile-android-login-codesign-md5-burp-auto-resign/) | verified | high | 2026-11-06 |
| [Android 组件导出：未登录启动 ChangePasswordActivity 用于钓鱼/未授权页面](mobile-android-exported-activity-unauth-changepassword-phishing/) | verified | high | 2026-11-06 |
| [Android 请求/响应 AES 解密：hook CryptoHelper.getKey 固定随机 key + 固定 IV 的 CBC/PKCS7+Base64](mobile-android-aes-random-key-hook-fixed-iv-decrypt/) | verified | high | 2026-11-06 |
| [Android 请求参数加密逆向：DES/ECB + MD5(str2+salt+时间窗) 密钥 + Base64](mobile-android-param-encryption-des-md5-timewindow/) | verified | high | 2026-11-06 |
| [Android 运行时密文提取与多层解密：frida-dexdump 脱壳 + Frida Hook 静态字段 + 复用应用内 RC4/AES](mobile-android-runtime-ciphertext-frida-dexdump-java-char-rc4-aes/) | verified | high | 2026-11-07 |
| [Android 远程协助 APK 的高权限远控链路识别：无障碍操控 + MediaProjection 录屏 + WebRTC 实时通道](mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc/) | verified | high | 2026-11-05 |
| [Android 防录屏绕过：LSPosed DisableFlagSecure 解除 FLAG_SECURE](mobile-android-disable-flag-secure-lsposed-screen-capture/) | verified | high | 2026-11-06 |
| [Android 风控 /proc/cpuinfo 检测与 Hook 对抗：伪造 CPU 型号/核心数绕过模拟器识别](mobile-android-cpuinfo-emulator-detection-hook-bypass/) | verified | high | 2026-11-06 |
| [APatch/KPM SyscallHook：sys_call_table 函数指针替换 + transit 链 before/after 回调](mobile-android-kpm-syscall-function-pointer-hook-transit/) | verified | high | 2026-11-06 |
| [APatch/KPM 内核 InlineHook：ARM64 trampoline、PC 相对重定位与页表改权限](mobile-android-kpm-inline-hook-arm64-trampoline-relocation/) | verified | high | 2026-11-06 |
| [APK 伪装 so 藏 dex：protobuf 登录伪造 + LCG XOR/RSA-AES 封装](mobile-android-apk-hidden-dex-protobuf-login-forge/) | verified | high | 2026-11-06 |
| [APK 签名校验逆向：用应用签名 SHA1 作为 XOR key 解密内置密文](mobile-android-apk-signature-sha1-xor-key-decrypt/) | verified | high | 2026-11-06 |
| [APK 长按隐藏 Activity + JNI 本地门校验与静态可逆解密](mobile-android-apk-native-gate-hidden-activity-decrypt/) | verified | high | 2026-11-06 |
| [App 请求 token 签名逆向：MD5(account+timestamp+sign) 与时间戳单位坑](mobile-android-token-md5-account-timestamp-sign-reverse/) | verified | high | 2026-11-06 |
| [DEX 结构手工解析：按 header 偏移定位 string/type/proto/field/method 与 class_defs](mobile-android-dex-format-manual-parse/) | verified | medium | 2026-11-07 |
| [Frida Hook Kotlin 协程 DelayKt.delay 绕过 96 小时时间锁](mobile-android-frida-kotlin-coroutine-delay-bypass/) | verified | high | 2026-11-06 |
| [Frida 直接启动未导出 Activity：加固 APP 隐藏功能与接口发现](mobile-android-frida-jump-internal-activity/) | verified | high | 2026-11-07 |
| [Frida 还原 APK 本地 HTTP 二阶段校验：精确 URI 与尾部 0x0a](mobile-android-frida-local-http-uri-check-recover/) | verified | high | 2026-11-06 |
| [MCP 辅助 Android App 验签逆向：ida-pro-mcp 还原排序拼接 + hooker 取 AES key + Flask autoDecoder 自动重签](mobile-android-mcp-assisted-sign-reverse-autodecoder/) | verified | high | 2026-11-06 |
| [Pixel 8 Android 16 APatch Root：按 Build 取 boot.img 修补、核对 slot 后 fastboot 刷入](mobile-android-pixel-apatch-root-boot-img-slot/) | verified | high | 2026-11-06 |
| [SagerNet 规则代理：禁用 IPv6/远程 DNS 后按域名/IP 分流，规避系统代理检测](mobile-android-sagernet-rule-proxy-avoid-system-proxy-detection/) | verified | high | 2026-11-06 |
| [Unity IL2CPP 手游免死改包：Frida-Gadget 脱机注入与 RestartStage→AutoRevival 重定向](mobile-android-unity-il2cpp-frida-gadget-infinite-revival/) | verified | high | 2026-11-05 |
| [严格 SSL pinning 下改用旧版 APK 并重写版本检测 API 抓包](mobile-android-ssl-pinning-downgrade-version-check-rewrite/) | verified | medium | 2026-11-06 |
| [仿冒公安网站投递 SpyNote RAT：无障碍服务窃取锁屏/金融/钱包凭据并阻止卸载](mobile-android-spynote-fake-police-accessibility-credential-theft/) | verified | high | 2026-11-05 |
| [伪装云盘 Android 间谍 APP 静态分析：随机包名 + 通讯录/短信/相册权限组合与 ContentResolver 窃取](mobile-android-spyware-clouddisk-contact-sms-photo-exfil/) | verified | high | 2026-11-06 |
| [恶意 APP C2 接口逆向：MD5(时间戳+硬编码盐) 签名 + 注册 userId + multipart 上传复现](mobile-android-c2-api-md5-salt-signature-replay/) | verified | high | 2026-11-06 |
| [短信验证码登录账户接管：双 MD5 手机号 token 伪造 + 无次数限制爆破 + 验证码重放](mobile-android-sms-login-code-bruteforce-replay/) | verified | high | 2026-11-06 |
| [第一代 DEX 加固：attachBaseContext 解密 assets dex 并反射替换 mClassLoader（脱壳点）](mobile-android-first-gen-dex-packer-attachbasecontext-classloader/) | verified | high | 2026-11-06 |
| [车联网 APK 蓝牙 VIN 加密逆向：Java 预变换 + native 变种 RC4 + BLE 流量解密](mobile-android-apk-ble-native-modified-rc4-vin/) | verified | high | 2026-11-06 |
| [随身 WiFi 暴露 adbd TCP 7628 + userdebug 构建免授权 root](mobile-android-adbd-tcp-userdebug-root/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
