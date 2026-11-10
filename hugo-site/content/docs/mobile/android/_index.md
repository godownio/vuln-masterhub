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
| [AhMyth Android RAT 样本静态剖析：ahmyth.mine.king.ahmyth 包结构、IOSocket 设备信息外链与七类 Manager 指令映射](mobile-android-ahmyth-rat-static-command-map/) | verified | high | 2026-11-09 |
| [Android 16 证书信任绕过：AlwaysTrustUserCerts 模块 + 重启生效](mobile-android-android16-certificate-trust-alwaystrustusercerts/) | verified | high | 2026-11-06 |
| [Android allowBackup=true + adb backup/restore：导出应用数据并恢复登录态](mobile-android-allowbackup-adb-backup-restore-account-takeover/) | verified | high | 2026-11-06 |
| [Android API sign 逆向：SHA-256 hex 重排 + AES-CBC 生成请求头签名](mobile-android-aes-cbc-sign-header-hash-rotate/) | verified | high | 2026-11-06 |
| [Android APK 字符串异或混淆批量还原：JADX 反编译 + 同构解密脚本正则替换](mobile-android-apk-xor-string-batch-deobfuscation/) | verified | high | 2026-11-05 |
| [Android APK 静态定位链路：Manifest launcher 入口 → onCreate → setContentView 资源 ID → 布局 onClick → 事件常量逆运算](mobile-android-apk-static-entry-layout-resource-locate/) | verified | high | 2026-11-08 |
| [Android APP 反检测环境：Shamiko/HideMyApplist/PlayIntegrityFork 与 iptables 透明代理绕过](mobile-android-anti-detection-root-emulator-proxy/) | verified | high | 2026-11-05 |
| [Android Content Provider projection/selection SQL 注入：Drozer 扫描后用 SQLITE_MASTER 枚举表并读取数据库](mobile-android-content-provider-projection-sql-injection-sqlite-master/) | verified | high | 2026-11-08 |
| [Android Content Provider 目录遍历：FileBackupProvider 任意文件读取与私有数据库下载](mobile-android-content-provider-path-traversal-file-read-db-download/) | verified | medium | 2026-11-08 |
| [Android JNI native 校验链模拟执行：ARM64 机器码常量提取 + Unicorn hook 调用](mobile-android-jni-native-unicorn-emulation-constant-extraction/) | verified | high | 2026-11-06 |
| [Android JNI 多层自定义加密逆向：运行时提取 XXTEA key + Block-TEA 变体 + AES S-box 8 轮白化](mobile-android-jni-xxtea-blocktea-aes-sbox-multilayer/) | verified | medium | 2026-11-07 |
| [Android libnesec.so Frida 反调试定位与线程替换绕过：dlopen/路径监控 + pthread_create 精准替换第一条线程](mobile-android-native-frida-antidebug-thread-bypass/) | verified | high | 2026-11-08 |
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
| [Android 加密参数由 JNI 函数生成时用 Frida hook 取密钥材料与预计算字符映射，跳过 so 静态逆向](mobile-android-frida-hook-native-key-material-precomputed-mapping/) | verified | high | 2026-11-08 |
| [Android 多关卡校验逆向：Frida dump 8 关 target + 逐关自定义变换/流水线逆运算](mobile-android-multilevel-checker-frida-transform-chain/) | verified | high | 2026-11-07 |
| [Android 应用 SQLCipher 数据库静态密钥还原：逆向 keyBase（MD5 前 6 位）解密应用数据库](mobile-android-sqlcipher-static-key-derivation/) | verified | high | 2026-11-06 |
| [Android 登录 codeSign 签名逆向与 Burp 自动重签：MD5(body+nonce+固定串+timestamp) 支撑账号爆破](mobile-android-login-codesign-md5-burp-auto-resign/) | verified | high | 2026-11-06 |
| [Android 组件导出：未登录启动 ChangePasswordActivity 用于钓鱼/未授权页面](mobile-android-exported-activity-unauth-changepassword-phishing/) | verified | high | 2026-11-06 |
| [Android 请求/响应 AES 解密：hook CryptoHelper.getKey 固定随机 key + 固定 IV 的 CBC/PKCS7+Base64](mobile-android-aes-random-key-hook-fixed-iv-decrypt/) | verified | high | 2026-11-06 |
| [Android 请求参数加密逆向：DES/ECB + MD5(str2+salt+时间窗) 密钥 + Base64](mobile-android-param-encryption-des-md5-timewindow/) | verified | high | 2026-11-06 |
| [Android 运行时密文提取与多层解密：frida-dexdump 脱壳 + Frida Hook 静态字段 + 复用应用内 RC4/AES](mobile-android-runtime-ciphertext-frida-dexdump-java-char-rc4-aes/) | verified | high | 2026-11-07 |
| [Android 远程协助 APK 的高权限远控链路识别：无障碍操控 + MediaProjection 录屏 + WebRTC 实时通道](mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc/) | verified | high | 2026-11-05 |
| [Android 银行木马短信拦截双通道外传：SMS_RECEIVED 广播解析 PDU，C2 下发转发号码用 SmsManager 转发并 JSON POST 回传](mobile-android-sms-received-forward-c2-number-banking-trojan/) | verified | medium | 2026-11-09 |
| [Android 防录屏绕过：LSPosed DisableFlagSecure 解除 FLAG_SECURE](mobile-android-disable-flag-secure-lsposed-screen-capture/) | verified | high | 2026-11-06 |
| [Android 风控 /proc/cpuinfo 检测与 Hook 对抗：伪造 CPU 型号/核心数绕过模拟器识别](mobile-android-cpuinfo-emulator-detection-hook-bypass/) | verified | high | 2026-11-06 |
| [APatch/KPM SyscallHook：sys_call_table 函数指针替换 + transit 链 before/after 回调](mobile-android-kpm-syscall-function-pointer-hook-transit/) | verified | high | 2026-11-06 |
| [APatch/KPM 内核 InlineHook：ARM64 trampoline、PC 相对重定位与页表改权限](mobile-android-kpm-inline-hook-arm64-trampoline-relocation/) | verified | high | 2026-11-06 |
| [APK 伪装 so 藏 dex：protobuf 登录伪造 + LCG XOR/RSA-AES 封装](mobile-android-apk-hidden-dex-protobuf-login-forge/) | verified | high | 2026-11-06 |
| [APK 改 versionName/versionCode 绕过强制更新：jadx 定位两处版本字段 + apktool 重打包 + keytool/jarsigner/zipalign 重签](mobile-android-apk-version-spoof-bypass-forced-update/) | verified | high | 2026-11-09 |
| [APK 签名校验逆向：用应用签名 SHA1 作为 XOR key 解密内置密文](mobile-android-apk-signature-sha1-xor-key-decrypt/) | verified | high | 2026-11-06 |
| [APK 补 android:debuggable="true" 重打包重签 + jadx/JDWP 附加：让依赖调试状态的应用输出隐藏逻辑](mobile-android-apk-debuggable-repack-jadx-attach/) | verified | high | 2026-11-08 |
| [APK 长按隐藏 Activity + JNI 本地门校验与静态可逆解密](mobile-android-apk-native-gate-hidden-activity-decrypt/) | verified | high | 2026-11-06 |
| [App _sign 逆向：TreeMap 参数 key+value 字典序拼接 + 固定 KEY_V2 首尾包裹 + MD5 大写](mobile-android-sign-treemap-salts-both-ends-md5-uppercase/) | verified | high | 2026-11-10 |
| [App udid 逆向：IMEI|nanoTime|deviceId 拼接后 3DES-CBC（JNI 返回固定 key + 固定 IV appapich）Base64](mobile-android-udid-3des-jni-key-hook-fixed-iv/) | verified | high | 2026-11-10 |
| [APP 强制更新弹窗绕过：jadx 按文案定位 UpdateDialog.show() 并用 Frida 覆盖实现](mobile-android-frida-hook-update-dialog-bypass/) | verified | high | 2026-11-09 |
| [App 请求 token 签名逆向：MD5(account+timestamp+sign) 与时间戳单位坑](mobile-android-token-md5-account-timestamp-sign-reverse/) | verified | high | 2026-11-06 |
| [Conscrypt 客户端私钥内存提取：Hook libconscrypt_jni.so 的 EVP_parse_private_key 与 Java 证书读取，导出 mTLS p12](mobile-android-conscrypt-native-client-key-extract/) | verified | high | 2026-11-08 |
| [DEX 结构手工解析：按 header 偏移定位 string/type/proto/field/method 与 class_defs](mobile-android-dex-format-manual-parse/) | verified | medium | 2026-11-07 |
| [Ermak（Ermac）Android 银行木马命令分发与能力映射：无障碍操控、录屏 VNC、USSD/短信/电话、凭据与 OTP 窃取](mobile-android-ermak-banking-trojan-command-dispatch-map/) | verified | medium | 2026-11-09 |
| [Frida Hook Kotlin 协程 DelayKt.delay 绕过 96 小时时间锁](mobile-android-frida-kotlin-coroutine-delay-bypass/) | verified | high | 2026-11-06 |
| [Frida 直接启动未导出 Activity：加固 APP 隐藏功能与接口发现](mobile-android-frida-jump-internal-activity/) | verified | high | 2026-11-07 |
| [Frida 还原 APK 本地 HTTP 二阶段校验：精确 URI 与尾部 0x0a](mobile-android-frida-local-http-uri-check-recover/) | verified | high | 2026-11-06 |
| [Frida 重写会员模型构造函数 $init：伪造 isVip/expireTime 字符串解锁客户端 VIP 状态](mobile-android-frida-vipinfo-constructor-forge-membership/) | verified | high | 2026-11-08 |
| [Hook 私有协议开关强制 Android App 从 SPDY 降级到 HTTP，绕过 Charles/Fiddler 抓不到的限制](mobile-android-frida-spdy-switch-disable-force-http-capture/) | verified | high | 2026-11-08 |
| [IDA 远程调试 Android .so：android_x86_server + adb forward + JEB 启动调试 + attach 进程](mobile-android-ida-remote-debug-so-x86-server/) | verified | high | 2026-11-08 |
| [JNI native 校验定位与逆运算：IDA Exports 找 Java_ 导出函数、提取 strcmp 目标串并按字符交换逆序还原](mobile-android-jni-native-strcmp-target-inverse/) | verified | high | 2026-11-08 |
| [JNI RegisterNatives 静态定位真实 native 函数：JNI_OnLoad → JNINativeMethod{name,signature,fnPtr}](mobile-android-jni-registernatives-static-real-function-locate/) | verified | high | 2026-11-08 |
| [MCP 辅助 Android App 验签逆向：ida-pro-mcp 还原排序拼接 + hooker 取 AES key + Flask autoDecoder 自动重签](mobile-android-mcp-assisted-sign-reverse-autodecoder/) | verified | high | 2026-11-06 |
| [Pixel 8 Android 16 APatch Root：按 Build 取 boot.img 修补、核对 slot 后 fastboot 刷入](mobile-android-pixel-apatch-root-boot-img-slot/) | verified | high | 2026-11-06 |
| [SagerNet 规则代理：禁用 IPv6/远程 DNS 后按域名/IP 分流，规避系统代理检测](mobile-android-sagernet-rule-proxy-avoid-system-proxy-detection/) | verified | high | 2026-11-06 |
| [smali 静态改会员判断 u()/a() 返回 true：重打包绕过客户端 VIP 校验解锁付费功能](mobile-android-smali-vip-check-force-true-repack/) | verified | high | 2026-11-10 |
| [SpyMax Android RAT：仿冒 Telegram 投递 + 无障碍服务键盘记录 + gzip over TCP 7771 下发命令/APK](mobile-android-spymax-telegram-phishing-accessibility-keylogger-gzip-c2/) | verified | high | 2026-11-08 |
| [unidbg 还原 so 签名 __ns_sig3：trace 反查缓冲 + CRC32 + 白盒 AES DFA + HMAC-SHA256](mobile-android-sig3-unidbg-trace-crc32-whitebox-aes-hmac/) | verified | medium | 2026-11-08 |
| [Unity IL2CPP 手游免死改包：Frida-Gadget 脱机注入与 RestartStage→AutoRevival 重定向](mobile-android-unity-il2cpp-frida-gadget-infinite-revival/) | verified | high | 2026-11-05 |
| [VirtualApp 类容器（Blackbox）无 root 欺骗 Android Framework 的机制与检测缺口](android-virtualapp-container-deception-and-detection-gaps/) | draft | medium | 2026-11-08 |
| [Windows 热点 + Netch TUN 网卡共享 + Reqable SOCKS 透明代理：连接设备无感抓包、规避 APP 代理/VPN 检测并兼作 WiFi 近源流量嗅探](mobile-android-windows-hotspot-netch-tun-reqable-transparent-proxy/) | verified | high | 2026-11-08 |
| [严格 SSL pinning 下改用旧版 APK 并重写版本检测 API 抓包](mobile-android-ssl-pinning-downgrade-version-check-rewrite/) | verified | medium | 2026-11-06 |
| [从 JNI getSign 还原请求签名：设备 ID 与入参异或混淆后拼固定串再做标准 MD5，签名库不校验则本地可复算](mobile-android-native-so-getsign-xor-devid-smiletozz-md5/) | verified | medium | 2026-11-08 |
| [仿冒公安网站投递 SpyNote RAT：无障碍服务窃取锁屏/金融/钱包凭据并阻止卸载](mobile-android-spynote-fake-police-accessibility-credential-theft/) | verified | high | 2026-11-05 |
| [伪装云盘 Android 间谍 APP 静态分析：随机包名 + 通讯录/短信/相册权限组合与 ContentResolver 窃取](mobile-android-spyware-clouddisk-contact-sms-photo-exfil/) | verified | high | 2026-11-06 |
| [加固 App 的 Frida 检测绕过的两条互补手法：Hook dlsym 把 pthread_create 换成空壳函数（让反调试线程根本不启动），或按 so 基址+固定偏移直接替换检测子函数](mobile-android-frida-antidebug-dlsym-fake-pthread-create-offset-patch/) | verified | medium | 2026-11-08 |
| [反射大师 + Xposed 脱第一代壳：夜神 Android 7.1.2 上从运行中 APP dump classes.dex 再用 jadx 审计](mobile-android-reflection-master-xposed-dex-dump/) | verified | high | 2026-11-08 |
| [反编译定位 isRootPhone() 并 Frida 覆盖 isRooted()/isSimulator() 绕过 root/模拟器检测弹窗](mobile-android-frida-hook-isrooted-issimulator-bypass/) | verified | high | 2026-11-09 |
| [导出 Activity 的 Intent 重定向 + WebView 未导出页 file:// 加载：Cookie 持久化存储型 XSS 借软链接外带](mobile-android-intent-redirect-webview-cookie-stored-xss-file-symlink/) | verified | high | 2026-11-08 |
| [嵌套 Intent 重定向 + FileProvider grantUriPermissions：借助受害者应用身份读取其私有目录文件](mobile-android-intent-redirection-fileprovider-grant-uri-private-file-read/) | verified | high | 2026-11-08 |
| [恶意 APK 同源家族溯源：硬编码 C2 路径复用 + 签名证书指纹比对（thumbprint/序列号/有效期/DN）+ 日志 TAG 聚类](mobile-android-apk-family-attribution-cert-c2-reuse/) | verified | medium | 2026-11-09 |
| [恶意 APP C2 接口逆向：MD5(时间戳+硬编码盐) 签名 + 注册 userId + multipart 上传复现](mobile-android-c2-api-md5-salt-signature-replay/) | verified | high | 2026-11-06 |
| [未知 native 签名逆向：hook 逐层收窄到哈希函数后与本地 MD5 对拍确认，再定位「仅一个时间戳变量 + 固定后缀」的 auth 生成式](mobile-android-native-sign-hash-identify-differential-md5-fixed-suffix/) | verified | medium | 2026-11-08 |
| [用 objection 追 Activity 触摸与启动日志定位开屏广告入口，再以 frida 伪造 MotionEvent 或强改广告请求开关布尔值跳过广告](mobile-android-objection-method-trace-frida-forged-motionevent-splash-ad-skip/) | verified | medium | 2026-11-09 |
| [短信验证码登录账户接管：双 MD5 手机号 token 伪造 + 无次数限制爆破 + 验证码重放](mobile-android-sms-login-code-bruteforce-replay/) | verified | high | 2026-11-06 |
| [第一代 DEX 加固：attachBaseContext 解密 assets dex 并反射替换 mClassLoader（脱壳点）](mobile-android-first-gen-dex-packer-attachbasecontext-classloader/) | verified | high | 2026-11-06 |
| [腾讯加固新闻类 App 的 st/sn 风控参数逆向：BlackDex 脱壳 + jadx 搜「sn=」定位混淆类 + hook bmz$a.a 打印闭包字段 + IDA 从 so 取出 readMD5Key 硬编码盐后复现 MD5 拼接](mobile-android-blackdex-tencent-packer-hook-bmz-native-md5-key-sign/) | verified | high | 2026-11-09 |
| [车联网 APK 蓝牙 VIN 加密逆向：Java 预变换 + native 变种 RC4 + BLE 流量解密](mobile-android-apk-ble-native-modified-rc4-vin/) | verified | high | 2026-11-06 |
| [逐字符独立加密的 Frida DFS 爆破：hook 结果对象 getter 按调用计数取中间值](mobile-android-frida-result-getter-callcount-dfs-char-bruteforce/) | verified | medium | 2026-11-08 |
| [重打包改 AndroidManifest 启动 Activity：跳过会员开通引导页直入主界面](mobile-android-apk-manifest-launcher-vip-charge-bypass/) | verified | high | 2026-11-10 |
| [随身 WiFi 暴露 adbd TCP 7628 + userdebug 构建免授权 root](mobile-android-adbd-tcp-userdebug-root/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
