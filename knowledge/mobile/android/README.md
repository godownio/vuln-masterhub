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
| [360 加固 APK 脱壳：PKID 查壳 + FunDex/LSPosed dump（frida-dexdump 被检测时的替代）](mobile-android-360-hardening-fundex-lsposed-dump.md) | verified | high | 2026-11-06 |
| [AhMyth Android RAT 样本静态剖析：ahmyth.mine.king.ahmyth 包结构、IOSocket 设备信息外链与七类 Manager 指令映射](mobile-android-ahmyth-rat-static-command-map.md) | verified | high | 2026-11-09 |
| [Android 16 证书信任绕过：AlwaysTrustUserCerts 模块 + 重启生效](mobile-android-android16-certificate-trust-alwaystrustusercerts.md) | verified | high | 2026-11-06 |
| [Android 7+ 手工把 Burp CA 注入系统证书目录：openssl subject_hash_old 命名 + adb push cacerts](mobile-android-system-cacerts-openssl-subject-hash-push.md) | verified | high | 2026-11-12 |
| [Android allowBackup=true + adb backup/restore：导出应用数据并恢复登录态](mobile-android-allowbackup-adb-backup-restore-account-takeover.md) | verified | high | 2026-11-06 |
| [Android API sign 逆向：SHA-256 hex 重排 + AES-CBC 生成请求头签名](mobile-android-aes-cbc-sign-header-hash-rotate.md) | verified | high | 2026-11-06 |
| [Android APK 字符串异或混淆批量还原：JADX 反编译 + 同构解密脚本正则替换](mobile-android-apk-xor-string-batch-deobfuscation.md) | verified | high | 2026-11-05 |
| [Android APK 源码级免杀：自建工程重实现 meterpreter loader、改写启动与代码风格并裁剪 Manifest 元数据绕过静态查杀](mobile-android-apk-source-level-av-evasion-meterpreter-loader.md) | verified | medium | 2026-11-13 |
| [Android APK 静态定位链路：Manifest launcher 入口 → onCreate → setContentView 资源 ID → 布局 onClick → 事件常量逆运算](mobile-android-apk-static-entry-layout-resource-locate.md) | verified | high | 2026-11-08 |
| [Android APP 反检测环境：Shamiko/HideMyApplist/PlayIntegrityFork 与 iptables 透明代理绕过](mobile-android-anti-detection-root-emulator-proxy.md) | verified | high | 2026-11-05 |
| [Android Content Provider projection/selection SQL 注入：Drozer 扫描后用 SQLITE_MASTER 枚举表并读取数据库](mobile-android-content-provider-projection-sql-injection-sqlite-master.md) | verified | high | 2026-11-08 |
| [Android Content Provider 目录遍历：FileBackupProvider 任意文件读取与私有数据库下载](mobile-android-content-provider-path-traversal-file-read-db-download.md) | verified | medium | 2026-11-08 |
| [Android JNI native 校验链模拟执行：ARM64 机器码常量提取 + Unicorn hook 调用](mobile-android-jni-native-unicorn-emulation-constant-extraction.md) | verified | high | 2026-11-06 |
| [Android JNI 多层自定义加密逆向：运行时提取 XXTEA key + Block-TEA 变体 + AES S-box 8 轮白化](mobile-android-jni-xxtea-blocktea-aes-sbox-multilayer.md) | verified | medium | 2026-11-07 |
| [Android libnesec.so Frida 反调试定位与线程替换绕过：dlopen/路径监控 + pthread_create 精准替换第一条线程](mobile-android-native-frida-antidebug-thread-bypass.md) | verified | high | 2026-11-08 |
| [Android mTLS BKS 客户端证书抓包：Hook KeyStore.load 导出密码与真实密钥流十六进制，BKS 转 PKCS#12 导入 Burp](mobile-android-mtls-bks-keystore-load-hex-dump-keystore-explorer.md) | verified | high | 2026-11-13 |
| [Android mTLS 双向认证抓包：r0capture 从应用层导出客户端 p12 并导入 Burp/Reqable](mobile-android-mtls-r0capture-client-cert-export.md) | verified | high | 2026-11-06 |
| [Android Native 手动栈回溯：__builtin_frame_address 沿 FP 链遍历 + dladdr 符号化，及 ART/JNI 帧 FP/LR 对位于 SP+0x20 与 -fomit-frame-pointer 断链](mobile-android-native-fp-chain-manual-backtrace-dladdr.md) | verified | high | 2026-11-13 |
| [Android OkHttp 自定义请求头定位：hook addHeader 堆栈 + native calSign 的路径/时间戳/JSON/key 拼接 MD5](mobile-android-okhttp-addheader-stack-native-sign-locate.md) | verified | high | 2026-11-06 |
| [Android SSL Pinning 绕过：系统证书迁移 + TrustMe/objection/自定义 Frida 脚本](mobile-android-ssl-pinning-bypass-cert-frida.md) | verified | high | 2026-11-05 |
| [Android WebView JSBridge 任意页面凭证窃取：exported ProxyActivity 路由 + 无域名校验 WebView + 全局 handler 注册表](mobile-android-webview-jsbridge-arbitrary-origin-credential-theft.md) | verified | high | 2026-11-06 |
| [Android WebView 开启 file 协议通用访问：恶意 file:// 页面跨域读取私有目录与本地文件](mobile-android-webview-file-universal-access-local-read.md) | verified | medium | 2026-11-06 |
| [Android Zygote ptrace 注入：ARM32 shellcode dlopen SO，fork 后全应用继承](mobile-android-zygote-ptrace-dlopen-injection.md) | verified | high | 2026-11-06 |
| [Android 二代壳静态脱壳：从 libshell.so 按偏移 carve 内嵌 ELF，恢复 JNI setData/ihk/test 实现](mobile-android-shell-so-embedded-elf-carve-extract-dat.md) | verified | medium | 2026-11-07 |
| [Android 免费影视应用借 bandwidth monetizer SDK 将设备变为住宅代理节点](mobile-android-bandwidth-monetizer-sdk-residential-proxy.md) | verified | high | 2026-11-05 |
| [Android 加固 APK 查壳与脱壳：APKiD 识别 + frida-dexdump 内存 dump + jadx/apktool 审计](mobile-android-packer-apkid-frida-dexdump-jadx.md) | verified | high | 2026-11-05 |
| [Android 加密 so 运行时解密/dlopen：从 /data/data 提取解密后的 .so 逆向 TEA 校验](mobile-android-encrypted-so-runtime-dlopen-extraction.md) | verified | high | 2026-11-06 |
| [Android 加密参数由 JNI 函数生成时用 Frida hook 取密钥材料与预计算字符映射，跳过 so 静态逆向](mobile-android-frida-hook-native-key-material-precomputed-mapping.md) | verified | high | 2026-11-08 |
| [Android 国密流量解密：patch so 将 SM2 包裹的 SM4 随机 key 固定为 32 个 A 后 ECB 解密](mobile-android-sm2-sm4-sm3-native-key-patch-fixed-traffic-decrypt.md) | verified | high | 2026-11-12 |
| [Android 多关卡校验逆向：Frida dump 8 关 target + 逐关自定义变换/流水线逆运算](mobile-android-multilevel-checker-frida-transform-chain.md) | verified | high | 2026-11-07 |
| [Android 子进程 ptrace 占坑反 Frida：spawn 模式先注入再 %resume 绕过](mobile-android-frida-ptrace-slot-antidebug-spawn-resume.md) | verified | high | 2026-11-12 |
| [Android 导出深链 Activity 加载任意 URL：homeassistant://navigate 进入 WebView，externalApp.getExternalAuth 的 callback 被拼进 evaluateJavascript 窃取令牌](mobile-android-exported-deeplink-webview-externalauth-callback-xss.md) | verified | high | 2026-11-11 |
| [Android 应用 SQLCipher 数据库静态密钥还原：逆向 keyBase（MD5 前 6 位）解密应用数据库](mobile-android-sqlcipher-static-key-derivation.md) | verified | high | 2026-11-06 |
| [Android 支付结果客户端校验绕过：jadx 定位 PayTask 返回码 9000 判断，smali 赋值 9000 或反转 if-eqz 免支付购买](mobile-android-payment-result-code-client-check-bypass.md) | verified | high | 2026-11-13 |
| [Android 登录 codeSign 签名逆向与 Burp 自动重签：MD5(body+nonce+固定串+timestamp) 支撑账号爆破](mobile-android-login-codesign-md5-burp-auto-resign.md) | verified | high | 2026-11-06 |
| [Android 组件导出：未登录启动 ChangePasswordActivity 用于钓鱼/未授权页面](mobile-android-exported-activity-unauth-changepassword-phishing.md) | verified | high | 2026-11-06 |
| [Android 自定义加固：assets 中 dex 被改 magic（naga→dex\n），运行时修复落盘 .cache 后直接拉取](mobile-android-assets-dex-magic-naga-repatch-cache-dump.md) | verified | high | 2026-11-12 |
| [Android 请求/响应 AES 解密：hook CryptoHelper.getKey 固定随机 key + 固定 IV 的 CBC/PKCS7+Base64](mobile-android-aes-random-key-hook-fixed-iv-decrypt.md) | verified | high | 2026-11-06 |
| [Android 请求参数加密逆向：DES/ECB + MD5(str2+salt+时间窗) 密钥 + Base64](mobile-android-param-encryption-des-md5-timewindow.md) | verified | high | 2026-11-06 |
| [Android 运行时密文提取与多层解密：frida-dexdump 脱壳 + Frida Hook 静态字段 + 复用应用内 RC4/AES](mobile-android-runtime-ciphertext-frida-dexdump-java-char-rc4-aes.md) | verified | high | 2026-11-07 |
| [Android 远程协助 APK 的高权限远控链路识别：无障碍操控 + MediaProjection 录屏 + WebRTC 实时通道](mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc.md) | verified | high | 2026-11-05 |
| [Android 银行木马短信拦截双通道外传：SMS_RECEIVED 广播解析 PDU，C2 下发转发号码用 SmsManager 转发并 JSON POST 回传](mobile-android-sms-received-forward-c2-number-banking-trojan.md) | verified | medium | 2026-11-09 |
| [Android 防录屏绕过：LSPosed DisableFlagSecure 解除 FLAG_SECURE](mobile-android-disable-flag-secure-lsposed-screen-capture.md) | verified | high | 2026-11-06 |
| [Android 风控 /proc/cpuinfo 检测与 Hook 对抗：伪造 CPU 型号/核心数绕过模拟器识别](mobile-android-cpuinfo-emulator-detection-hook-bypass.md) | verified | high | 2026-11-06 |
| [AndroidManifest 二进制 AXML 加固修复：魔改 magic/stylesStart/stringCount 后用 010Editor 模板与 AXMLPrinter2 报错逐字段还原](mobile-android-axml-manifest-hardening-repair.md) | verified | medium | 2026-11-13 |
| [Anubis Android 银行木马命令映射：del_sws/Send_GO_SMS/startaccessibility/startrat/startforward 等指令与 /olo/a1.php、/olo/a2.php C2 协议](mobile-android-anubis-banker-command-map.md) | verified | high | 2026-11-13 |
| [AOSP 8 源码级 root 隐藏：su 改名（fs_config/file_contexts 同步）+ 构建指纹 test-keys/userdebug 去除 + adb root 固化](mobile-android-aosp-root-detection-evasion-su-rename-build-fingerprint-adb-root.md) | verified | medium | 2026-11-13 |
| [APatch/KPM SyscallHook：sys_call_table 函数指针替换 + transit 链 before/after 回调](mobile-android-kpm-syscall-function-pointer-hook-transit.md) | verified | high | 2026-11-06 |
| [APatch/KPM 内核 InlineHook：ARM64 trampoline、PC 相对重定位与页表改权限](mobile-android-kpm-inline-hook-arm64-trampoline-relocation.md) | verified | high | 2026-11-06 |
| [APK 伪装 so 藏 dex：protobuf 登录伪造 + LCG XOR/RSA-AES 封装](mobile-android-apk-hidden-dex-protobuf-login-forge.md) | verified | high | 2026-11-06 |
| [APK 改 versionName/versionCode 绕过强制更新：jadx 定位两处版本字段 + apktool 重打包 + keytool/jarsigner/zipalign 重签](mobile-android-apk-version-spoof-bypass-forced-update.md) | verified | high | 2026-11-09 |
| [APK 签名校验逆向：用应用签名 SHA1 作为 XOR key 解密内置密文](mobile-android-apk-signature-sha1-xor-key-decrypt.md) | verified | high | 2026-11-06 |
| [APK 补 android:debuggable="true" 重打包重签 + jadx/JDWP 附加：让依赖调试状态的应用输出隐藏逻辑](mobile-android-apk-debuggable-repack-jadx-attach.md) | verified | high | 2026-11-08 |
| [APK 长按隐藏 Activity + JNI 本地门校验与静态可逆解密](mobile-android-apk-native-gate-hidden-activity-decrypt.md) | verified | high | 2026-11-06 |
| [APKiD 壳检测机制：is_apk 通用规则 + 壳特征文件 Yara 规则 + zip 成员二次扫描，可自写规则扩充加固识别](mobile-android-apkid-yara-rule-packer-detection-mechanism.md) | verified | high | 2026-11-13 |
| [App _sign 逆向：TreeMap 参数 key+value 字典序拼接 + 固定 KEY_V2 首尾包裹 + MD5 大写](mobile-android-sign-treemap-salts-both-ends-md5-uppercase.md) | verified | high | 2026-11-10 |
| [App udid 逆向：IMEI|nanoTime|deviceId 拼接后 3DES-CBC（JNI 返回固定 key + 固定 IV appapich）Base64](mobile-android-udid-3des-jni-key-hook-fixed-iv.md) | verified | high | 2026-11-10 |
| [APP 强制更新弹窗绕过：jadx 按文案定位 UpdateDialog.show() 并用 Frida 覆盖实现](mobile-android-frida-hook-update-dialog-bypass.md) | verified | high | 2026-11-09 |
| [App 请求 token 签名逆向：MD5(account+timestamp+sign) 与时间戳单位坑](mobile-android-token-md5-account-timestamp-sign-reverse.md) | verified | high | 2026-11-06 |
| [AXML 单字节 fuzz 反编译对抗：改 String Offsets 为越界下标，apktool/jadx 崩在 ArrayIndexOutOfBounds 而 APK 仍可安装运行](mobile-android-axml-byte-fuzz-antidecompile.md) | verified | high | 2026-11-13 |
| [BB/SecShell 加固 APK 脱壳后修复重打包：BlackDex 取真实 dex + NP 修复 + 改回 MyApplication 入口 + 删 appComponentFactory + 去 SecShell 特征重签](mobile-android-blackdex-secshell-unpack-entry-repair-repack.md) | verified | high | 2026-11-12 |
| [Bitter APT Android 远控样本 photos.apk 分析：无图标隐藏、伪装弹框、九类数据收集写入 systemservice 并 POST 上传](mobile-android-bitter-photos-apk-rat-multisource-exfil.md) | verified | high | 2026-11-11 |
| [Conscrypt 客户端私钥内存提取：Hook libconscrypt_jni.so 的 EVP_parse_private_key 与 Java 证书读取，导出 mTLS p12](mobile-android-conscrypt-native-client-key-extract.md) | verified | high | 2026-11-08 |
| [DEX 结构手工解析：按 header 偏移定位 string/type/proto/field/method 与 class_defs](mobile-android-dex-format-manual-parse.md) | verified | medium | 2026-11-07 |
| [DroidJack/SandroRat Android RAT（net.droidjack.server）静态命令映射：Controller 模块覆盖短信、通讯录、通话记录、WhatsApp 数据库 su 拷贝、应用列表与屏幕开关](mobile-android-droidjack-sandrorat-controller-module-command-map.md) | verified | medium | 2026-11-11 |
| [Ermak（Ermac）Android 银行木马命令分发与能力映射：无障碍操控、录屏 VNC、USSD/短信/电话、凭据与 OTP 窃取](mobile-android-ermak-banking-trojan-command-dispatch-map.md) | verified | medium | 2026-11-09 |
| [Frida Hook Kotlin 协程 DelayKt.delay 绕过 96 小时时间锁](mobile-android-frida-kotlin-coroutine-delay-bypass.md) | verified | high | 2026-11-06 |
| [Frida 直接启动未导出 Activity：加固 APP 隐藏功能与接口发现](mobile-android-frida-jump-internal-activity.md) | verified | high | 2026-11-07 |
| [Frida 还原 APK 本地 HTTP 二阶段校验：精确 URI 与尾部 0x0a](mobile-android-frida-local-http-uri-check-recover.md) | verified | high | 2026-11-06 |
| [Frida 重写会员模型构造函数 $init：伪造 isVip/expireTime 字符串解锁客户端 VIP 状态](mobile-android-frida-vipinfo-constructor-forge-membership.md) | verified | high | 2026-11-08 |
| [Hook 私有协议开关强制 Android App 从 SPDY 降级到 HTTP，绕过 Charles/Fiddler 抓不到的限制](mobile-android-frida-spdy-switch-disable-force-http-capture.md) | verified | high | 2026-11-08 |
| [HttpCanary 静态注入改 /inner/user/member 响应：is_vip 等字段改 true 解锁客户端会员状态](mobile-android-httpcanary-static-injection-member-response.md) | verified | high | 2026-11-12 |
| [Hybrid APK assets/www H5 资源泄露 AES-CBC 密钥与隐藏 method 接口：篡改 method + org_id 遍历员工 PII](mobile-android-hybrid-apk-assets-www-js-aes-key-method-idor-enumeration.md) | verified | high | 2026-11-11 |
| [IDA 远程调试 Android .so：android_x86_server + adb forward + JEB 启动调试 + attach 进程](mobile-android-ida-remote-debug-so-x86-server.md) | verified | high | 2026-11-08 |
| [JNI native 校验定位与逆运算：IDA Exports 找 Java_ 导出函数、提取 strcmp 目标串并按字符交换逆序还原](mobile-android-jni-native-strcmp-target-inverse.md) | verified | high | 2026-11-08 |
| [JNI RegisterNatives 静态定位真实 native 函数：JNI_OnLoad → JNINativeMethod{name,signature,fnPtr}](mobile-android-jni-registernatives-static-real-function-locate.md) | verified | high | 2026-11-08 |
| [Joker 家族 Beauty Wallpaper HD 与其 DEX 衍生物剖析：远程指令驱动 WebView 自动订阅，JavascriptInterface 暴露短信收发删与自定义 HTTP](mobile-android-joker-beauty-wallpaper-dex-webview-sms.md) | verified | high | 2026-11-13 |
| [MCP 辅助 Android App 验签逆向：ida-pro-mcp 还原排序拼接 + hooker 取 AES key + Flask autoDecoder 自动重签](mobile-android-mcp-assisted-sign-reverse-autodecoder.md) | verified | high | 2026-11-06 |
| [mPaaS RPC 签名抓取：hook RpcSignUtil.signature 打印待签明文，配合 RpcInvoker.a 取 Request-Data 并 Base64 解码](mobile-android-mpaas-rpcsignutil-signature-request-data-hook.md) | verified | medium | 2026-11-12 |
| [Pixel 8 Android 16 APatch Root：按 Build 取 boot.img 修补、核对 slot 后 fastboot 刷入](mobile-android-pixel-apatch-root-boot-img-slot.md) | verified | high | 2026-11-06 |
| [SagerNet 规则代理：禁用 IPv6/远程 DNS 后按域名/IP 分流，规避系统代理检测](mobile-android-sagernet-rule-proxy-avoid-system-proxy-detection.md) | verified | high | 2026-11-06 |
| [smali 反转 SharedPreferences 登录标志判断：if-nez 改 if-eqz 批量改点跳过客户端登录门禁](mobile-android-smali-isuserlogin-flag-branch-invert-bypass.md) | verified | high | 2026-11-13 |
| [smali 改 VIP 字段 vip_grade="1" 解锁会员：setter 参数寄存器 p1 与 const-string p/v 陷阱](mobile-android-smali-vip-grade-field-setter-patch-register.md) | verified | medium | 2026-11-13 |
| [smali 改比较分支并给寄存器赋期望常量：if-ne 改 if-eq 绕过客户端输入相等校验](mobile-android-smali-branch-invert-expected-constant-bypass.md) | verified | high | 2026-11-12 |
| [smali 静态 Log 插桩：插入 Log.d 打印关键寄存器值并用 logcat 过滤观察（注意寄存器冲突）](mobile-android-smali-log-instrumentation-register-logcat.md) | verified | high | 2026-11-12 |
| [smali 静态改会员判断 u()/a() 返回 true：重打包绕过客户端 VIP 校验解锁付费功能](mobile-android-smali-vip-check-force-true-repack.md) | verified | high | 2026-11-10 |
| [SpyMax Android RAT：仿冒 Telegram 投递 + 无障碍服务键盘记录 + gzip over TCP 7771 下发命令/APK](mobile-android-spymax-telegram-phishing-accessibility-keylogger-gzip-c2.md) | verified | high | 2026-11-08 |
| [uni-app 应用抓包：WWW 资源识别框架，Frida Hook OkHttp RequestBody/RealCall 打印明文报文，JS 侧定位 app-config/app-service 加密或 Chrome USB 调试 H5](mobile-android-uniapp-traffic-capture-okhttp-hook-encryption-locate.md) | verified | medium | 2026-11-13 |
| [Unidbg 调用动态注册 JNI：Frida hook RegisterNatives 定位 so + AbstractJni 补环境（getAndroidId/getSafeDeviceId/Build.MODEL）](mobile-android-unidbg-dynamic-jni-registernatives-abstractjni.md) | verified | medium | 2026-11-12 |
| [unidbg 还原 so 签名 __ns_sig3：trace 反查缓冲 + CRC32 + 白盒 AES DFA + HMAC-SHA256](mobile-android-sig3-unidbg-trace-crc32-whitebox-aes-hmac.md) | verified | medium | 2026-11-08 |
| [Unidbg 黑盒调用 JNI 静态注册方法解 CTF：resolveClass + callJniMethod 直接跑 j/p/init 求 flag](mobile-android-unidbg-jni-static-method-blackbox-call.md) | verified | high | 2026-11-12 |
| [Unity IL2CPP 手游免死改包：Frida-Gadget 脱机注入与 RestartStage→AutoRevival 重定向](mobile-android-unity-il2cpp-frida-gadget-infinite-revival.md) | verified | high | 2026-11-05 |
| [VirtualApp 类容器（Blackbox）无 root 欺骗 Android Framework 的机制与检测缺口](android-virtualapp-container-deception-and-detection-gaps.md) | draft | medium | 2026-11-08 |
| [Windows 热点 + Netch TUN 网卡共享 + Reqable SOCKS 透明代理：连接设备无感抓包、规避 APP 代理/VPN 检测并兼作 WiFi 近源流量嗅探](mobile-android-windows-hotspot-netch-tun-reqable-transparent-proxy.md) | verified | high | 2026-11-08 |
| [严格 SSL pinning 下改用旧版 APK 并重写版本检测 API 抓包](mobile-android-ssl-pinning-downgrade-version-check-rewrite.md) | verified | medium | 2026-11-06 |
| [从 JNI getSign 还原请求签名：设备 ID 与入参异或混淆后拼固定串再做标准 MD5，签名库不校验则本地可复算](mobile-android-native-so-getsign-xor-devid-smiletozz-md5.md) | verified | medium | 2026-11-08 |
| [仿冒公安网站投递 SpyNote RAT：无障碍服务窃取锁屏/金融/钱包凭据并阻止卸载](mobile-android-spynote-fake-police-accessibility-credential-theft.md) | verified | high | 2026-11-05 |
| [伪装云盘 Android 间谍 APP 静态分析：随机包名 + 通讯录/短信/相册权限组合与 ContentResolver 窃取](mobile-android-spyware-clouddisk-contact-sms-photo-exfil.md) | verified | high | 2026-11-06 |
| [加固 App 的 Frida 检测绕过的两条互补手法：Hook dlsym 把 pthread_create 换成空壳函数（让反调试线程根本不启动），或按 so 基址+固定偏移直接替换检测子函数](mobile-android-frida-antidebug-dlsym-fake-pthread-create-offset-patch.md) | verified | medium | 2026-11-08 |
| [反射大师 + Xposed 脱第一代壳：夜神 Android 7.1.2 上从运行中 APP dump classes.dex 再用 jadx 审计](mobile-android-reflection-master-xposed-dex-dump.md) | verified | high | 2026-11-08 |
| [反编译定位 isRootPhone() 并 Frida 覆盖 isRooted()/isSimulator() 绕过 root/模拟器检测弹窗](mobile-android-frida-hook-isrooted-issimulator-bypass.md) | verified | high | 2026-11-09 |
| [启动广告去除：SplashAdActivity 组合布尔导航条件短路验证 + smali 双条件改真直入主界面](mobile-android-splash-ad-navigation-boolean-gate-shortcircuit-repack.md) | verified | high | 2026-11-12 |
| [多广告 Activity 跳过：把 position >= data.size() 播放结束判断取反，首条广告即跳转 MainActivity](mobile-android-ad-activity-bounds-check-invert-skip.md) | verified | medium | 2026-11-13 |
| [导出 Activity 的 Intent 重定向 + WebView 未导出页 file:// 加载：Cookie 持久化存储型 XSS 借软链接外带](mobile-android-intent-redirect-webview-cookie-stored-xss-file-symlink.md) | verified | high | 2026-11-08 |
| [嵌套 Intent 重定向 + FileProvider grantUriPermissions：借助受害者应用身份读取其私有目录文件](mobile-android-intent-redirection-fileprovider-grant-uri-private-file-read.md) | verified | high | 2026-11-08 |
| [广告 Fragment 自动弹窗去除：布局查看器反查资源 id + smali onViewCreated/onCreate 插入 return-void](mobile-android-apk-ad-fragment-return-void-disable.md) | verified | high | 2026-11-12 |
| [强制更新弹窗取消按钮禁用绕过：定位 UpdateAppDialog 布尔设置函数 + Frida 强制 true / smali 去 xor 取反](mobile-android-update-dialog-cancel-button-boolean-bypass.md) | verified | high | 2026-11-12 |
| [恶意 APK 同源家族溯源：硬编码 C2 路径复用 + 签名证书指纹比对（thumbprint/序列号/有效期/DN）+ 日志 TAG 聚类](mobile-android-apk-family-attribution-cert-c2-reuse.md) | verified | medium | 2026-11-09 |
| [恶意 APP C2 接口逆向：MD5(时间戳+硬编码盐) 签名 + 注册 userId + multipart 上传复现](mobile-android-c2-api-md5-salt-signature-replay.md) | verified | high | 2026-11-06 |
| [手游实名认证客户端门禁绕过：改 isVerified 分支与 RidCheck 回调布尔值后重打包](mobile-android-realname-antiaddiction-smali-bypass.md) | verified | medium | 2026-11-12 |
| [未知 native 签名逆向：hook 逐层收窄到哈希函数后与本地 MD5 对拍确认，再定位「仅一个时间戳变量 + 固定后缀」的 auth 生成式](mobile-android-native-sign-hash-identify-differential-md5-fixed-suffix.md) | verified | medium | 2026-11-08 |
| [本地存档型手游金币/钻石修改：改 getCoins 返回值或 loadStore 赋值后重打包重签](mobile-android-local-save-currency-smali-patch-repack.md) | verified | high | 2026-11-12 |
| [用 objection 追 Activity 触摸与启动日志定位开屏广告入口，再以 frida 伪造 MotionEvent 或强改广告请求开关布尔值跳过广告](mobile-android-objection-method-trace-frida-forged-motionevent-splash-ad-skip.md) | verified | medium | 2026-11-09 |
| [短信验证码登录账户接管：双 MD5 手机号 token 伪造 + 无次数限制爆破 + 验证码重放](mobile-android-sms-login-code-bruteforce-replay.md) | verified | high | 2026-11-06 |
| [第一代 DEX 加固：attachBaseContext 解密 assets dex 并反射替换 mClassLoader（脱壳点）](mobile-android-first-gen-dex-packer-attachbasecontext-classloader.md) | verified | high | 2026-11-06 |
| [第一代 DEX 落地壳变体：加密 APK 附加到 classes.dex 尾部（末 4 字节长度）并修正 checksum/signature/file_size，运行时解密加载](mobile-android-first-gen-dex-shell-apk-tail-append-header-fix.md) | verified | medium | 2026-11-12 |
| [算法助手（Xposed）隐藏 WiFi 代理/VPN 状态 + 关键词屏蔽检测弹窗，绕过手游反抓包并抓到实名请求](mobile-android-algorithm-aide-hide-proxy-vpn-dialog-block.md) | verified | medium | 2026-11-12 |
| [腾讯加固新闻类 App 的 st/sn 风控参数逆向：BlackDex 脱壳 + jadx 搜「sn=」定位混淆类 + hook bmz$a.a 打印闭包字段 + IDA 从 so 取出 readMD5Key 硬编码盐后复现 MD5 拼接](mobile-android-blackdex-tencent-packer-hook-bmz-native-md5-key-sign.md) | verified | high | 2026-11-09 |
| [腾讯御安全（StubShell）加固 APK 脱壳回填：BlackDex dump + dex 修复改名 + WrapperProxyApplication 真实入口替换 + 壳特征清理](mobile-android-blackdex-tencent-yushan-stubshell-unpack-repack.md) | verified | high | 2026-11-12 |
| [车联网 APK 蓝牙 VIN 加密逆向：Java 预变换 + native 变种 RC4 + BLE 流量解密](mobile-android-apk-ble-native-modified-rc4-vin.md) | verified | high | 2026-11-06 |
| [逐字符独立加密的 Frida DFS 爆破：hook 结果对象 getter 按调用计数取中间值](mobile-android-frida-result-getter-callcount-dfs-char-bruteforce.md) | verified | medium | 2026-11-08 |
| [重打包后「请使用官方APP」检测绕过：jadx 定位 MainActivity.checkPackage，注释调用或对 if 取反](mobile-android-repackage-signature-package-check-bypass.md) | verified | high | 2026-11-13 |
| [重打包改 AndroidManifest 启动 Activity：跳过会员开通引导页直入主界面](mobile-android-apk-manifest-launcher-vip-charge-bypass.md) | verified | high | 2026-11-10 |
| [随身 WiFi 暴露 adbd TCP 7628 + userdebug 构建免授权 root](mobile-android-adbd-tcp-userdebug-root.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
