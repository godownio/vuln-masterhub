---
id: android-virtualapp-container-deception-and-detection-gaps
title: VirtualApp 类容器（Blackbox）无 root 欺骗 Android Framework 的机制与检测缺口
type: scenario
domain: mobile
path: mobile/android
technique: 系统服务代理 + Stub 占坑 Intent 替换 + IO/Binder/ClassLoader Hook
aliases:
- VirtualApp 原理
- 容器多开欺骗
- Blackbox sandbox
tags:
- android
- virtualapp
- sandbox
- hook
- io-redirect
- detection
severity: medium
confidence: medium
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

# 一句话结论

VirtualApp/Blackbox 类 Android 容器通过代理系统服务、Manifest 占坑 Stub 组件并替换 Intent、native 层 IO 重定向与 Binder getCallingUid 欺骗，在无 root 条件下让系统与应用互相"以为已安装"，可被恶意应用用于多开、隐藏运行环境与伪造身份；其实现存在可检测缺口（libc open/stat 未 Hook、seccomp 易探测、cmdline 可交叉验证）。

# 原理

- 三层协作：Java 层 Hook（ pine 框架反射替换单例）、Framework 层代理（BActivityManagerService 等自建 VA Framework）、Native 层（IO 重定向 + JNI hook）。
- 服务代理：宿主在黑进程/服务进程内通过 HookManager 注入数十个 Proxy（IActivityManagerProxy、IPackageManagerProxy 等），以 BlackReflection 替换 ActivityManager.Oreo.IActivityManagerSingleton/gDefault 的 mInstance；VAPP 的请求参数先被改成宿主身份发给真 AMS，返回结果再还原为 VAPP 信息。自建服务（BActivityManagerService 等）经 SystemCallProvider 的 `call("VM")` 以 Binder 暴露。
- 组件欺骗：Manifest 预注册 50 个 `ProxyActivity$P0..P49`（及 ProxyService、ProxyContentProvider）占坑；启动容器内应用时构造指向占坑组件的 shadow Intent（携带 ProxyActivityRecord），AMS 按合法流程启动 Stub；客户端侧 `ActivityThread.H.mCallback` 被 HCallbackProxy 替换，在 EXECUTE_TRANSACTION/LAUNCH_ACTIVITY 消息中把 LaunchActivityItem 的 mIntent/mInfo 改回真实目标，再交还原 callback 执行，于是加载的是目标 APK 的类与资源。
- 进程与身份：每个 bpid 对应一个 `:pN` 进程；`handleBindApplication` 中替换 LoadedApk.mApplicationInfo/mSecurityViolation、setupRuntime 改进程名、makeApplication 构建目标 Application；`Binder.getCallingUid` 被JNI hook，容器宿主 UID 被换算回容器内应用 buid。
- IO 重定向：规则（/data/data/<pkg> → 容器内 dataDir、/proc/self/cmdline → 伪造文件、/sdcard/Android → 容器外部目录）注册进 Trie 树并同步 NativeCore；通过 RegisterNatives 替换 `java/io/UnixFileSystem` 的 canonicalize0/getBooleanAttributes0/list0 等 JNI 函数，路径先过 redirectPath 再调原函数。
- 隐匿：VMClassLoader.findLoadedClass hook 依据 `de/robv/android/xposed/`、`me/weishu/epic` 等名单返回 null 隐藏 Xposed；`isHideRoot` 时重定向 su 等路径。
- Xposed 兼容：在 AppInstrumentation.newApplication 时机（进程已建、应用未跑）loadXposed——用 pine 对 XposedHelpers/XposedBridge 的 API 做自 hook 后调用模块的 handleLoadPackage，无需注入 Zygote。
- seccomp 扩展：Blackbox 另用 BPF 过滤 openat（args[4]==SECMAGIC 判断是否已处理），SIGSYS 回调中改寄存器后重放系统调用，实现系统调用层拦截。

# 触发条件

- 攻击场景：恶意/灰色应用以 VirtualApp 类容器为宿主分发，用户安装宿主 APK 后其中运行的应用即可获得欺骗后的运行环境（多开、改机、隐藏 root/Xposed、绕过设备指纹校验）。
- 防御场景：应用风控需识别自身运行在容器内。

# 利用步骤

无 PoC（源码机制分析；验证载体为开源项目 Blackbox/Monster-GM sandbox）。

# 变体与关联

- 检测缺口（文中明确指出）：IO 重定向仅 Hook java.io.UnixFileSystem 的 JNI 函数与少量入口，未 Hook libc 的 open/stat 等，native 代码直接 open 即可看到真实路径；seccomp 过滤器可通过探测 SIGSYS 行为/读取 seccomp 状态发现；/proc/self/cmdline 被重定向但 /proc/<pid>/cmdline 与 maps、进程名等可交叉验证；隐藏 Xposed 的固定类名名单可被反探测。
- 同类：分身/多开商业方案、VirtualXposed、太极；与 Frida/Xposed 移动分析场景互补。

# 检测与防御

- 检测：native 层直接 open /proc/self/cmdline、/data/data/<自己包名> 与 Java 层结果比对；探测 getCallingUid 返回值与 os.uid 是否一致；遍历已安装 Provider/Activity 发现占坑组件（proxy_content_provider_N、ProxyActivity$PN）；加载名单内 Xposed 类名验证是否被吞；检查 seccomp 过滤器存在性。
- 防御：服务端对关键操作做设备完整性交叉验证；检测同一 UID 下多包名/多进程特征；对容器特征（占坑组件、stub 命名、多开数据目录结构）建立指纹库。
