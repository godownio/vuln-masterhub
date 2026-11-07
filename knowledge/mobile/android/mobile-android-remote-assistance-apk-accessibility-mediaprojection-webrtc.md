---
id: mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc
title: Android 远程协助 APK 的高权限远控链路识别：无障碍操控 + MediaProjection 录屏 + WebRTC 实时通道
type: scenario
domain: mobile
path: mobile/android
technique: android-remote-control-apk-capability-analysis
aliases:
- Android 远控 APK
- 远程协助 APK 分析
- AccessibilityService 远控
- MediaProjection 录屏远控
- WebRTC 远程屏幕
- 无障碍远程操控
- 高权限远控应用识别
tags:
- android
- apk
- remote-control
- accessibility-service
- mediaprojection
- webrtc
- notification-listener
- boot-receiver
- privilege-abuse
- malware-analysis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V96
  verified_at: '2026-11-05T19:58:48+08:00'
  notes: 已对照原文（含4张内嵌图）与22张图片核对；样本com.cjtec.remoteassis 2.7.6、360加固、5个dex、Manifest权限、AccessibilityService/MediaProjection/WebRTC/通知监听/开机自启/自动授权均有正文或截图支撑；原文为样本行为分析，未复跑样本。
---

## 一句话结论

高权限远控类 APK 的完整接管链通常由四块拼成：无障碍服务负责读屏并注入点击/滑动/全局按键，MediaProjection 负责屏幕采集，WebRTC 负责实时音视频与控制数据通道，前台服务/通知监听/开机自启/悬浮窗/自动授权负责保活与降低授权门槛。分析样本 `com.cjtec.remoteassis`（2.7.6，360 加固）同时具备这四块能力，用户完成授权后控制端即可实时看屏并远程操作设备。

## 原理

- **无障碍服务是远程 UI 操控的核心**：`AccessibilityService` 通过 `onAccessibilityEvent()` 持续接收界面变化事件，用 `getRootInActiveWindow()`、`findAccessibilityNodeInfosByText()`、`getParent()`、`AccessibilityNodeInfo.performAction()` 定位并操作控件；`performGlobalAction(I)` 可执行返回、主页、最近任务等系统级动作；`dispatchGesture()` 可注入点击、滑动与多段轨迹。该链路不需要 root，只需用户在系统设置中启用无障碍服务。
- **MediaProjection 提供屏幕采集**：取得录屏授权后，`MediaProjection.createVirtualDisplay()` 把屏幕内容渲染到虚拟显示，`ImageReader.newInstance()` + `acquireNextImage()` 读取帧；配合 `RECORD_AUDIO` 与音频采集可同时获取声音。Android 10+ 每次录屏仍需系统弹窗授权，Android 14+ 还要求前台服务声明 `mediaProjection` 类型。
- **WebRTC 承载实时传输与控制信令**：`PeerConnectionFactory.initialize()`、`PeerConnection.IceServer`（STUN）、`createPeerConnection()`、`createOffer()/createAnswer()/setRemoteDescription()`、`createDataChannel()` 建立实时音视频与双向数据通道；控制端通过 JSON 消息（`offer`/`answer`/`candidate` 等）协商，业务消息用 `opname` 区分 `control`、`opencamera`、`switchcamera`、`warn` 等动作。
- **被控端能力面很宽**：除屏幕/音频外，样本还实现摄像头开关与前后摄切换（Camera2Enumerator）、锁屏解锁与屏幕唤醒（KeyguardManager + PowerManager.WakeLock）、音量调节（AudioManager）、屏幕旋转、模拟按键（返回/主页/菜单）与手势轨迹（TouchPath）、前台服务保活。
- **保活与授权引导降低门槛**：`NotificationListenerServiceImpl` 在通知监听连接后拉起被控服务，`BootBroadcastReceiver` 监听 `BOOT_COMPLETED` 开机自启，`DaemonService`/`PlayerMusicService`/`SinglePixelActivity` 等做进程保活，前台通知显示“远程协助服务”；`AutoOpenPermissionActivity` 配合悬浮窗弹出“开始自动授权/请勿点击屏幕”一类提示，把多个系统授权流程串起来；清单还申请 `SYSTEM_ALERT_WINDOW`、`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`、`WRITE_SECURE_SETTINGS`、`REQUEST_INSTALL_PACKAGES`、`MANAGE_EXTERNAL_STORAGE`、`CAMERA`、`RECORD_AUDIO`、`READ_PHONE_STATE` 等高敏权限。
- **为什么危险**：这套组合把“屏幕共享”升级为“远程接管”——控制端能看到被控端全部画面（包括聊天、验证码、银行页面），并能代替用户点击、滑动、返回、打开应用、拍照录像。它不依赖系统漏洞，而是利用用户对无障碍/录屏/通知权限的授权；360 加固使静态分析先看到壳代码，进一步降低被发现概率。
- **边界**：无障碍服务必须由用户在设置中手动启用（或通过 ADB/开发者选项/激活工具辅助开启），MediaProjection 每次会话需系统确认，Android 高版本对后台启动、悬浮窗、无障碍权限有额外限制；样本 `targetSdk 30`，部分行为在较新系统上可能受限或触发提示。

## 触发条件

- 用户安装 APK 并授予无障碍、录屏、通知监听、相机/麦克风、悬浮窗、电池白名单等权限；或攻击者通过社交工程/远程指导让用户逐步开启，样本还包含开发者选项与 USB 调试引导、自动授权提示等降低门槛的逻辑。
- 设备为 Android 5.0+（样本 `minSdk 21`、`targetSdk 30`）；Android 11+ 的 `MANAGE_EXTERNAL_STORAGE`、Android 14+ 的录屏前台服务限制会影响部分能力。
- 控制端与被控端可访问信令/STUN 服务并建立 WebRTC 连接；样本使用多个公共 STUN（如 `stun.l.google.com:19302`）。
- 应用使用 360 加固（`assets/libjiagu.so`、`libjiagu_a64.so`），直接反编译只能看到壳代码，需要先脱壳才能审计业务逻辑。
- 系统未限制侧载、Play Protect/MDM 未拦截，用户未识别应用真实用途。

## 利用步骤

本条为样本行为分析与风险识别，不是攻击复现；可按以下顺序还原能力面：

1. **清单与组件枚举**：用 `aapt`/`apkanalyzer` 导出权限、service、receiver；重点看 `BIND_ACCESSIBILITY_SERVICE`、`MediaProjection` 前台服务类型、`NotificationListenerService`、`BOOT_COMPLETED`、`SYSTEM_ALERT_WINDOW`、`REQUEST_INSTALL_PACKAGES`、`MANAGE_EXTERNAL_STORAGE`。
2. **查壳与脱壳**：用 APKiD/ApkCheckPack 识别 360 加固特征（`assets/libjiagu.so` 等）；再用 frida-dexdump 或对应脱壳工具从内存取出业务 dex（样本脱壳后得到 `classes.dex` 到 `classes5.dex` 共 5 个）。
3. **jadx 审计关键词**：`AccessibilityService`、`onAccessibilityEvent`、`performGlobalAction`、`dispatchGesture`、`MediaProjection`、`createVirtualDisplay`、`ImageReader`、`PeerConnectionFactory`、`createDataChannel`、`NotificationListenerService`、`BOOT_COMPLETED`、`startForeground`、`KeyguardManager`、`PowerManager.WakeLock`、`Camera2Enumerator`。
4. **还原控制协议**：在 `ControlledService`/`ControlService` 中找 JSON 消息解析，记录 `type`（offer/answer/candidate）、`opname`（control/opencamera/switchcamera/warn）、手势点数组、按键码（返回/主页/菜单）等字段，判断控制端可下发哪些动作。
5. **评估权限组合与保活**：把清单权限与代码调用一一对应，确认是否存在自动授权、悬浮窗覆盖、通知监听拉起、开机自启、电池白名单等提高存活率的逻辑。
6. 输出风险结论：是否具备实时屏幕/音频采集、远程 UI 操作、摄像头/麦克风控制、文件与安装权限、持久化能力，以及数据流向哪些服务器。

## PoC

无利用 PoC（本文为样本行为分析）。可用以下命令复现能力面提取：

```bash
# 权限与组件
aapt dump permissions sample.apk
aapt dump xmltree sample.apk AndroidManifest.xml | \
  grep -iE "accessibility|mediaProjection|notification|BOOT_COMPLETED|SYSTEM_ALERT_WINDOW|INSTALL_PACKAGES"

# 查壳（APKiD）与脱壳后的 dex 审计
apkid sample.apk
jadx -d out/ classes*.dex

# 能力关键词
grep -RInE "performGlobalAction|dispatchGesture|createVirtualDisplay|ImageReader|createDataChannel|NotificationListenerService|BOOT_COMPLETED" out/
```

说明：原文使用 ApkCheckPack 识别 360 加固并脱壳得到 5 个 dex，用 jadx 逐段核对 `ControlService`/`ControlledService` 的无障碍、录屏、WebRTC、保活与自动授权逻辑；本卡未对样本复跑工具，命令为通用分析流程。

## 变体与关联

- **正规远程协助软件**：TeamViewer QuickSupport、AirDroid 等也使用无障碍/录屏/前台服务，但通常有明确品牌、可见授权说明与厂商服务器；判断风险应看透明度、数据去向与是否诱导授权，而不是只看 API。
- **银行木马/短信木马**：常滥用无障碍服务读取屏幕、点击授权、拦截/读取通知验证码；本条补充了 MediaProjection + WebRTC 的“完整远控”形态。
- **通知监听滥用**：`NotificationListenerService` 可读取通知中的验证码、聊天内容；与无障碍组合可完成自动登录/转账类操作。
- **保活变体**：前台服务 + 双进程/播放静音音乐/1 像素 Activity/JobScheduler/电池白名单；不同厂商 ROM 的保活效果差异大。
- **加固与对抗**：360、梆梆、腾讯乐固等壳会隐藏业务 dex；分析需先脱壳，参见 [[mobile-android-packer-apkid-frida-dexdump-jadx]]；运行期可结合 [[mobile-android-anti-detection-root-emulator-proxy]] 与 [[mobile-android-ssl-pinning-bypass-cert-frida]] 观察环境检测与网络通信。
- **权限变体**：`WRITE_SECURE_SETTINGS` 可修改系统设置，`REQUEST_INSTALL_PACKAGES` 可静默引导安装其他 APK，`MANAGE_EXTERNAL_STORAGE` 可批量读写文件，均为远控之外的二次危害。

## 检测与防御

- **检测（静态）**：
  - 清单中同时出现无障碍服务、`MediaProjection` 前台服务、`NotificationListenerService`、`BOOT_COMPLETED`、`SYSTEM_ALERT_WINDOW`、`REQUEST_INSTALL_PACKAGES`、`MANAGE_EXTERNAL_STORAGE` 等高敏能力组合；
  - 无障碍服务声明 `android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"`，且服务描述模糊、应用无品牌/官网；
  - 存在自动授权/覆盖层引导文案（“开始自动授权”“请勿点击屏幕”）、隐藏图标、开发者选项/USB 调试引导；
  - 360 等加固特征与未知签名，且应用市场无对应包名。
- **检测（动态/网络）**：
  - 运行期出现 `MediaProjection` 录屏指示、无障碍悬浮按钮/覆盖层、频繁的 `performGlobalAction`/`dispatchGesture` 调用；
  - 前台通知“远程协助/屏幕共享”与用户认知不符；后台长期持有 `PARTIAL_WAKE_LOCK`；
  - WebRTC/STUN 流量（`stun.l.google.com:19302` 等）与未知信令服务器；屏幕帧/音频上传；
  - 通知监听读取验证码、开机自启拉起服务、无障碍设置被修改。
- **防御**：
  - 不向来源不明的应用授予无障碍、录屏、通知监听、悬浮窗权限；从官方商店安装并核对开发者与包名；
  - 企业环境用 MDM/Play Protect/应用白名单禁止侧载，监控无障碍服务与录屏授权变更；
  - Android 11+ 限制 `SYSTEM_ALERT_WINDOW` 与后台启动，Android 14+ 强制录屏前台服务类型与每次授权提示；及时升级系统；
  - 对高敏业务 App 增加自己的防截屏/防无障碍标记（`FLAG_SECURE`、`setFilterTouchesWhenObscured`），检测覆盖层与异常无障碍事件；
  - 发现此类应用后立即撤销无障碍/录屏/通知权限、卸载应用、检查是否安装其他 APK、修改重要账号口令并排查验证码泄露。
