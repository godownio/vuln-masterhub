---
id: mobile-android-bandwidth-monetizer-sdk-residential-proxy
title: Android 免费影视应用借 bandwidth monetizer SDK 将设备变为住宅代理节点
type: scenario
domain: mobile
path: mobile/android
technique: android-bandwidth-monetizer-sdk-residential-proxy
tags:
- android
- malware
- residential-proxy
- sdk
- boot-receiver
- jni
- mproxy
- ioc
cve: []
severity: high
confidence: high
affected_versions: FlixVision v3.1.1r（APK）；SDK com.mon.app_bandwidth_monetizer_sdk
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V93
  verified_at: '2026-11-05T19:40:21+08:00'
  notes: 已对照原文与29张图片核对：BootReceiver/BOOT_COMPLETED/exported=true、UUID b4ee55d5-...、startKoin/startService/startForegroundService、Retrofit dror.applinked.cloud、registerMyDevice/getNewConfiguration参数、mproxy.cfg、libmproxy.so导出与run_mproxy_main/cycle_step/proxy_thread_func均与截图一致。未验证点：图20仅展开显示x86/x86_64目录下的libmproxy.so，arm64-v8a/armeabi-v7a目录未展开，四ABI齐备为推断；未复跑样本
url: /docs/mobile/android/mobile-android-bandwidth-monetizer-sdk-residential-proxy/
draft: false
kb_aliases:
- 带宽货币化 SDK
- bandwidth_monetizer_sdk
- 住宅代理节点
- FlixVision
- mproxy
---

## 一句话结论

一款看似正常的免费影视应用 FlixVision（Android/Fire TV）内嵌 `com.mon.app_bandwidth_monetizer_sdk`：应用在开机广播后拉起前台服务，向 C2 注册设备并拉取配置，写入 `mproxy.cfg`，再加载 `libmproxy.so` 启动原生代理服务，把用户家庭网络变成可被第三方使用的住宅代理出口节点。

## 原理

- 应用前端只提供影视播放功能，但 Manifest 中注册了 `com.mon.app_bandwidth_monetizer_sdk.service.BootReceiver`，监听 `android.intent.action.BOOT_COMPLETED` 且 `exported="true"`；系统开机/重启后即触发 SDK 初始化，无需用户再次打开应用。
- SDK 初始化时构造 `AppBandwidthMonetizerSdkHelper(publisher, uid, category, version, ...)`，其中 publisher 为推广 ID（样本中为 `b4ee55d5-c3dc-4183-9c58-3eb5a82c93cb`），随后调用 `startKoin`/`startService`。
- 服务以前台服务方式运行（`startForegroundService`/`startService`），降低被系统回收的概率；通过 Retrofit 向 `https://dror.applinked.cloud/` 及 `https://<tenant>.apis.cyberprotector.online/` 发起注册与配置请求：
  - `registerMyDevice`：`.../ ?regcc=1&pub=<publisher>&uid=<uid>&cid=<cid>&ver=<ver>`；
  - `getNewConfiguration`：`.../?get=1&cc=...&pub=...&uid=...&foreground=...&ver=...&socks...`。
- 收到的配置写入应用私有目录的 `mproxy.cfg`；`MProxy` Java 类 `System.loadLibrary("mproxy")` 加载内置 `libmproxy.so`，并调用 native 的 `start/stop/reload`。
- native 层 `run_mproxy_main` 读取 `mproxy.cfg`（样本路径如 `/data/user/0/<pkg>/files/mproxy.cfg`），初始化配置与信号处理，进入 `cycle_step` 事件循环；通过 SocketAPI 的 `connect`/`poll`/`sendto`/`recvfrom` 等函数和 `pthread_create` 启动代理线程，对外提供代理转发服务。
- 结果是设备公网 IP 与闲置带宽被租给第三方使用：外部流量看起来来自用户家庭网络，用户可能承担带宽消耗、隐私暴露与流量归因/法律风险；应用界面完全看不出该行为。

## 触发条件

- 用户安装并启动应用（或设备重启后由 BOOT_COMPLETED 自动拉起）；设备联网。
- Android 版本/厂商允许应用创建前台服务与开机自启；应用拥有网络权限。
- C2 域名可达（`dror.applinked.cloud`、`*.apis.cyberprotector.online`）。
- APK 包含对应 ABI 的 `libmproxy.so`（样本含 armeabi-v7a、arm64-v8a、x86、x86_64）。
- 配置下发成功并可写入应用私有目录，native 代理才能启动。

## 分析/复现步骤

1. 静态检查 Manifest：搜索 `BOOT_COMPLETED`、`exported="true"` 的 receiver、前台服务与网络权限；记录可疑包名（如 `com.mon.app_bandwidth_monetizer_sdk`）。
2. 反编译 DEX（jadx/apktool），定位 `BootReceiver.onReceive` → `initPro` → `AppBandwidthMonetizerSdkHelper` → `startService` 的调用链。
3. 抓包/看 DNS：确认 `dror.applinked.cloud`、`<tenant>.apis.cyberprotector.online` 等外联；分析注册与配置请求参数（publisher/uid/cid/ver）。
4. 检查应用私有目录的 `mproxy.cfg` 与 `libmproxy.so`；用 IDA 查看导出函数 `Java_AppBandwidthMonetizer_MProxy_start/stop/reload` 与 `run_mproxy_main`、`cycle_step`、`proxy_thread_func`。
5. 动态验证：启动应用/重启设备后，观察前台服务、代理端口监听与外联；必要时在模拟器中隔离网络运行。
6. 处置：卸载应用、阻断 IOC 域名、检查设备是否被用作代理出口；企业环境用 MDM 禁止未知来源应用与开机自启。

## PoC

```text
# 关键行为链（静态分析视角）
BOOT_COMPLETED
  -> com.mon.app_bandwidth_monetizer_sdk.service.BootReceiver.onReceive
  -> AppBandwidthMonetizerSdkHelper.initPro
  -> startKoin / startService (前台服务)
  -> Retrofit: https://dror.applinked.cloud/
  -> registerMyDevice: https://<tenant>.apis.cyberprotector.online/?regcc=1&pub=...&uid=...
  -> getNewConfiguration: .../?get=1&cc=...&pub=...&uid=...&foreground=...&ver=...
  -> write files/mproxy.cfg
  -> System.loadLibrary("mproxy")
  -> MProxy.start(argv) -> run_mproxy_main -> cycle_step / proxy_thread_func
```

```text
IOC:
FlixVision_v3.1.1r.apk
MD5 9A1B1407D26D6979C95D21DE4CEDA965
dror.applinked.cloud
flixview.apis.cyberprotector.online
com.mon.app_bandwidth_monetizer_sdk
```

## 变体与关联

- 变体：其他“带宽 monetization/被动收入”SDK 与 proxyware（Honeygain、Peer2Profit 等）也会把设备变为出口节点；区别在于是否透明告知、是否有用户同意与收益。
- 变体：Android TV/机顶盒、免费影视/直播应用是常见载体；也可通过 sideload APK、第三方商店分发。
- 变体：SDK 可能同时收集设备标识（uid/cid）、前台状态与网络信息，用于节点调度和风控规避。
- 关联：[[mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc]]（另一类高权限远控/滥用链路）、[[mobile-android-spynote-fake-police-accessibility-credential-theft]]（仿冒应用投递恶意载荷）。

## 检测与防御

- 检测：Manifest 中出现与业务无关的 `BOOT_COMPLETED` receiver/前台服务；包名含 `bandwidth`、`monetizer`、`proxy` 等关键词；应用私有目录出现 `mproxy.cfg`、`libmproxy.so`；DNS/流量命中已知 proxyware C2 域名；设备出现异常代理端口与持续外联。
- 防御：只从官方商店安装应用；审查权限与开机自启；企业 MDM 禁止未知来源与后台代理；网络侧阻断 IOC 域名、限制异常出站；发现后卸载并检查网络滥用/流量归因风险。
- 加固：Android 平台限制后台启动与前台服务滥用；应用商店加强 SDK 行为审计；对“免费影视/带宽赚钱”类应用做供应链与隐私合规审查。
