---
id: mobile-android-anubis-banker-command-map
title: Anubis Android 银行木马命令映射：del_sws/Send_GO_SMS/startaccessibility/startrat/startforward 等指令与 /olo/a1.php、/olo/a2.php C2 协议
type: scenario
domain: mobile
path: mobile/android
technique: anubis-banker-command-protocol-analysis
tags:
- android
- malware
- banker
- anubis
- static-analysis
- command-dispatch
- sms
- accessibility
- mediaprojection
- vnc
- call-forwarding
- ussd
- ransomware
- c2
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V680
  verified_at: '2026-11-13T13:31:57+08:00'
  notes: 已对照原文全文与61张本地截图逐张核对：命令表(del_sws/Send_GO_SMS/recordsound/save_inj/nymBePsG0/GetSWSGO/telbookgotetxt/getapps/getpermissions/startaccessibility/startpermission/=ALERT|/=PUSH|/startAutoPush/RequestPermissionInj/RequestPermissionGPS/ussd/sockshost/stopsocks5/spam/startapplication/killBot/getkeylogger/startrat/startforward/stopforward/openbrowser/openactivity/cryptokey/decryptokey/getIP/network/gps/lookscreen)与反编译截图分支逐条对应；/olo/a2.php(tuk_tuk=|:!getPath!!!!|refreshfilefolder)与/olo/a1.php(multipart serverID=getfiles+VNC[]/sound[])回传协议与截图一致。修正4处：cwwzcpcub(原cwzwpcpu)、|:!getPath!!!!(原3个感叹号)、**startbrurl**(原startbrul)、代理服务类名按图为sfswnwyaкpjr(原sfswunyakyjr)；补充getIP与startrat子命令(opendir/downloadfile/deletefilefolder经a2.php回传)；GetSWSGO由'短信数量'改为'上传sent/inbox/draft内容'以贴合截图。另有3张xzfile.aliyuncs.com外链图(网络定位/GPS/锁屏)未下载，staging cards.json已如实注明，相应内容按正文文字与命令表记录。dedup：Ermak(JSON cmd字段)与sms-forward卡均为不同家族/机制，非同链；dup-scan无涉及pair。未动态运行样本。
url: /docs/mobile/android/mobile-android-anubis-banker-command-map/
draft: false
kb_aliases:
- Anubis 银行木马
- Anubis 样本分析
- banker.anubis
- tnbzgzykdy.nalryogycw.slsa
- Android Security.apk
- del_sws
- Send_GO_SMS
- startaccessibility
- startrat
- startscreenVNC
- startforward
- AnubisCrypt
---

## 一句话结论

Anubis 银行木马样本（伪装 "Android security"，包名 `tnbzgzykdy.nalryogycw.slsa`，样本 MD5 `b1a49883e8f0be6ef9df8e52ccff5024`）用一个基于 `contains` 字符串匹配的巨型命令分发器解析 C2 指令，覆盖短信删除/读取/群发、通讯录与安装应用/权限/定位外传、无障碍与键盘记录、MediaProjection 录屏 VNC、前后台录音、USSD 拨号、`*21*`/`#21#` 呼叫转移、WebView 钓鱼注入、`.AnubisCrypt` 文件加密与锁屏；指令来自 `del_sws`、`Send_GO_SMS`、`|recordsound=`、`startaccessibility`、`|startrat=`、`startforward=` 等字符串，结果与截图分别经 `/olo/a2.php`（`tuk_tuk=` 表单）与 `/olo/a1.php`（`VNC[]` multipart）回传。

## 原理

- **样本与家族**：伪装成 "Android security" 的 Google Play 风格图标，包名 `tnbzgzykdy.nalryogycw.slsa`，297.98 KB，证书 MD5 `e89b158e4bcf988ebd09eb83f5378e87`，VirusTotal 22/57 检出为 Anubis/bankbot；同源列表中还出现 `wocwvy.czyxoxmbauu.slsa`（Hepsi Yanimda/MMS Message）、`ghost26.ghost28.slsa`（tobereplaced）、`br.com.bb.android.carteirabb`（Modulo BB）等样本，包名后缀 `.slsa` 是这批样本的一个共同特征。
- **命令分发结构**：核心分发器对 C2 返回/下发的长字符串做大量 `d.contains("...")` 判断，每个分支用固定分隔符解析参数（如 `|openbrowser=` 与 `|endbrowser`、`|telbookgotetxt=` 与 `|endtextbook`、`!!!!`、`!@!`、`|:!getPath!!!!`），再启动对应 Activity/Service 或直接调用短信、文件、定位 API。命令并不是结构化 JSON，而是拼接协议。
- **C2 交互**：`a1.php` 接收截图/录音等文件：multipart 表单含 `serverID`（固定 `getfiles`）与 `VNC[]`/`sound[]` 文件段，URL 来自本地偏好 `websocket` + `/olo/a1.php`；`a2.php` 接收命令结果：POST `tuk_tuk=<设备标识>|:!...` 形式的文本，路径 `/olo/a2.php`；WebView 钓饵页走 `/fafa.php?f=<参数>&p=<设备>|<国家>`，分支标签 grab1-grab4 表示 "Info + Grabber cards mini"/"Grabber cards"（银行卡/信息抓取页面）。
- **短信与联系人**：
  - `del_sws`：按 `|del_sws|` 标志删除 `content://sms/inbox` 与 `content://sms/sent` 中匹配的短信（按 `_id` 删除），删除结果回传 `tuk_tuk`。
  - `Send_GO_SMS`：从指令中拆出 `number=` 与 `text=`，用 `SmsManager.divideMessage` + `sendMultipartTextMessage` 发送短信，并记录 "Outgoing SMS / Number / Text" 到 C2。
  - `GetSWSGO`：上传 `content://sms/sent`、`inbox`、`draft` 三个短信库的内容（原文标题为"上传发送、接收、删除的短信"）；`getNumber`/`nymBePsG0` 查询 `CommonDataKinds.Phone.CONTENT_URI`，按 "Numbers from the phone book: 名称 号码" 拼接后上传（过滤 `*`、`#` 与长度 <=6 的号码）。
  - `|telbookgotetxt=`：把通讯录文本传给 `wami.class` Activity（配合钓鱼页）。
- **应用/权限/定位画像**：`getapps` 遍历 `getInstalledApplications(0x80)` 上传包名列表；`getpermissions` 遍历请求的权限并标注 `ON/OFF` 上传；`network`/`gps` 分别上传网络与 GPS 经纬度（`LocationManager.requestLocationUpdates("network", 15000, 10f)`，格式 `%1$.4f:%2$.4f`），后台服务 `frvvkgp` 在偏好 `network=true` 时启动。
- **无障碍/键盘记录与权限诱导**：`startaccessibility` 把偏好 `startRequest` 中的 `Access=0` 改为 `Access=1`；`startpermission` 同样改写 `Perm=0→1`；`RequestPermissionInj` 拉起 `dzudmx.class` 并显示伪造的"统计数据访问"对话框（原文截图含土耳其语/俄语文案），点击跳到 `android.settings.USAGE_ACCESS_SETTINGS`；`RequestPermissionGPS` 跳 `LOCATION_SOURCE_SETTINGS`，用本地化话术诱导用户授予通知/定位权限。键盘记录服务在 `save_inj` 偏好有值时循环读取，记录写入 `keys.log`（`|^|` 分隔），`getkeylogger` 读取后把分隔符换成换行上传（参数 12）并清空日志。
- **录屏 VNC**：`startscreenVNC` 拉起 `cwwzcpcub` Activity，用 `MediaProjectionManager.createScreenCaptureIntent()`（requestCode 59706）申请录屏授权，把 `resultCode`/`resultIntent` 转交 `jkggfql` 服务；服务每 500ms 截屏到 `getExternalFilesDir(null)/screenshot.jpg`，按 `websocket` + `/olo/a1.php` 以 `VNC[]` 字段上传，文件名在 0-10 间循环；`stopscreenVNC` 或偏好 `vnc != start`/`websocket` 为空时停止。
- **录音**：`|recordsound=`/`startsound`/`startforegroundsound` 启动 `brtltydqhiuqqb` 服务，`MediaRecorder` 用 `setAudioSource(1)`、`setOutputFormat(3)`、`setAudioEncoder(1)` 录制到文件，到时 `stop/release` 后以 `sound[]` 上传；`|recordsound=` 的参数是录音秒数，`startforegroundsound` 走前台服务（SDK>=26 时用 "Update Google Play Service" 假通知伪装）。
- **USSD/呼叫转移**：`|ussd=` 读取标记间内容，存偏好 `USSD` 后启动 `gcmysyhtova` Activity，`str.replace("AAA","#")` 后 `ACTION_CALL` 拨打 `tel:` 并 `setRingerMode(0)`，回传 "Request USSD is executed"；`startforward=` 直接拨 `*21*<号码>#` 开启无条件呼叫转移，`stopforward` 拨 `#21#` 关闭。
- **钓鱼弹窗/通知/WebView**：`=ALERT|` 解析 `|title=`/`text=`，启动 `fyqapyahei` Activity 弹 AlertDialog；`=PUSH|`/`startAutoPush` 按系统语言（RU/US/TR/DE/IT/FR）生成 "紧急消息/确认您的账户" 类通知并启动 `nepgaqmyfrhw` 服务；`|openbrowser=` 打开 `url`/`**startbrurl**` 页面，`|openactivity=` 用 `kbypzruy` Activity 的 WebView 加载 URL（JS 开启），`|startrat=` 读取 `|endrat=`-`|endurl` 之间的 WebSocket 地址启动远控服务 `xelytgswelv`（命令表中其子命令 `opendir:`/`downloadfile:`/`deletefilefolder:` 分别把目录/文件信息以 `|:!getPath!!!!<path>!@!<dir>`、`|:|:|:|!!!refreshfilefolder!!!` 形式经 `/olo/a2.php` 回传）。
- **文件加密/锁屏**：`|cryptokey=` 对目标文件加密并改名追加 `.AnubisCrypt`（已加密的跳过），`|decryptokey=` 解密并去掉后缀；原文截图未给出具体加解密算法；`lookscreen` 执行锁屏。
- **SOCKS/垃圾短信/启动应用**：`|sockshost=` 解析 `host/user/pass/port` 启动 `sfswnwyaкpjr` 代理服务（`ServerSocket(34500)` + 每连接一个线程），`stopsocks5` 置 `socks=stop`；`|spam=` 设置 `textSPAM`/`spamSMS=start` 触发短信群发；`|startapplication=` 按包名 `getLaunchIntentForPackage` 启动应用；`getIP` 获取设备 IP；`killBot` 清空 `url`/`urls`/`urlInj` 并停止键盘注入服务。
- **动态 DEX**：`sendNotification_0` 通过 `DexClassLoader(new File(getDir("apk", 0), "Android Security.apk"), outdex, ..., 系统 ClassLoader)` 加载 `apps.com.app.utils` 并反射调用，说明样本把部分通知/钓鱼模块放在二次释放的 DEX 中。

## 触发条件

- 用户侧装了该 Anubis 样本并授予短信、通讯录、定位、通知、无障碍、录屏等权限（样本用伪造的"统计/定位"对话框诱导开启）。
- C2 可达并下发上述拼接式指令；`websocket`/`urlInj` 等偏好已配置为基础 URL。
- 分析侧：拿到 APK，可用 jadx/JADX 反编译；字符串 `del_sws`、`Send_GO_SMS`、`|startrat=`、`startscreenVNC`、`.AnubisCrypt`、`/olo/a1.php` 等可直接定位命令分发与 C2 逻辑。
- 样本为 2023-08-28 上传的该变种；同家族其他样本可能更换包名后缀、C2 与命令标记。

## 利用步骤

1. 样本初筛：计算 MD5/SHA256，`apkid` 查壳；该样本未加壳，jadx 可直接反编译出 Java 源码。
2. 全局搜索命令标记（`del_sws`、`Send_GO_SMS`、`|recordsound=`、`save_inj`、`getapps`、`startaccessibility`、`|startrat=`、`startforward=`、`|cryptokey=` 等），定位包含大量 `contains` 的巨型分发方法。
3. 在分发方法中还原每条命令的参数分隔符与跳转目标（Activity/Service 类名），对照本卡命令表。
4. 搜索 `/olo/a1.php`、`/olo/a2.php`、`/fafa.php` 与 `tuk_tuk`、`VNC[]`、`sound[]`、`serverID`，还原上传接口与字段。
5. 搜索 `MediaProjectionManager`、`createScreenCaptureIntent`、`59706`、`getExternalFilesDir`、`screenshot.jpg`，确认录屏 VNC 实现；搜索 `MediaRecorder` 的 `setAudioSource(1)` 确认录音；搜索 `*21*`、`#21#` 确认呼叫转移。
6. 搜索 `DexClassLoader`、`getDir("apk"`、`Android Security.apk`、`apps.com.app.utils`，确认二次 DEX 模块。
7. 提取 IOC（包名、证书、C2 路径与偏好键）用于检测与样本家族归属。

## PoC

无 PoC（恶意样本，禁止在非隔离环境运行）。静态定位命令：

```bash
apkid sample.apk
jadx -d out sample.apk
grep -RIn "del_sws\|Send_GO_SMS\|recordsound\|startaccessibility\|startrat\|startforward\|AnubisCrypt\|olo/a[12].php" out/
```

样本 IOC：

- 应用名：`Android security`；包名：`tnbzgzykdy.nalryogycw.slsa`
- MD5：`b1a49883e8f0be6ef9df8e52ccff5024`；证书 MD5：`e89b158e4bcf988ebd09eb83f5378e87`
- 首次提交：2023-08-28 00:55:06 UTC；VT 检出 22/57
- 回传路径：`/olo/a1.php`（`VNC[]`/`sound[]` multipart）、`/olo/a2.php`（`tuk_tuk=` 文本）、`/fafa.php`（WebView 钓鱼页）

## 变体与关联

- **同家族命令面差异**：Anubis 与 Ermak/Cerberus 系银行木马都采用无障碍+覆盖层+录屏的银行木马范式；Ermak 的命令分发与 47 条命令见 [[mobile-android-ermak-banking-trojan-command-dispatch-map]]，Anubis 这里的特征是用 `contains` 拼接标记而非 JSON `cmd` 字段、以 `/olo/a1.php`/`a2.php` 分离文件与文本回传。
- **其他 Android RAT/银行木马命令映射**：[[mobile-android-ahmyth-rat-static-command-map]]（Socket.IO/`order` 事件）、[[mobile-android-droidjack-sandrorat-controller-module-command-map]]。
- **无障碍/录屏/短信能力单点卡**：[[mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc]]、[[mobile-android-sms-received-forward-c2-number-banking-trojan]]、[[mobile-android-spymax-telegram-phishing-accessibility-keylogger-gzip-c2]]。
- **同名文件后缀**：`.AnubisCrypt` 加密后缀可作为勒索/文件破坏行为的检测串。

## 检测与防御

- **静态检测**：APK 包名/文件名带 `.slsa` 后缀、应用名伪装 "Android security"、`DexClassLoader` 从 `getDir("apk")` 加载 "Android Security.apk"、字符串 `del_sws`/`Send_GO_SMS`/`|startrat=`/`startscreenVNC`/`.AnubisCrypt`/`olo/a1.php`/`olo/a2.php` 任一出现即可高分告警。
- **动态/EDR 检测**：每 500ms 截屏并写 `screenshot.jpg`、频繁查询/删除 `content://sms/*`、`ACTION_CALL` 拨打 `*21*`/`#21#`、诱导跳转 `USAGE_ACCESS_SETTINGS`/`LOCATION_SOURCE_SETTINGS`、MediaProjection 授权请求（requestCode 59706）、`sound[]`/`VNC[]` multipart 外传。
- **防御**：只从官方商店安装应用并开启 Play Protect；禁止旁加载不明 APK；严格管控无障碍、通知访问、使用情况访问与录屏权限；对已知包名/证书/哈希与 C2 路径做拦截；对银行类 App 检测覆盖层与无障碍注入。
- **研究注意**：样本具备短信删除/转发、呼叫转移、文件加密与远程 SOCKS 能力，分析必须在断网隔离环境进行，禁止执行。
