---
id: mobile-android-droidjack-sandrorat-controller-module-command-map
title: DroidJack/SandroRat Android RAT（net.droidjack.server）静态命令映射：Controller 模块覆盖短信、通讯录、通话记录、WhatsApp 数据库 su 拷贝、应用列表与屏幕开关
type: scenario
domain: mobile
path: mobile/android
technique: droidjack-sandrorat-controller-module-static-triage
aliases:
- DroidJack RAT
- SandroRat
- net.droidjack.server
- Aida006
- Controller 模块
- Android 远控命令映射
- Kryonet UDP C2
tags:
- android
- malware
- rat
- droidjack
- sandrorat
- static-analysis
- command-map
- data-exfiltration
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V530
  verified_at: '2026-11-11T16:49:46+08:00'
  notes: 已对照原文全文与全部50张图核对：net.droidjack.server 与 MainActivity 启动 Controller 服务（正文/图30-31）、Controller 初始化列表 a=am/b=bt/c=CallListener/f=q/.../o=be 并注册 SCREEN_ON/OFF（图32）、bt 短信 content://sms/sent + SMS_RECEIVED（图34）、q/g 通话记录 content://call_log/calls 含 Incoming/Outgoing/Missed（图39）、ContentProviderOperation 写 RawContacts（图37）、浏览器书签/历史（图41）、WhatsApp msgstore.db su 拷贝（图35）、mount yaffs2+cp 到 /system/app 持久化（图44）、应用列表含图标（图45）、音量读取（图46）、be 广播发 UDPM_SCREEN true/false（图43）、Kryonet UDP/TCP connect（图47/48）、droidjack.net/storeReport.php（图40）、SandroRat_Configuration_Database/SystemConfigurationTable（图38）均一致。与 AhMyth 静态命令映射卡为不同家族/网络模型，非同一链。未运行样本。
---

## 一句话结论

CharmingKitten 投递的 Android 远控样本图标为 Aida006、包名 `net.droidjack.server`，`MainActivity` 启动 `Controller` 服务；`Controller` 初始化 `am/bt/CallListener/f/q/b/ah/GPSLocation/bn/ca/a/bz/cf/bf/be` 等模块并注册 `SCREEN_ON/OFF` 接收器，静态可还原出短信收发与监听、通话记录、通讯录写入、浏览器书签/历史、WhatsApp `msgstore.db` 经 su 拷贝、已安装应用列表（含图标）、音频音量读取、屏幕开关状态上报与 Kryonet UDP/TCP 连接等能力，并有崩溃信息上报 `http://www.droidjack.net/storeReport.php`。

## 原理

- **模块化 Controller**：DroidJack 系 RAT 把功能拆成多个类，`Controller` 构造函数 `new am()/new bt()/new q()/new b()/new ah()/new be()` 等逐一初始化，并把 `be` 注册为 `android.intent.action.SCREEN_OFF/SCREEN_ON` 的 `BroadcastReceiver`；每个模块对应一组远程指令。
- **数据面来自 Android ContentProvider**：
  - 短信：`content://sms/sent` 读取已发送短信（body/address/date），并注册 `ContentObserver` 监听 `content://sms` 与 `SMS_RECEIVED` 广播（模块 bt）；
  - 通话记录：`content://call_log/calls` 读取 number/date/duration/type（Incoming/Outgoing/Missed）（模块 q/g）；
  - 通讯录：通过 `ContentProviderOperation` 批量写入 `ContactsContract.RawContacts`/`Data`（模块对应代码）；
  - 浏览器：`Browser.BOOKMARKS_URI` 与 `Browser.HISTORY_PROJECTION` 读取书签/历史（模块 b/ay）。
- **文件与持久化**：通过 `Runtime.getRuntime().exec("su")` 执行 `cp data/data/com.whatsapp/databases/msgstore.db <外部存储>/WhatsApp/Databases/wams.db` 窃取 WhatsApp 数据库；另一个模块尝试 `mount -o remount,rw -t yaffs2 /dev/block/mtdblock3 /system` 并把自身 APK `cp` 到 `/system/app/` 实现系统分区持久化。
- **其他能力**：枚举 `PackageManager.getInstalledApplications` 并把应用名、包名、图标（JPEG 压缩）序列化外传；读取音频流音量（`getStreamVolume`）；`be` 在屏幕开关时向 C2 发送 `UDPM_SCREEN:"true"/"false"`；网络层使用 Kryonet（`com.esotericsoftware.kryo`）建立 TCP/UDP 连接（`connect(host, tcpPort, udpPort)`）。
- **配置与崩溃上报**：存在 `SandroRat_Configuration_Database`（表 `SystemConfigurationTable`）保存配置；未捕获异常时把 `Build.MANUFACTURER/MODEL/VERSION.RELEASE` 与堆栈通过 `DefaultHttpClient` POST 到 `http://www.droidjack.net/storeReport.php`，是家族识别的强特征。

## 触发条件

- 目标 Android 设备安装并运行该 APK（用户手动安装/钓鱼诱导），授予短信、通讯录、通话记录、存储、网络等权限；
- `MainActivity` 启动 `Controller` 服务后，模块按 C2 指令执行数据读取/外传；
- 设备可访问外网与 C2（含 droidjack.net 上报端点）；
- 部分功能（WhatsApp 数据库拷贝、/system/app 持久化）需要 root/su 权限，失败时走异常分支。

## 分析/利用步骤

1. 用 jadx/JEB 打开 APK，确认包名 `net.droidjack.server`、入口 `MainActivity` 与 `Controller` 服务；
2. 查看 `Controller` 构造函数与模块初始化列表（am/bt/q/b/ah/be 等），逐个定位模块类与远程指令字符串；
3. 搜索 ContentProvider URI（`content://sms`、`content://call_log/calls`、`ContactsContract`、`Browser.BOOKMARKS_URI`）确认数据窃取面；
4. 搜索 `Runtime.getRuntime().exec("su")`、`/system/app`、`msgstore.db` 确认 root 行为与 WhatsApp 窃取；
5. 搜索 Kryonet/`com.esotericsoftware.kryo`、`connect(`、UDP/TCP 端口参数，还原 C2 网络模型；
6. 检索 `droidjack.net/storeReport.php`、`SandroRat_Configuration_Database`、图标名 Aida006 作为家族/变种指纹，结合权限清单与广播接收器输出检测规则。

## PoC

原文为静态分析，无 PoC。关键代码形态（示意）：

```java
// Controller 初始化
Controller.a = new am();
Controller.b = new bt((Context)this);
Controller.c = new CallListener();
Controller.f = new q(this.getApplicationContext());
Controller.h = new f(this.getApplicationContext());
Controller.j = new GPSLocation(this.getApplicationContext());
Controller.k = new bn(this.getApplicationContext());
Controller.l = new ca(this.getApplicationContext());
Controller.p = new bz(this.getApplicationContext());
Controller.r = new cf(this.getApplicationContext());
Controller.q = new bf(this.getApplicationContext());
Controller.o = new be();
registerReceiver(Controller.o, new IntentFilter("android.intent.action.SCREEN_OFF"));
registerReceiver(Controller.o, new IntentFilter("android.intent.action.SCREEN_ON"));
```

## 变体与关联

- 同源/衍生：配置数据库名 `SandroRat_Configuration_Database` 表明与 SandroRat 共用代码基础，模块字母与 C2 端口可变；
- 与库内 `mobile-android-ahmyth-rat-static-command-map`（AhMyth RAT 七类 Manager 映射）对比：两者都是开源/商用 Android RAT 的静态命令映射，但本样本使用 Controller 模块字母 + Kryonet 网络 + droidjack.net 上报，数据面多了 WhatsApp 数据库 su 拷贝与 /system/app 持久化；
- 与 `mobile-android-ermak-banking-trojan-command-dispatch-map` 等银行木马卡区别：本卡是通用远控（短信/通讯录/通话/应用/屏幕），非银行覆盖攻击。

## 检测与防御

- 移动端检测：包名 `net.droidjack.server`、图标 Aida006、`droidjack.net/storeReport.php`、`SandroRat_Configuration_Database`、Kryonet 库与 `su` 调用组合；
- 权限组合告警：短信+通讯录+通话记录+存储+网络同时申请，且应用无对应商店来源；
- 禁止侧载未知来源 APK、启用 Play Protect/企业 MDM 策略；root 设备重点排查 `/system/app` 异常 APK 与 WhatsApp 数据库被复制到外部存储；
- 网络侧封锁 droidjack.net 与可疑 UDP/TCP 长连接，结合 `UDPM_SCREEN:` 等协议字符串做流量检测。
