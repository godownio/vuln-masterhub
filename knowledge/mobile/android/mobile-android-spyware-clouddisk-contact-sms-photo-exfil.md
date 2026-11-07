---
id: mobile-android-spyware-clouddisk-contact-sms-photo-exfil
title: 伪装云盘 Android 间谍 APP 静态分析：随机包名 + 通讯录/短信/相册权限组合与 ContentResolver 窃取
type: scenario
domain: mobile
path: mobile/android
technique: android-spyware-contact-sms-photo-contentresolver-exfil
aliases:
- 伪装云盘恶意 APP
- Android 间谍软件静态分析
- 通讯录短信相册窃取
- 随机包名恶意应用
- ContentResolver 数据收割
tags:
- android
- malware
- spyware
- static-analysis
- contentresolver
- permission-abuse
- data-exfiltration
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:33:11+08:00'
  notes: 已对照原文与图01-11核对：VT 4/66 trojan.avfj/spyagent、随机包名 com.hxyvvwbtbqy.bgpbqve、READ_EXTERNAL_STORAGE/WRITE_EXTERNAL_STORAGE/READ_CONTACTS/READ_SMS/INTERNET、SplashActivity 为 launcher 经 MainNavigation.toLogin 走 ARouter MAIN_LOGIN、App 延时 1500ms、getContacts 用 ContactsContract.Phone、getMySms 用 content://sms 且 type=2、getPhoto 用 MediaStore 按 datetaken DESC 且最多 50 张、RxHttp 上传，均与卡片一致。未验证点：PoC 未本机执行（仅静态排查命令）；样本 versionName 1.0.0 非受影响区间；frontmatter 无 sources/source_url。
---

## 一句话结论

一款伪装成“云盘”的 Android APK 使用随机包名、申请 `READ_CONTACTS`/`READ_SMS`/`READ_EXTERNAL_STORAGE` 权限组合，在登录后通过 `ContentResolver` 批量读取通讯录、短信和相册（最多 50 张），再用 RxHttp 把数据上传到硬编码 C2；这是典型的隐私窃取+敲诈类间谍软件。

## 原理

- **权限组合即特征**：`READ_CONTACTS` + `READ_SMS` + `READ_EXTERNAL_STORAGE` + `INTERNET` 同时出现，远超普通云盘/工具类应用的最小权限需求，是数据收割型间谍软件的强指标。
- **随机包名**：包名如 `com.hxyvvwbtbqy.bgpbqve` 无业务含义，用于规避基于包名的静态检测/黑名单；正常应用包名通常与厂商/产品对应。
- **入口与静默跳转**：`SplashActivity` 为 launcher，延时后调用 `MainNavigation.toLogin()`，经 ARouter 路由到 `LoginActivity`，再 `finish()` 闪屏页，用户几乎无感知。
- **数据读取**：
  - 通讯录：`ContentResolver.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI)`，取 `display_name`/`data`；
  - 短信：`content://sms`，筛选 `type=2`（接收），取 `address`/`body`/`date`；
  - 相册：`MediaStore.Images.Media.EXTERNAL_CONTENT_URI`，按 `datetaken DESC` 取 `_data` 路径，限制 50 张。
- **数据回传**：`RxHttp.postJson(Urls.upLoadList/upLoadSms)` 与 `RxHttp.postForm(Urls.upLoadImg).addFile("file", path)`，URL 硬编码在 `Urls` 类中（明文 HTTP + IP）。
- 为什么成立：Android 权限一旦授予，ContentResolver 可读取全局联系人/短信/媒体库；恶意应用把“读取—封装—上传”写成固定流水线，静态分析即可还原。

## 触发条件

- 拿到可疑 APK，未加壳或可脱壳，能反编译出 Java/Kotlin 源码。
- Manifest 中出现上述高危权限组合与随机包名。
- 代码中存在 ContentResolver/MediaStore 查询与上传框架（RxHttp/OkHttp/Retrofit）。
- 有网络权限与硬编码 C2 地址；上传接口可达。

## 利用步骤

1. 样本初筛：VirusTotal/多引擎、`apkid` 查壳；记录 MD5/SHA-1/SHA-256。
2. `jadx`/`apktool` 反编译，先看 `AndroidManifest.xml`：包名、权限、launcher Activity、`exported` 组件。
3. 跟踪入口：`SplashActivity` → `MainNavigation` → ARouter → `LoginActivity`，确认静默跳转与登录流程。
4. 全局搜索 `ContentResolver`、`ContactsContract`、`content://sms`、`MediaStore`、`READ_SMS`、`READ_CONTACTS`、`upload`、`RxHttp`。
5. 定位 `Urls`/常量类，提取 C2 域名/IP、端口、API 路径；确认 HTTP/HTTPS、证书校验情况。
6. 还原数据封装与上传参数（phone/userId/sjc/ttttt/file），评估泄露数据范围与受害者数量。
7. 将样本、C2、权限、数据流、上传接口整理为报告，提交处置/举报；不要在未授权环境执行恶意样本。

## PoC

静态排查命令（不执行样本）：

```bash
jadx -d out app.apk
grep -rn "READ_CONTACTS\|READ_SMS\|READ_EXTERNAL_STORAGE" out/AndroidManifest.xml
grep -rn "ContentResolver\|ContactsContract\|content://sms\|MediaStore" out/sources
grep -rn "upload\|postJson\|postForm\|http://" out/sources | head -50
```

已安装样本的权限核验（授权取证环境）：

```bash
adb shell dumpsys package com.hxyvvwbtbqy.bgpbqve | grep -i permission
adb shell pm list packages -3
```

说明：原文通过 JADX 静态分析还原了权限、入口、ContentResolver 读取与 RxHttp 上传；未在本机执行样本。

## 变体与关联

- 变体（权限）：`READ_CALL_LOG`、`RECORD_AUDIO`、`CAMERA`、`ACCESS_FINE_LOCATION`、无障碍服务、`SYSTEM_ALERT_WINDOW`；权限越多，间谍软件特征越明显。
- 变体（窃取方式）：无障碍服务读取屏幕/输入、MediaProjection 录屏、通知监听、剪贴板监听、设备管理员阻止卸载。
- 变体（回传）：WebSocket、MQTT、Telegram Bot API、云存储预签名 URL；不一定是明文 HTTP。
- 关联：[[mobile-android-spynote-fake-police-accessibility-credential-theft]]（SpyNote RAT）；[[mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc]]（远控 APK）；[[mobile-android-ssl-pinning-bypass-cert-frida]]（抓包/动态分析前置）。
- 边界：APK 加壳/混淆、权限动态申请但用户拒绝、数据仅在本地加密、C2 已下线时，静态分析只能还原部分行为，需要动态沙箱/流量分析补充。

## 检测与防御

- 检测：安装/运行前扫描权限组合与随机包名；应用商店/EDR 对 ContentResolver 批量读取 + 网络上传行为告警；网络侧对硬编码 IP/明文 HTTP 上传接口做检测。
- 防御：用户只授予最小权限；Android 11+ 的分区存储/一次性权限降低影响；企业 MDM 禁止侧载未知来源 APK。
- 加固：应用商店加强静态/动态检测；对通讯录/短信/相册读取 API 做访问审计；对高风险权限组合要求额外说明与复核。
- 响应：隔离样本、保存 APK 与哈希、提取 C2 与上传接口、评估泄露数据、通知受害者并举报；不要在未授权环境复现上传。
