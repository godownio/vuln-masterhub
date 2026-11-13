---
id: mobile-android-bitter-photos-apk-rat-multisource-exfil
title: Bitter APT Android 远控样本 photos.apk 分析：无图标隐藏、伪装弹框、九类数据收集写入 systemservice 并 POST 上传
type: scenario
domain: mobile
path: mobile/android
technique: bitter-android-rat-multisource-exfil
tags:
- mobile
- android
- rat
- bitter
- apt
- spyware
- exfiltration
- sms
- contacts
- call-logs
- gps
- cell-info
- malicious-apk
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V510
  verified_at: '2026-11-11T05:02:52+08:00'
  notes: 已对照原文与全部 23 张截图核对：img01 VT 关系图（playstorenet.ddns.net/Youtube/home.php、23.227.201.160、10/91 检出）与 img02 Bitdefender 白皮书外传站点表（playupdateatp.serveblog.net/Youtube/home.php、blitzchatzlog.ddns.net 等）；img03/04 应用信息与短信/联系人/通话记录/定位权限弹框；img06-08 index.php POST（multipart/form-data）、MSG/URL 经 MY_ACTION 广播、Toast+ACTION_VIEW 伪装；img09 九类收集与 InputSettings/UpdateSettings 启动；img10-18 GPS（##LATLONG）、短信（content://sms/inbox/sent/draft、##SESSAGES）、联系人（CommonDataKinds.Phone/Email）、通话记录（INCOMING/OUTGOING/MISSED）、设备信息（getPhoneType/DeviceId/SimSerialNumber）、getInstalledPackages(128)、AccountManager(com.google)、SD 文件筛选（.pdf/.txt/.xml/.doc/.xls/.xlsx/.amr/.docx/.apk/.rec）；img19-21 基站监听（LISTEN_CELL_LOCATION 16/LISTEN_DATA_CONNECTION_STATE 64、GsmCellLocation/CdmaCellLocation、getNeighboringCellInfo）；img22/23 InputSettings.writeFile 写 /storage/sdcard0/systemservice、broadcast_execKeyboard、multipart POST home.php?IMEI=&SIMNO=。元数据（photos.apk/701723 字节/MD5 D20C6731E278A1D3202B4CAA0902AFA8/SHA1 B6353DAC1E425C3081F672ADF24D49B33E53A902/包名
    google.comgooglesettings/证书 SHA1 1173C15E0E3E69EE088CE0654CAB314F94DBD018）与原文一致。已修正白皮书站点拼写 blitzchatslog→blitzchatzlog（img02 为 blitzchatzlog）。未验证点：原文元数据包名 google.comgooglesettings 与 img03 安装截图应用名 com.android.settings 不一致（原文自身差异），卡片按原文文字记录；C2 已失效未动态验证。dedup：与 mobile-android-spyware-clouddisk-contact-sms-photo-exfil 等 Android 窃密卡为同域不同样本/基础设施，判 related/new 成立。原文未给组件版本，未设 affected_versions；无 sources/source_url。
url: /docs/mobile/android/mobile-android-bitter-photos-apk-rat-multisource-exfil/
draft: false
kb_aliases:
- Bitter Android RAT
- photos.apk
- playstorenet.ddns.net
- google.comgooglesettings
- systemservice 窃密文件
- Bitter APT 手机远控
---

## 一句话结论

Bitter 组织使用的 Android 远控样本 `photos.apk`（包名 `google.comgooglesettings`，无桌面图标）安装并授予短信/联系人/通话/定位等权限后，由 `InputSettings`/`UpdateSettings` 服务在后台收集 GPS、短信、联系人、通话记录、设备信息、已安装应用、账户、SD 卡指定文档、当前/相邻基站共九类数据，按 `##GPS`/`##SESSAGES` 等分段写入 `/storage/sdcard0/systemservice`，再以 multipart POST 上传到 `http://playstorenet.ddns.net/Youtube/home.php?IMEI=<DeviceId>&SIMNO=<SimSerialNumber>`；同时 POST `Youtube/index.php` 获取 `MSG`/`URL` 并弹框/打开网页，伪装成服务程序报错。

## 原理

- **隐藏与权限滥用**：APK 无启动图标，安装后申请通话记录、定位、短信、联系人等运行时权限；权限授予后由后台 Service 持续运行，普通用户难以发现。
- **伪装行为**：`HttpURLConnection` POST `http://playstorenet.ddns.net/Youtube/index.php`（multipart/form-data），从响应中提取 `MSG`、`URL` 字段，通过 `sendBroadcast(new Intent("MY_ACTION"))` 发给接收器；接收器 `Toast` 显示 `MSG`，若 `URL` 不以 `http://` 开头则补全，再用 `ACTION_VIEW` 打开网页。`URL` 在其余代码中并无实际用途，作者判断其目的是把自身伪装成一个会弹框报错的服务程序。
- **九类收集（ContentResolver/系统 API）**：
  - GPS：定位监听后拼接 `##LATLONG STARTS##`、时间、`LAT`/`LONG`；
  - 短信：查询 `content://sms/inbox`、`sent`、`draft`，取 `date`、`body`、`address`；
  - 联系人：`ContactsContract.Contacts.CONTENT_URI` 取 `display_name`，再用 `CommonDataKinds.Phone`/`Email` 关联号码与邮箱；
  - 通话记录：`CallLog.Calls.CONTENT_URI` 取 `number`、`type`（1/2/3 → INCOMING/OUTGOING/MISSED）、`date`、`duration`；
  - 设备信息：`Build.VERSION.RELEASE`/`Build` 字段、`getPhoneType`（GSM/CDMA）、`DeviceId`、`SimSerialNumber`、订阅者 ID；
  - 已安装应用：`PackageManager.getInstalledPackages(128)`，按 `applicationInfo.flags & 1` 跳过系统应用；
  - 账户：`AccountManager.getAccountsByType("com.google")` 与全部账户的 name/type；
  - 文件路径：递归 `Environment.getExternalStorageDirectory()`，筛选 `.pdf/.txt/.xml/.doc/.xls/.xlsx/.amr/.docx/.apk/.rec` 并记录绝对路径；
  - 基站：`PhoneStateListener` 监听 `LISTEN_CELL_LOCATION(16)`/`LISTEN_DATA_CONNECTION_STATE(64)`，`onCellLocationChanged` 处理 `GsmCellLocation`（cid/lac/operator/mcc/mnc）与 `CdmaCellLocation`（baseStationId/lat/long），并用 `getNeighboringCellInfo` 取相邻基站 RSSI/lac/cid。
- **落盘与上传**：数据按 `##FILE LIST STARTS##`、`##FILE LIST ENDS##`、`##APPS INFO`、`##ACCOUNT INFO`、`##CELL LOCATION` 等标记拼进缓冲区，通过 `InputSettings.writeFile` 写入 `/storage/sdcard0/systemservice`；`broadcast_execKeyboard` 触发上传服务，读取该文件并以 `multipart/form-data` POST 到 `home.php?IMEI=<DeviceId>&SIMNO=<SimSerialNumber>`。
- **基础设施关联**：VT 关系中样本外联 `playstorenet.ddns.net/Youtube/home.php`，IP `23.227.201.160`；Bitdefender Bitter APT 白皮书把 `playupdateatp.serveblog.net/Youtube/home.php` 列为该组织的用户数据外传站点之一，两个样本复用相同的 `Youtube/*.php` 路径结构。
- **为什么隐蔽**：无图标 + 权限诱导 + 合法外观的服务名 + 动态 DNS 域名 + 分段文本文件上传，都是 Android 间谍软件的常见伪装；静态上看不到传统 C2 心跳，只有一次性批量上传。

## 触发条件

- 用户安装该 APK 并授予短信、联系人、通话记录、定位等权限（或系统被诱导开启）。
- 设备可访问互联网与 `playstorenet.ddns.net`（动态 DNS）。
- 分析场景：静态/动态逆向样本，非漏洞利用。

## 利用步骤（分析步骤）

1. 记录样本元数据：`photos.apk`，701723 字节，MD5 `D20C6731E278A1D3202B4CAA0902AFA8`，SHA1 `B6353DAC1E425C3081F672ADF24D49B33E53A902`，CRC32 `4D82C814`，包名 `google.comgooglesettings`，证书 SHA1 `1173C15E0E3E69EE088CE0654CAB314F94DBD018`。
2. `aapt`/jadx 查看 Manifest：无 launcher 图标、后台 Service（`InputSettings`/`UpdateSettings`）与申请的敏感权限。
3. 定位 `index.php` POST 与广播接收器：确认 `MSG`/`URL` 提取、`MY_ACTION` 广播、Toast 与 `ACTION_VIEW` 的伪装逻辑。
4. 定位九类收集函数（`get_gps`、`get_messages`、`get_contacts`、`get_calllogs`、`get_phone_details`、`get_apps_info`、`get_account_info`、`get_somefile_list`、`get_phone_listen`/`onCellLocationChanged`）。
5. 跟踪 `InputSettings.writeFile` 与 `broadcast_execKeyboard`，确认落盘路径 `/storage/sdcard0/systemservice` 与上传 URL 参数 `IMEI`/`SIMNO`。
6. 在隔离环境抓包或沙箱运行，验证 POST 地址、multipart 内容与文件标记；用 VT/公开报告做家族关联。

## PoC

无 PoC（样本分析卡）。IOC/检测摘要：

```text
样本：photos.apk，701723 字节
MD5：D20C6731E278A1D3202B4CAA0902AFA8
SHA1：B6353DAC1E425C3081F672ADF24D49B33E53A902
包名：google.comgooglesettings
证书 SHA1：1173C15E0E3E69EE088CE0654CAB314F94DBD018
伪装/外联：http://playstorenet.ddns.net/Youtube/index.php（取 MSG/URL）
上传：http://playstorenet.ddns.net/Youtube/home.php?IMEI=<DeviceId>&SIMNO=<SimSerialNumber>
落盘：/storage/sdcard0/systemservice
关联 IP：23.227.201.160；同族外传站点 playupdateatp.serveblog.net/Youtube/home.php
数据段标记：##GPS / ##LATLONG / ##SESSAGES / ##CONTACTS / ##CALL LOG / ##PHONE DETAILS / ##APPS INFO / ##ACCOUNT INFO / ##FILE LIST / ##CELL LOCATION
```

## 变体与关联

- **同族 Android RAT 分析**：`mobile-android-ahmyth-rat-static-command-map`（AhMyth 指令映射）、`mobile-android-spymax-telegram-phishing-accessibility-keylogger-gzip-c2`（SpyMax）、`mobile-android-spynote-fake-police-accessibility-credential-theft`（SpyNote）、`mobile-android-spyware-clouddisk-contact-sms-photo-exfil`（云盘间谍）。
- **Bitter APT**：Bitdefender 白皮书《Bitter APT Revisited: The Untold Evolution of an Android Espionage Tool》列出的多个外传站点（blitzchatzlog.ddns.net、playupdateatp.serveblog.net、techfront.com.cn 等），本样本与之共享 `Youtube/*.php` 路径。
- **变体**：更换动态域名/邮箱/上传脚本；增加录音、拍照、屏幕录制、无障碍键盘记录；把数据分片/加密后上传。
- **边界**：C2 已失效时无法观察完整回包；静态分析依赖反编译可读性，混淆样本需动态辅助。

## 检测与防御

- **IOC 检测**：MD5/SHA1/包名/证书指纹；`/storage/sdcard0/systemservice` 文件；`##SESSAGES`/`##CALL LOG` 等分段标记；访问 `*.ddns.net/Youtube/*.php` 的 POST；`IMEI=`/`SIMNO=` 查询参数。
- **Android 侧**：检查无桌面图标但申请短信/联系人/通话/定位权限的应用；监控后台 Service 的 ContentResolver 批量查询；Play Protect/企业 MDM 拦截侧载与未知来源安装。
- **网络侧**：对动态 DNS 域名的出站连接做告警；识别非浏览器应用的 multipart 批量上传；结合证书/包名情报。
- **响应**：卸载样本、撤销权限、排查同来源 APK 与账号泄露；对泄露的短信/联系人/文件路径做风险评估与通知。
