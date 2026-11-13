---
id: mobile-android-joker-beauty-wallpaper-dex-webview-sms
title: Joker 家族 Beauty Wallpaper HD 与其 DEX 衍生物剖析：远程指令驱动 WebView 自动订阅，JavascriptInterface 暴露短信收发删与自定义 HTTP
type: scenario
domain: mobile
path: mobile/android
technique: joker-family-dex-webview-sms-triage
tags:
- android
- malware
- joker
- dex
- webview
- javascriptinterface
- sms
- subscription-fraud
- dynamic-loading
- c2
cve: []
severity: high
confidence: high
affected_versions: Beauty Wallpaper HD 1.0.16（com.wellnone.wallpaper，2023-09-14 更新）
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V675
  verified_at: '2026-11-13T11:43:24+08:00'
  notes: 已对照原文与15图核对：远程指令 switch case 1000-1008（cmd_timeout/page_timeout/hold/load_url/entry_timeout/wait_pin/sleep/do_nothing/wait_mo）、@JavascriptInterface（moSend/injectNumber/ajaxGet/customAjax/customSubmit/recaptcha/imageDama/dpage 等）、SMS_RECEIVED 监听、Telephony.Sms.CONTENT_URI 删除、设备信息 JSON POST http://nicephoto.biquaurall[.]site:8080/device/、onReceive PIN、viplive[.]win 载荷 404 均与截图一致；affected_versions 1.0.16 与 2023-09-14 在原文图（VirusTotal 文件名 Beauty Wallpaper HD_1.0.16_apkcombo.com.apk、APKSos Version 1.0.16/Updated September 14, 2023）显式可见，保留；已修正两处措辞（资源下线表述改为2023-09-21抓包时已删除、删去“桥接方法击”笔误）。样本未执行，仅静态核对。
url: /docs/mobile/android/mobile-android-joker-beauty-wallpaper-dex-webview-sms/
draft: false
kb_aliases:
- Joker 家族分析
- Beauty Wallpaper HD 恶意样本
- com.wellnone.wallpaper
- abc.png-v265.tmp
- Android SP 订阅欺诈
- WebView JavascriptInterface 滥用
- Joker 短信窃取
---

## 一句话结论

Joker（Bread）家族的 Beauty Wallpaper HD（`com.wellnone.wallpaper`，1.0.16，2023-09 上架 Google Play）在运行后从 C2 下载伪装成 `abc.png-v265.tmp` 的 59KB DEX 动态加载；该 DEX 用一组远程指令（`cmd_timeout`/`page_timeout`/`hold`/`load_url`/`entry_timeout`/`wait_pin`/`sleep`/`do_nothing`/`wait_mo`）驱动 WebView，并通过 `@JavascriptInterface` 把注入号码、发送/接收/删除短信、自定义 ajax 提交、验证码打码等能力暴露给页面脚本，实现自动订阅收费 SP 服务与短信窃取。

## 原理

- **Joker 家族模式**：主 APK 以正常壁纸应用为外壳，运行时下载小型恶意 DEX 动态加载（本例衍生物 `abc.png-v265.tmp`，59KB，无独立包名），把恶意代码与审核面分离；Google Play 上架时仅 2/63 引擎检出（Kaspersky/ZoneAlarm 报 `HEUR:Trojan.AndroidOS.Joker.zy`）。
- **远程指令状态机**：DEX 的 Handler 对 `Message.what` 做 switch，把数字指令映射为字符串动作：1000 `cmd_timeout`、1001 `page_timeout`、1002 `hold`（执行指定 Javascript）、1003 `load_url`（加载页面）、1004 `entry_timeout`、1005 `wait_pin`（等待 PIN 确认码）、1006 `sleep`、1007 `do_nothing`、1008 `wait_mo`。服务端据此按步骤驱动 WebView 完成订阅流程（打开运营商/SP 页面 → 等待 → 注入号码 → 执行 JS → 等待验证码/PIN）。
- **JS 桥即能力集**：`@JavascriptInterface` 暴露的方法覆盖整条订阅欺诈链：
  - `injectNumber(s)`：把用户手机号注入页面表单，免手工输入；
  - `moSend(address, content)`：用 `SmsManager` 直接发短信（含 `SENT_SMS_ACTION`/`DELIVERED_SMS_ACTION` PendingIntent 状态回调），用于向 SP 服务号上行订阅/确认短信；
  - `hold`/`customAjax`/`customSubmit`/`ajaxGet`：页面脚本可发起任意 GET/POST（自定义 URL/body），绕过同源限制提交订阅请求；
  - `recaptcha(s, step, json)` 与 `imageDama(get/post, url)`：对接外部打码平台（v2/v3 参数携带 `website_url`/`website_key`/`action`/`score`，或 `recaptcha_task_id`），自动过验证码；
  - `dpage`/`addComment`/`cmdRunCount`/`stopTask`/`getOp`/`getScreen`：页面下载、日志上报、指令计数、停止任务、SIM 运营商与屏幕尺寸采集。
- **短信窃取与控制**：注册 `SMS_RECEIVED` 广播监听新短信（号码+正文保存并回调），`Telephony.Sms.CONTENT_URI` 查询/删除短信（先尝试作为默认短信应用执行 `tryDeleteSMS`），可在收到银行/验证码短信时删除以隐藏扣费通知。
- **设备信息外传**：把 CPU、小区信息（MCC/MNC）、GPS、电量等打包为 JSON POST 到后台 `http://nicephoto.biquaurall[.]site:8080/device/`；启动时还有 BroadcastReceiver 收集 PIN（日志 `onReceive PIN:`）。
- **为什么隐蔽**：主 APK 功能正常、权限申请与壁纸应用匹配；恶意逻辑在动态下发的 DEX 中，静态扫描与商店审核难以覆盖；DEX 文件名伪装为图片缓存（`abc.png-v265.tmp`），且下载地址使用多个域名（`viplive[.]win`、`nicephoto.biquaurall[.]site`）。

## 触发条件

- 用户在 Google Play/第三方商店安装该应用（Android 4.0+），并授予短信/电话权限（低版本安装即授予）。
- 设备能访问 C2 以下载恶意 DEX（本例资源 2023-09-21 抓包时已从服务器删除，返回 404）。
- 分析侧：拿到 APK 或 DEX 样本，具备 jadx/JEB 静态反编译与抓包环境；运行样本须隔离。

## 分析步骤

1. 计算 APK/衍生物哈希（APK MD5 `5d53a4977ceddd86083c0ae66f3b3133`，DEX MD5 `627f6746d8d1eb9afdf067968e4122d3fc8f3a14`），VirusTotal 仅 2 家检出。
2. 静态反编译主 APK，检索动态加载入口（DexClassLoader/InMemoryDexClassLoader、下载文件名 `.png`/`.tmp`）与 C2 URL。
3. 反编译衍生物 DEX，检索 `@JavascriptInterface` 注解与 `addJavascriptInterface` 调用，列出全部桥接方法与参数（见上表）。
4. 搜索指令码/字符串（`cmd_timeout`、`load_url`、`wait_pin` 等）还原远程指令 switch 表与 Handler 逻辑。
5. 审计短信能力：`SmsManager.sendTextMessage`、`SMS_RECEIVED` 广播、`Telephony.Sms.CONTENT_URI` 的 query/delete；确认删除短信与默认短信应用判断逻辑。
6. 抓包确认设备信息外传与 DEX 下载地址；对 `abc.png-v265.tmp` 与 `viplive[.]win/*.log` 等路径做落盘/请求样本留存。

## PoC

无可用 PoC（恶意样本为实测对象，原文为分析报告；资源 2023-09-21 抓包时已下线）。核心证据为样本反编译片段：远程指令 switch 表（`case 1000..1008`）与 `@JavascriptInterface` 方法（`moSend`/`injectNumber`/`recaptcha`/`customSubmit`/`ajaxGet` 等）的源码截图。

## 变体与关联

- 变体：Joker 后续变体会更换包名/证书、把 DEX 加密或分片下载、把下载文件名伪装为图片/字体/缓存；指令码与 JS 桥方法名可能微调，但"远程指令 + WebView 自动订阅 + 短信操作"的组合稳定。
- 关联：Android 恶意样本静态剖析方法参考 [[mobile-android-ahmyth-rat-static-command-map]]、[[mobile-android-droidjack-sandrorat-controller-module-command-map]]（同为指令映射式远控分析）；WebView JS 桥脆弱性见 [[mobile-android-webview-jsbridge-arbitrary-origin-credential-theft]]。
- 边界：资源下线后仅能静态分析；不同 Android 版本短信权限策略（默认短信应用、READ_SMS 限制）会影响行为复现。

## 检测与防御

- 检测（端侧/EDR）：监控应用从非商店域名下载并以 `.png/.tmp` 等伪装后缀落盘、再由 `DexClassLoader`/`InMemoryDexClassLoader` 加载的行为；申请 READ/SEND/RECEIVE_SMS 组合的壁纸/工具类应用；WebView 加载与主业务无关的运营商/SP 页面并调用 `addJavascriptInterface` 的桥接方法；短时间多笔 SP 扣费短信与短信被删除。
- 检测（IOC）：发布者邮箱 `fm0989184@gmail[.]com`；载荷 `https://viplive[.]win/G7B8B9S79SH8H0DWNK9L.log`；后台 `http://nicephoto.biquaurall[.]site:8080/device/`；证书 MD5 `7af3f792457692ff9dd2b47d29911c82`。
- 防御：应用商店加强动态行为检测（安装后侧载 DEX）；用户避免安装小众/新上线应用、限制短信权限；企业 MDM 禁用未知来源与动态代码加载。
