---
id: mobile-android-spynote-fake-police-accessibility-credential-theft
title: 仿冒公安网站投递 SpyNote RAT：无障碍服务窃取锁屏/金融/钱包凭据并阻止卸载
type: scenario
domain: mobile
path: mobile/android
technique: android-spynote-fake-police-accessibility-credential-theft
aliases:
- SpyNote RAT
- 仿冒公安网站
- 110gongan.com
- 无障碍服务窃取密码
- 锁屏密码窃取
- 金融应用密码窃取
- 虚拟货币钱包劫持
- Gate.io 转账劫持
- Binance 提币劫持
- Android 防卸载
tags:
- android
- malware
- spyware
- rat
- accessibility-service
- credential-theft
- overlay-attack
- phishing
- apk
- spynote
- financial-fraud
- crypto-wallet
- persistence
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:40:07+08:00'
  notes: 已对照原文与30张图核对：诱饵页 triggerDownload/apkUrl、无障碍授权话术、伪造锁屏、锁屏/金融应用/币安/Gate.io/TokenPocket 包名与 View ID、截屏与 MediaProjection 录屏、按品牌防卸载、fusu666.cc WebSocket/report.php 与 IOC 均与原文一致。未验证点：样本归因 SpyNote 仅凭原文结论，未独立比对家族特征；图09 模拟器中 gaj.nanjing.gov.cn 实际 ERR_NAME_NOT_RESOLVED，卡片未声称加载成功；未动态运行样本；frontmatter 未含 sources/source_url。
---

## 一句话结论

仿冒公安的钓鱼站点（`110gongan.com` 及同页面的 IP 镜像）以“公安一网通办/安全检测”为诱饵，诱导用户下载 APK（包名 `com.gameclicker.autoclicker.pro`）；应用申请无障碍服务后读取屏幕与输入事件，伪装锁屏页骗取锁屏密码，窃取支付宝/微信支付/多家银行及 Trust Wallet、TokenPocket、imToken 等钱包密码，通过覆盖层劫持 Gate.io 转账并读取短信/邮箱/Google 验证码、替换收款地址，自动确认 Binance 提币，按品牌自动点击“取消”阻止卸载，最终经 WebSocket（`fusu666.cc`）外联。

## 原理

- **诱饵与投递**：站点仿冒公安“一网通办”页面，页面任意点击触发下载；页面源码中的 `triggerDownload()` 把 `const apkUrl` 指向 `https://207.56.30.188:37095/down/2ZMHNO2OqgKa.apk`，创建隐藏 `<a download>` 触发下载。第二个站点 `https://207.56.30.194` 页面相同、APK 地址相同，属于同一套钓鱼基础设施。
- **伪装与授权引导**：APK 图标伪装成“安全检测”类系统工具；启动后弹窗以“因网络受限本次需要开启权限才能使用”为由，引导用户点击“确定 → 打开已下载服务 → 安全检测 → 开始使用 → 等待加载 100%”；随后弹出系统无障碍授权页“要允许安全检测完全控制您的设备吗？”，并说明可“查看和控制屏幕”“查看及执行操作”。应用内嵌 WebView 加载真实的南京公安网站 `gaj.nanjing.gov.cn` 作为内容伪装，降低用户疑心。
- **锁屏密码窃取**：样本用无障碍事件识别 `com.android.systemui` 的锁屏控件：`passwordEntry`（标准 PIN/密码）、`passwordEntry + btn_letter_ok`（字母键盘）、`securityEditText`/`pwd_input_layout`（安全输入框）、`mix_up`（混合密码）等；当用户输入时读取文本变化并暂存，配合伪造的锁屏页面诱导输入，从而拿到真实锁屏密码。
- **金融应用密码窃取**：样本按应用标识符收集各类密码：`alipaynew`（支付宝）、`wecpaynew`（微信支付）、`yunnew`（云闪付）、`jiannew/younew/nongnew/zhongnew/gongnew/zhaonew`（建行/邮储/农行/中行/工行/招行）、`gpaynew`（Google Pay）、`phonepenew`（PhonePe）、`ananew`（安安支付）、`mbnew/bcnew`（MB/BC 银行）、`twpwd`（Trust Wallet）、`paytp`（TokenPocket）、`payim`（imToken）、`paycy`（Mona）。代码按应用包名/输入框 ID 识别密码框，读取文本事件并拼装外发。
- **Binance 提币劫持**：当无障碍事件出现 `com.binance.dev` 的提币确认相关 View ID（`2131365306`、`2131365309`、`2131430824`、`2131430869`）时，样本自动触发验证码/确认操作，在用户不知情下完成提币确认。
- **Gate.io 转账劫持**：包名 `com.gatei0.cn.gatei0`（仿冒/抢注域名样式）；样本监测提币确认页 View ID，创建覆盖层页面盖在正常页面上，用户点击确认时实际点到覆盖层按钮；随后读取 `sms_code_input`（短信验证码）、`email_code_input`（邮箱验证码）、`google_code_input`（Google 验证码）的当前内容，并把收款地址注入/替换为攻击者地址，完成转账劫持。
- **TokenPocket 钱包密码窃取**：监测 `vip.mytokenpocket:id/edt_dialog_pwd` 密码输入框；输入框获得焦点后记录后续所有文本变化；当窗口状态变化事件包含“TokenPocket”文本时判定输入完成，保存密码。
- **截屏与录屏**：样本使用无障碍截屏回调（`AccessibilityService.takeScreenshot` 的 `ScreenshotResult` + `Bitmap.wrapHardwareBuffer`）把屏幕压缩为 WEBP/Base64 外发；录屏部分使用 `MediaProjection`/`ImageReader`/虚拟显示等接口采集画面（原文截图显示 `createVirtualDisplay`、`ImageReader.newInstance`）。
- **防卸载**：读取设备品牌，按品牌匹配卸载界面元素并自动点击“取消/negative”按钮：华为 `com.huawei.android.launcher:id/delete_item`、小米 `com.miui.home:id/title`、OPPO `com.oppo.launcher:id/txt_uninstall_main_title` + `btn_negative`、Vivo `com.bbk.launcher2:id/uninstall_title`、三星/其他 `android:id/alertTitle`、荣耀 `com.hihonor.android.launcher:id/delete_item`/`delete_item_enhanced`。用户点卸载时实际被引导点到取消，从而阻止卸载。
- **外联**：字符串经 XOR 混淆后存放；解密后可见 `public static String mydom = "fusu666.cc"`，WebSocket 地址为 `wss://fusu666.cc/api/ws/?dk=60531725ccc66ecdc64b70aa850e8c4ab29a449ef90e4723b5e7eefc984f52a0`，错误上报 `https://fusu666.cc/api/report.php`。
- **为什么危险**：整条链不依赖 Android 系统漏洞，只利用用户对“公安”品牌的信任和对无障碍权限的误解；无障碍服务一旦开启，样本可以读屏、注入点击、监听所有应用输入，绕过锁屏与部分双因素保护，直接威胁资金账户。防卸载机制进一步延长驻留时间。

## 触发条件

- 用户在 Android 设备上访问仿冒站点，下载并侧载 APK（Play Protect/MDM 未拦截，系统允许未知来源安装）。
- 用户在诱导下启用无障碍服务，并授予应用所需的悬浮窗/通知/存储等权限；Android 高版本对无障碍授权有额外确认，但社工话术可降低戒心。
- 设备上安装了被针对的金融/支付/钱包应用（支付宝、微信、银行、Binance、Gate.io、TokenPocket 等），且用户会在其中输入密码或进行提币/转账。
- 设备可访问 C2 域名 `fusu666.cc`（WebSocket 443）；应用未被安全软件查杀或卸载。
- 目标 Android 版本支持样本使用的无障碍截屏/MediaProjection 接口；样本对品牌卸载界面的适配依赖具体 ROM 版本。

## 利用步骤

（以下按攻击链/分析顺序描述，非本机复现。）

1. **投放诱饵**：搭建仿冒公安“一网通办”页面，任意点击触发 APK 下载；准备多个镜像域名/IP 与同一 APK 地址，页面内嵌真实公安网站内容增加可信度。
2. **诱导安装与授权**：以“安全检测/网络受限需开启权限”为由，逐步引导用户打开应用、点击确定、进入无障碍设置并允许“查看和控制屏幕/执行操作”。
3. **伪装运行**：应用启动后加载真实公安网站 WebView，显示“安全检测/加载 100%”等界面；在需要时弹出伪造锁屏页，骗取锁屏密码。
4. **凭据收割**：无障碍服务持续监听窗口/文本事件，按包名与 View ID 识别锁屏、银行/支付/钱包密码框和提币确认页；记录输入、读取验证码、自动点击确认。
5. **交易劫持**：对 Gate.io 等创建覆盖层，诱导点击确认并注入攻击者收款地址；对 Binance 自动完成提币确认；对 TokenPocket 记录钱包密码。
6. **数据外带与驻留**：截屏/录屏、收集凭据后经 WebSocket 发往 `fusu666.cc`；按品牌自动点击卸载对话框的“取消”阻止卸载，保持驻留。
7. **验证/分析**：在模拟器安装样本，观察无障碍授权弹窗、内嵌 WebView、伪造锁屏页；用 JADX 反编译并按 View ID/包名/域名检索，确认上述能力。

## PoC

原文为恶意样本分析，没有提供攻击 PoC；可用以下方式复现能力面（未在本机执行）：

```bash
# 反编译 APK（样本有字符串异或混淆，先解混淆再检索）
jadx -d out/ sample.apk

# 关键能力关键词
grep -RInE "AccessibilityService|onAccessibilityEvent|takeScreenshot|MediaProjection|createVirtualDisplay" out/
grep -RInE "passwordEntry|securityEditText|mix_up|btn_letter_ok" out/
grep -RInE "com.binance.dev|com.gatei0.cn.gatei0|vip.mytokenpocket|alipaynew|wecpaynew" out/
grep -RInE "fusu666|/api/ws|report.php" out/
```

```text
IOC:
sha256  c692ad120cc90548d48dbe57d006f2403c49833b8993af3c38fe031eb39999bd
package com.gameclicker.autoclicker.pro
domains fusu666.cc / 110gongan.com / gongan.us.ci / fusu.us.ci
IPs     207.56.30.188 / 207.56.30.194
APK     https://207.56.30.188:37095/down/2ZMHNO2OqgKa.apk
C2      wss://fusu666.cc/api/ws/?dk=60531725ccc66ecdc64b70aa850e8c4ab29a449ef90e4723b5e7eefc984f52a0
```

## 变体与关联

- **同族/同类**：SpyNote RAT 家族及其定制版；其他滥用无障碍的 Android 银行木马（Cerberus/Anatsa/Hook 类）、屏幕共享诈骗、远程协助类 APK。能力面识别可参考 [[mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc]]。
- **诱饵变体**：仿冒公安/ETC/税务/社保/航空公司/快递等政务或生活服务页面；APK 伪装成“安全检测/政策查询/补贴申领”工具；多镜像域名/IP、短链跳转、二维码分发。
- **能力变体**：覆盖层（tapjacking）骗取确认、读取 OTP、注入收款地址、自动确认提币；无障碍录屏/截屏；通知监听获取验证码；设备管理员/无障碍防卸载；WebSocket/HTTP 双通道 C2。
- **分析关联**：字符串 XOR 批量还原见 [[mobile-android-apk-xor-string-batch-deobfuscation]]；加固 APK 查壳脱壳见 [[mobile-android-packer-apkid-frida-dexdump-jadx]]；SSL Pinning 绕过见 [[mobile-android-ssl-pinning-bypass-cert-frida]]。
- **边界**：需要用户手动开启无障碍；部分 ROM 对无障碍/悬浮窗/后台限制较严；目标应用升级可能改变 View ID；C2 域名可能被接管/下线；样本主要针对中文用户与特定金融/钱包应用。

## 检测与防御

- **终端侧**：检查“设置 → 无障碍”中不明应用（尤其名为“安全检测/系统服务”）；关闭未知来源安装；用 Play Protect/厂商安全中心扫描；对已安装样本，进入安全模式卸载或恢复出厂；检查悬浮窗/通知监听/设备管理员权限。
- **网络侧**：封禁 `fusu666.cc`、`110gongan.com`、`gongan.us.ci`、`fusu.us.ci` 及上述 IP；监控 WebSocket 连接与 `/api/ws/`、`/api/report.php` 路径；对政务仿冒域名做证书/WHOIS/页面指纹监测。
- **静态检测**：`AndroidManifest.xml` 中 `BIND_ACCESSIBILITY_SERVICE` 声明与无障碍配置；代码中的 `onAccessibilityEvent`、`takeScreenshot`、`MediaProjection`、`createVirtualDisplay`；大量 `com.android.systemui:id/*`、支付/钱包包名与 View ID；WebSocket/HTTP C2 字符串；XOR 字节数组混淆特征。
- **动态检测**：安装后观察无障碍授权诱导、内嵌 WebView 访问真实政务站、伪造锁屏页；监控无障碍事件读取密码框、覆盖层窗口、自动点击卸载对话框；抓包看 WebSocket 外联与上报。
- **防御建议**：企业和个人不侧载来源不明的“政务/安全”APK；通过官方应用商店或政务官方渠道办理业务；对高危人群开启 MDM/应用白名单；Android 企业版限制无障碍服务与悬浮窗；金融机构 App 增加防覆盖层（`setFilterTouchesWhenObscured`）、禁止无障碍读取敏感输入框、检测无障碍服务滥用；用户定期审查已授权无障碍应用。
