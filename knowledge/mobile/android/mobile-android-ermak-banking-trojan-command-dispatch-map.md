---
id: mobile-android-ermak-banking-trojan-command-dispatch-map
title: Ermak（Ermac）Android 银行木马命令分发与能力映射：无障碍操控、录屏 VNC、USSD/短信/电话、凭据与 OTP 窃取
type: scenario
domain: mobile
path: mobile/android
technique: ermak-banking-trojan-command-dispatch-analysis
aliases:
- Ermak 银行木马
- Ermac 银行木马
- HookAPP
- Hook Builder
- University Duplex Math Builder
- com.pogetezurecigu.tamike
- Cerberus reborn
- Ermak 命令列表
tags:
- android
- malware
- banker
- ermak
- command-dispatch
- accessibility-service
- mediaprojection
- ussd
- sms
- cookie-theft
- otp
- malware-analysis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V425
  verified_at: '2026-11-09T17:19:10+08:00'
  notes: 已完整阅读原文并逐张核对34张图片：命令表47条与反编译片段（start_vnc/streamScreen、startussd/sim 选卡、send_sms_many/numbers 分号拆分、startAdmin 写 start_admin=1、forwardsms/number、getcallhistory/cnt、onpointerevent down/continue/up、clickatcontaintext 等）逐条吻合；Hook Builder/University Duplex 面板、包名 com.pogetezurecigu.tamike、证书 serial/thumbprint、2024-05-02 时间线与图01/03/04一致。核验时修正两处：命令数 49→47（原文表共47条）；VT 检出率原文表格 2/63 与同文图02截图 19/67 矛盾，已改为并记两值。未验证点：未动态运行样本、未取得C2完整报文（原文未给）。dedup 候选 AhMyth 命令映射/远程协助/SMS 银行木马均为不同家族与机制，不重复。dup-scan.json（2026-11-08）早于建卡且无本卡 pair。原文未给样本/家族版本，affected_versions 已 --clear。
---

## 一句话结论

Ermak（Ermac，Cerberus 的重生家族）样本 `HookAPP`（包名 `com.pogetezurecigu.tamike`）从 C2 接收 JSON 指令，按其中的 `cmd` 字段在混淆后的巨大 `if/equals` 分发链中解析参数（`numbers` 按 `;` 拆分、坐标 `x/y`、SIM 卡槽、`app`/`url`/`text` 等），再调用各混淆 helper 执行约 47 类命令（原文命令表共 47 条）——覆盖无障碍点击/手势/文本注入、MediaProjection 录屏与截屏（VNC）、USSD 执行、短信群发/转发、电话拨打/转接、Cookie/Gmail/账户/Google 身份验证器相关窃取、注入应用列表更新、设备数据收集与管理员权限请求；样本由 Web 端 Builder（伪装成 “University Duplex - Math Builder” 的面板）按勾选功能生成。

## 原理

- **命令分发架构**：C2 下发 JSON，代码用 `payload.getString("cmd")` 取出命令名，经过一个由大量 `if (v2_6.equals("...")) goto label_xxx;` 组成的混淆分发链。每个分支解析自己的参数并实例化/调用 helper 类；参数解析有明显模式：数字坐标先 `getString("x")` 再 `f4.h.A0()` 转 double、失败时 `Integer.parseInt`；`numbers` 以 `;` 分割；`sim` 参数用 `i.a(getString("sim"),"sim2")` 选择卡槽；应用/文本参数直接 `getString("app"/"url"/"text")`。
- **能力分组**（按原文命令表与反编译分支整理）：
  - **无障碍远程操控**：`clickat`、`clickattext`、`clickatcontaintext`、`onpointerevent`（解析 `text/x/y` 与 `down/continue/up` 事件）、`tap`、`swipe`/`swipeup`/`swipedown`/`swipeleft`/`swiperight`、`longpress`、`settext`、`cuttext`、`removeview`/`removewaitview`；用于在银行 App 内代替受害者点击、输入、滑动、剪贴，绕过界面交互。
  - **屏幕与媒体**：`start_vnc`/`stop_vnc`（启动带 `streamScreen=true` extra 的混淆 Activity，配合 MediaProjection 持续回传屏幕）、`takescreenshot`、`takephoto`、`getimages`、`downloadimage`。
  - **电话与短信/USSD**：`startussd`（按 `sim` 参数选择 SIM1/SIM2 后执行 USSD 代码）、`send_sms_many`（`numbers` 分号分隔批量发送）、`sendsms`/`sendsmsall`、`forwardsms`、`makecall`/`calling`（`ACTION_CALL` 带 `number` 与 `lock` 标志）、`forwardcall`、`getcallhistory`（带 `cnt` 数量）。
  - **凭据与 OTP**：`cookie`（访问指定 `url` 获取 Cookie）、`getgmailmessage`、`getaccounts`、`logaccounts`、`startauthenticator2`（拉起 Google 身份验证器）、`getcontacts`、`addcontact`。
  - **应用与覆盖**：`updateinjectandlistapps`（刷新注入目标应用列表）、`push`（按 `app/title/text` 弹通知，点击启动指定应用）、`startapp`、`deleteapplication`、`clearcache`、`openwhatsapp`。
  - **侦察与提权**：`getlocation`、`getinstallapps`、`logaccounts`、`startAdmin`（向 SharedPreferences 写 `start_admin=1` 并触发设备管理员权限请求）。
- **Builder 商品化**：样本由 Web 面板生成，面板（伪装名 “University Duplex - Math Builder”）提供通用 APK 设置（回连 URL、无障碍服务名、白名单 App、日志 Java 类）与构建参数勾选项（屏幕录制、截屏、键盘记录、隐藏图标、短信列表、删除应用、文件、账户、发送短信、拨打电话、电话转接、推送、VNC 等），说明该家族把远程控制/欺诈能力做成了可按需勾选的产品。
- **混淆与免杀**：包名/类名随机无意义（`com.pogetezurecigu.tamike`、helper `com.vemotogeroziha.donuyi.nezuze.rigepegexodovofu`），控制流用 goto 扁平化；VT 检出率低（原文表格记 2/63，但同文 VT 截图为 19/67，两处数据不一致），证书信息随机（serial `e767fa93b6d398d5`、thumbprint `7966d9a6...`），发布 2024-05-02 左右。
- **为什么危险**：无需 root，只靠用户授予无障碍/录屏/短信/电话/管理员等权限，就能在设备上实时看屏、代替用户操作银行 App、读取短信验证码与邮件、拨打电话并转接、执行 USSD 业务，构成完整的“设备接管 + 交易欺诈 + OTP 拦截”能力。

## 触发条件

- 用户安装并运行 APK，按引导授予无障碍服务、MediaProjection 录屏、短信/电话/联系人/位置/相机等权限（部分命令需要管理员权限）。
- 设备可访问 C2；攻击者控制端已上线并能下发 JSON 指令。
- 目标银行/支付类 App 未做无障碍检测、界面防截屏或完整性校验；系统未限制无障碍/录屏权限。
- 样本未被应用商店/终端安全拦截（当时 VT 检出率很低）。

## 利用步骤

（按样本行为与命令表还原，非攻击复现）

1. 安装运行后，木马回连 C2，上报设备与权限状态；控制端按需下发 `{"cmd":"<命令>", ...参数}`。
2. 分发链按 `cmd` 进入分支：如 `start_vnc` 启动 `streamScreen=true` 的 Activity 开始 MediaProjection 录屏；`cookie` 访问指定 URL 取 Cookie；`startussd` 按 `sim` 选择卡槽执行 USSD。
3. 遥控类命令（`clickattext`/`onpointerevent`/`swipe` 等）通过无障碍服务在银行 App 界面注入点击/文本/手势；`updateinjectandlistapps` 更新要覆盖的银行 App 列表。
4. 数据类命令（`getgmailmessage`/`getaccounts`/`getcontacts`/`getcallhistory`/`getlocation`/`getinstallapps`）收集信息；`push` 用伪造通知诱导用户打开指定 App。
5. 攻击者利用短信/邮件/通知中的验证码、通话转接与 USSD 完成账户接管或资金操作。

## PoC

原文未提供可执行 PoC（样本分析与命令表）。可复现的分发链形态（按反编译截图重写，命令字符串为样本值）：

```java
// 简化后的分发链形态
String cmd = payload.getString("cmd");
if (cmd.equals("start_vnc")) {
    // 启动带 streamScreen=true extra 的 Activity，开始录屏
} else if (cmd.equals("startussd")) {
    String ussd = payload.getString("ussd");
    int sim = helper.a(payload.getString("sim"), "sim2") ? 1 : 0;
    new s1.p(sim, context, ussd);           // 按卡槽执行 USSD
} else if (cmd.equals("send_sms_many")) {
    String numbers = payload.getString("numbers");
    for (String n : numbers.split(";")) { /* 批量发送短信 */ }
} else if (cmd.equals("clickatcontaintext")) {
    helper.b(payload.getString("text"));    // 无障碍点击包含指定文本的控件
} else if (cmd.equals("updateinjectandlistapps")) {
    helper.c(helper.i);                     // 刷新注入目标应用列表
}
```

```text
# 命令 → 能力映射（原文命令表节选）：
start_vnc / stop_vnc / takescreenshot       屏幕录制、截屏
startussd                                  执行 USSD（sim/sim2 选卡）
send_sms_many / sendsms / sendsmsall       批量/指定/全联系人发送短信
forwardsms / forwardcall / makecall        短信转发、电话转接、拨打电话
clickat / clickattext / clickatcontaintext 无障碍按坐标/文本点击
onpointerevent / tap / swipe* / longpress  手势注入
cookie / getgmailmessage / getaccounts     Cookie、Gmail、账户信息窃取
startauthenticator2                        拉起 Google 身份验证器（OTP 相关）
updateinjectandlistapps / push / startapp  注入列表更新、通知诱导、启动应用
getlocation / getinstallapps / getcontacts 设备与联系人信息收集
startAdmin                                请求设备管理员权限
```

## 变体与关联

- [[mobile-android-ahmyth-rat-static-command-map]]：同为 Android RAT 的“命令映射/静态能力清单”分析卡；AhMyth 用 Socket.IO 七类 Manager 指令，Ermak 是银行木马，命令面更广（无障碍、VNC、USSD、OTP）。
- [[mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc]]：无障碍操控 + MediaProjection 录屏的通用高权限远控链路；Ermak 的 `start_vnc`/点击手势命令与之同源，可作为该链路的银行木马实例。
- [[mobile-android-sms-received-forward-c2-number-banking-trojan]]：另一银行木马的短信拦截/转发实现，可与 Ermak 的 `forwardsms`/`send_sms_many` 对照。
- [[mobile-android-spynote-fake-police-accessibility-credential-theft]]：无障碍窃取凭据的另一家族。
- 变体：命令名与参数可按 builder 配置变化；能力可裁剪（勾选式构建）；C2 协议可换成 WebSocket/MQTT；无障碍操控可扩展为读屏+自动填写转账。
- 边界：用户拒绝无障碍/录屏权限、Android 高版本限制后台启动与录屏、银行 App 启用无障碍检测/防截屏、C2 下线时能力失效；原文未给出 C2 协议完整报文，命令参数名来自反编译片段。

## 检测与防御

- 检测：应用同时申请 `BIND_ACCESSIBILITY_SERVICE`、`MediaProjection`、`SEND_SMS`/`READ_SMS`、`CALL_PHONE`、`READ_CONTACTS`、`READ_CALL_LOG`、`DEVICE_ADMIN` 等组合；代码中出现大批命令字符串（`start_vnc`、`startussd`、`send_sms_many`、`clickatcontaintext`、`updateinjectandlistapps`、`startauthenticator2` 等）。
- 检测：随机包名/类名 + goto 扁平化分发链；C2 JSON 中的 `cmd` 字段；VT 家族标签 Ermac/Ermak；Builder 面板产物特征（固定权限/服务名）。
- 防御：用户不授予无障碍/录屏权限给非可信应用；Android 企业策略限制侧载与无障碍；银行 App 启用无障碍检测、FLAG_SECURE 防截屏、输入完整性校验；应用商店与 EDR 对上述命令字符串与权限组合扫描。
- 响应：卸载样本、撤销无障碍/管理员/录屏授权、检查短信发送记录与通话转接设置、修改银行与邮箱密码/撤销会话、联系运营商核查 USSD/增值业务；提取 C2 与 builder 面板做家族关联。
