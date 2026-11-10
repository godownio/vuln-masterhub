---
id: code-analysis-reverse-macos-movist-paddle-trial-bypass-surfaces
title: macOS Movist Pro（Paddle SDK）试用期/授权校验的多面绕过：本地立即数、服务端 duration、activated 分支、弹窗 NOP 与客户端缓存
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: macos-paddle-trial-license-bypass-surfaces
aliases:
- Movist Pro 试用绕过
- Paddle SDK 试用期
- setTrialLength 补丁
- Paddle v3.product.data duration
- activated 分支修改
- showProductAccessDialogWithProduct NOP
- macOS 软件授权逆向
- lldb 0x1001B9062
tags:
- macos
- reverse-engineering
- objective-c
- swift
- lldb
- paddle
- license
- trial
- binary-patching
- nop
- cache
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V305
  verified_at: '2026-11-08T11:34:15+08:00'
  notes: 已对照原文核对：IDA 字符串/xref、0x1001B9062 BF 07→09 与 lldb 断点、Burp v3.paddleapi.com/3.2/product/data duration 7→9999999 显示 9999993 天、断网 NSURLErrorDomain -1009 后显示 9999993 天、0x1001B9E47 test al,al/jz 0x1001B9E4E 改 0F85 后弹 License 窗口、0x1001BDF00 附近 90 NOP 去弹窗，均与 29 张图一致。路径 code-analysis/reverse 存在且合法。未验证点：未在本机复跑，Paddle 通杀未实现，偏移依赖该版本 Movist Pro。
---

## 一句话结论

对使用 Paddle SDK 的 macOS 应用 Movist Pro，试用期/授权校验存在四个可绕过的面：改本地 `setTrialLength:` 的立即数（会被服务端覆盖而无效）、改 Paddle `v3.product.data` 响应里的 `trial.duration`（直接生效）、改 `activated` 判断分支或 NOP 掉 `showProductAccessDialogWithProduct:` 弹窗（强制走已授权路径）、以及利用客户端对服务端试用数据的缓存（断网仍显示超长试用期）。

## 原理

- **本地试用长度只是“默认值”**：IDA 字符串搜索 `trial`/`subscriptionTrialPeriod` 命中 `setTrialLength:` 等 Objective-C selector；唯一 xref 在 `sub_1001B8EE0`，伪代码为 `NSNumber.init(integerLiteral:)(7)` → `objc_msgSend(v4, "setTrialLength:", isa)`，与用户看到的 7 天试用一致。汇编为 `0x1001B9062: BF 07 00 00 00 mov edi, 7`，把 `07` 改成 `09`（`BF 09 00 00 00`）后用 lldb `b 0x1001B9062` 断下可见 `movl $0x9, %edi`，但界面仍是 1 天——因为 Paddle SDK 的 `PADProduct.refresh` 会从卖家后台拉取产品数据，官方文档明确“remote values will supersede local”，服务端下发的 `trial.duration` 覆盖了本地设置。这说明只改本地立即数是“假入口”。
- **服务端响应决定试用期**：Burp 抓到 `POST https://v3.paddleapi.com/3.2/product/data`，响应 JSON 含 `"trial":{"text":"...","duration":7}`、`base_prices.USD=7.99`、`checkout_secret_key`、`payment_url` 等；把 `duration` 改成 `9999999` 后，客户端弹窗显示“试用期还剩余 9999993 天”（已消耗 6 天）。客户端信任该字段且未做签名/范围校验（`signature` 字段存在但未阻止篡改），是服务端响应篡改能生效的原因。
- **客户端缓存让绕过持久化**：成功改包后断网，应用日志出现 `NSURLErrorDomain Code=-1009`“似乎已断开与互联网的连接”、连接 `checkout.paddle.com` 失败，但试用弹窗仍显示 9999993 天；Paddle 的 `PADProduct` 是“产品的本地表示”，会把上次刷新的剩余试用天数/激活日期缓存在本地，刷新失败时保留旧值——于是“断网 + 已缓存超长试用期”成为离线绕过。
- **`activated` 分支控制**：字符串 `showProductAccessDialogWithProduct:` 是 Paddle 触发产品访问弹窗的方法。`sub_1001B9E30` 伪代码先 `objc_msgSend(a1, "activated")`：已激活则创建 `LicenseViewController` 并 `runModalForWindow:`，未激活则 `objc_msgSend(a2, "showProductAccessDialogWithProduct:", v9)`。汇编在 `0x1001B9E47` 调 `objc_msgSend`、`test al,al`、`0x1001B9E4E: 0F 84 D2 00 00 00 jz loc_1001B9F26`；把该条件跳转改成恒走“已激活”路径（或直接改 `activated` 返回值），即可弹出 License 窗口（Address/Deactivate/License/OK）并正常使用。
- **NOP 掉弹窗**：更直接的做法是把调用 `showProductAccessDialogWithProduct:` 的代码块用 `90`（NOP）覆盖，令其不执行任何操作；文章在 `0x1001BDF00` 一带把相关指令批量改为 `90`，重启后不再弹试用提示，播放器可正常播放视频。
- **Paddle 框架通用面**：文章最后提到可参考“Paddle 激活类 Mac 应用通杀”思路，从框架层（`Paddle`/`PADProduct` 的 `activated`、`refresh`、本地缓存）做通用绕过；本文未实际完成该部分。

## 触发条件

- 目标为 macOS 应用（本例 Movist Pro），使用 Paddle Classic SDK；应用二进制可被修改（未启用 SIP 保护的路径/已复制到可写目录，代码签名/公证校验未阻止运行修改后的副本）。
- 能使用 IDA/Hopper 静态分析 Objective-C/Swift 混合二进制，并能用 lldb 附加/启动调试。
- 能代理 HTTPS（Burp/Charles + 信任证书）观察并修改 Paddle API 响应；或能直接修改二进制分支/指令。
- 客户端把 Paddle 产品数据缓存在本地，且刷新失败时保留旧值。
- 应用未对 `trial.duration` 做签名校验、范围校验或服务端二次确认。

## 利用步骤

（按文章分析流程描述，仅用于授权测试/研究。）

1. IDA 字符串搜索 `trial`/`subscription`/`license`，定位 `setTrialLength:`、`subscriptionTrialPeriod`；对 `setTrialLength:` 做 xref，进入 `sub_1001B8EE0`，确认 `NSNumber(7)` → `setTrialLength:`。
2. 在 `0x1001B9062` 把 `BF 07 00 00 00` 改为 `BF 09 00 00 00`；lldb `b 0x1001B9062` 验证立即数变为 9；观察界面仍为 7 天/1 天，判断本地值被服务端覆盖。
3. 用 Burp 抓 `POST https://v3.paddleapi.com/3.2/product/data`，在响应 JSON 中把 `"duration":7` 改为 `9999999`，放行后界面显示 9999993 天。
4. 断网重启，确认应用仍显示 9999993 天（Paddle 本地缓存），说明缓存可维持绕过。
5. 在 IDA 中定位 `sub_1001B9E30` 的 `activated` 判断与 `jz loc_1001B9F26`，把条件跳转改为恒走已激活分支（或改 `activated` 返回值），重启后出现 License 窗口，应用可用。
6. 若仍有弹窗，定位调用 `showProductAccessDialogWithProduct:` 的代码块，用 `90` NOP 覆盖（如 `0x1001BDF00` 附近），重启验证不再弹窗且可正常播放。
7. 记录修改的偏移/字节与对应版本，后续版本需重新定位。

## PoC

```text
1) 本地立即数（会被服务端覆盖）：
0x1001B9062: BF 07 00 00 00   mov edi, 7
改为        : BF 09 00 00 00   mov edi, 9
lldb: b 0x1001B9062 → 断下可见 movl $0x9, %edi

2) 服务端响应篡改：
POST https://v3.paddleapi.com/3.2/product/data
响应 JSON：
"trial": { "text": "Thanks for downloading a trial...", "duration": 7 }
改为：
"trial": { "text": "Thanks for downloading a trial...", "duration": 9999999 }
→ 界面显示“您的试用期还剩余 9999993 天!”

3) 分支修改：
0x1001B9E4E: 0F 84 D2 00 00 00   jz loc_1001B9F26
把条件跳转改为恒走已激活分支（或改 activated 返回值）
→ 弹出 License 窗口（Address/Deactivate/License/OK），应用可用

4) NOP 弹窗调用：
把调用 showProductAccessDialogWithProduct: 的指令块改为 90 90 ...
→ 不再弹试用提示，播放器正常使用

5) 缓存：
改包成功后断网重启，日志出现 NSURLErrorDomain -1009 / checkout.paddle.com 连接失败，
但试用期仍显示 9999993 天（PADProduct 本地缓存）
```

## 变体与关联

- 变体：若本地校验与服务端校验不一致，优先找“权威源”（服务端响应、缓存、激活状态）；只改本地默认值往往无效。
- 变体：NOP 弹窗可换成改 `activated` 返回值、改 `runModalForWindow` 分支、或 Hook `showProductAccessDialogWithProduct:`。
- 变体：缓存绕过可换成修改本地 Paddle 缓存文件/偏好设置，或阻断刷新域名。
- 关联：macOS 授权校验案例在库内暂无同族卡；通用二进制补丁/NOP/分支控制思路可参考 `ctf/reverse` 下的 patch 类卡片；Paddle 框架通用绕过在原文中仅引用未展开。
- 边界：文章只针对特定版本 Movist Pro；本地立即数修改被证明无效；Paddle 通杀方法未实际验证；修改应用可能违反许可协议/法律，仅限授权测试与研究。

## 检测与防御

- 应用侧（防绕过）：服务端为权威状态源，客户端只做展示；对 Paddle 响应做签名校验/证书固定，校验 `trial.duration` 范围；不要仅依赖本地缓存，刷新失败应降级而不是保留超长值；对二进制完整性/签名做校验，检测 `setTrialLength:`/`activated`/弹窗函数附近的补丁与 NOP。
- 检测：应用启动时校验代码签名/哈希；监控对 `v3.paddleapi.com` 响应的异常修改（duration 超大）；检测本地 Paddle 缓存被篡改/断网后仍显示异常试用期。
- 加固：启用 Hardened Runtime/公证、SIP 保护的安装路径；敏感判断放到服务端或加密/混淆；对关键分支做多点校验与控制流完整性。
- 研究边界：本文是软件测试/逆向研究，不提供成品或绕过工具；实际测试应在授权环境、遵守许可与法律。
