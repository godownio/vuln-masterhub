---
id: code-analysis-reverse-windows-unity-mono-cheat-engine-dissect
title: Cheat Engine Mono Dissect：静态字段/方法枚举与运行时解密调用
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: unity-mono-cheat-engine-dissect
tags:
- reverse
- unity
- mono
- cheat-engine
- dynamic-analysis
- game
- csharp
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:02:55+08:00'
  notes: 已对照 content.md 与图 04-12 核对：CE 附加后出现 Mono 菜单、Dissect mono/.NET Info 枚举类/静态字段/方法、encryptKey=test、Find out what calls/断点/修改字段均一致；截图窗口标题为 .NET Info，卡片按原文叙述称 Dissect mono。未在本机运行 CE/游戏。frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-unity-mono-cheat-engine-dissect/
draft: false
kb_aliases:
- CE Mono
- Dissect mono
- Unity 内存查看
- Mono 类/字段枚举
- Cheat Engine Unity 逆向
---

## 一句话结论

Cheat Engine 附加到 Unity Mono 游戏后会多出 Mono 菜单；用 “Dissect mono” 可以枚举所有程序集/类，查看静态字段（如 `encryptKey=test`）、实例字段和方法，并直接调用 `Decrypt`/`OnClick` 或在方法上下断点，从而绕过静态分析中的字符串加密、覆盖 UI 或多 DLL 调用顺序问题。

## 原理

- Unity Mono 运行时保留完整的 .NET 元数据：程序集、类、字段、方法、对象实例都在 Mono 运行时中可枚举。CE 的 Mono 功能通过 Mono 调试/反射接口读取这些信息，不依赖静态反编译。
- 附加进程后，CE 菜单栏出现 `Mono`；`Dissect mono` 左侧列出模块/类（如 `UnityEngine.UmbraModule.Main`、游戏自己的类），右侧显示继承关系、静态字段、实例字段和方法。
- 静态字段的“值”列可以直接看到运行时值：示例 `encryptKey` 为 `System.String`，地址 `157c493cbc0`，值 `test`；这类字段往往就是加密 key/校验开关。
- 方法列表中的 `Decrypt`、`Encrypt`、`OnClick`、`Start` 可以直接右键 “Find out what calls this function” 查调用者，或在方法上设断点；也可以在 CE 中调用方法/修改字段值。
- 对静态分析卡住的场景（例如 SCTF 题在输入框上又覆盖了一层点击框、真正逻辑在较新的 DLL），CE 能直接看到当前运行的对象与方法，快速定位实际执行路径；缺点是依赖进程运行、可能被反调试/CE 检测拦截。

## 触发条件

- 目标是 Unity Mono 打包（`Data/Managed/Assembly-CSharp.dll`），运行在 Windows，CE 能附加。
- 游戏没有强反调试/反 CE/完整性校验，或可先绕过；IL2CPP 游戏没有 Mono 菜单，需要 Frida/IL2CPP 工具。
- 需要观察运行时字段/调用方法，或静态反编译因混淆/多 DLL/覆盖 UI 难以定位。
- 允许在本机运行游戏（CTF/本地分析）。

## 利用步骤

1. 启动游戏，运行 Cheat Engine（建议管理员权限），点击左上角“打开进程”选择游戏进程。
2. 附加成功后，CE 菜单栏出现 `Mono`；点击 `Mono → Dissect mono`。
3. 在左侧模块/类树中展开目标程序集（如 `Assembly-CSharp`），选择可疑类（示例 `UnityEngine.UmbraModule.Main`/游戏自定义类）。
4. 查看右侧静态字段：记录 `encryptKey`、密钥、分数、开关等字段的地址与值；必要时双击修改值。
5. 查看方法列表：`Decrypt`/`Encrypt`/`OnClick`/`Start` 等；右键方法选择 “Find out what calls this function” 追调用链，或设置断点。
6. 在游戏里触发对应按钮/事件，断点命中后查看参数、局部变量与返回值；也可以在 CE 中直接调用 `Decrypt` 传入密文，读取返回的明文。
7. 若静态解密结果输入后仍不对，检查是否有覆盖 UI/第二个点击框；用 CE 查看当前被点击对象的 `text` 与 `OnClick` 实际绑定的类，确认真正逻辑所在。

## PoC

```text
CE 操作流程（无脚本）：
1. Open Process -> 选择 Unity 游戏进程
2. 菜单 Mono -> Dissect mono
3. 左侧选择 Assembly-CSharp / 目标类
4. 右侧 Static fields 查看 encryptKey / 密钥 / 分数
5. Methods 中右键 Decrypt -> Find out what calls this function
6. 在 Decrypt/OnClick 上下断点，游戏内触发按钮
7. 断点命中后查看参数/返回值，或直接调用 Decrypt 解密密文
```

```text
示例观察：
Class: UnityEngine.UmbraModule.Main
Static field: encryptKey  System.String  addr=157c493cbc0  value=test
Methods: Decrypt(string), Encrypt(string), OnClick(), Start()
```

## 变体与关联

- 变体：CE 的 Mono 功能也可用于修改玩家属性（金币/血量/等级）、解锁关卡、直接调用胜利方法；本质是运行时内存/对象修改。
- 变体：若 CE 被反调试拦截，可改用 dnSpy 调试器、x64dbg 或 Frida（Mono 游戏可用 frida-mono）。
- 变体：IL2CPP 游戏没有 Mono 菜单，需用 Il2CppDumper + Frida/IDA 分析 `GameAssembly.dll`。
- 关联卡片：[[code-analysis-reverse-windows-unity-mono-assembly-csharp-dnspy-analysis]]（静态定位）、[[code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass]]（dnSpy 改 IL）、[[mobile-android-unity-il2cpp-frida-gadget-infinite-revival]]（IL2CPP/Frida 变体）。
- 边界：CE Mono 依赖 Mono 运行时暴露的元数据；强混淆/字符串加密可能让字段名不可读，但运行时值和调用关系仍可见；反调试/完整性校验可能阻止附加。

## 检测与防御

- 检测（游戏保护）：检测 CE/调试器进程与窗口、检测 Mono 调试接口/远程线程、校验程序集完整性；对关键逻辑做混淆/字符串加密。
- 加固：使用 IL2CPP 替代 Mono；服务端校验关键结果；反调试与反 CE 插件；对内存中的关键字段做加密/校验。
- 分析安全：CE 附加会修改/读取进程内存，务必在隔离虚拟机、授权目标上使用；不要对生产环境游戏进程操作。
