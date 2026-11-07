---
id: code-analysis-reverse-anti-debug-tls-callback-pe-null-patch
title: TLS 回调反调试：PE 加载前执行检测，静态清零 TLS 目录/回调数组绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: tls-callback-pe-null-patch
tags:
- windows
- anti-debug
- pe
- tls
- tls-callback
- static-patch
- reversing
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:45:40+08:00'
  notes: 已对照原文与图片03-07核对：TLS Table RVA 0x3340/Size 0x18/文件偏移 0x1B0、ez_re.exe 与 RE4.exe 两示例的目录清零流程一致；已修正样本归属（ez_re.exe 目录、RE4.exe 回调地址）并明确第二例清的是 TLS 目录字段；PoC 未复跑。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-tls-callback-pe-null-patch/
draft: false
kb_aliases:
- TLS callback 反调试绕过
- TLS 回调退出程序
- 清零 TLS Directory
- PE TLS 表 patch
- ez_re.exe TLS
---

## 一句话结论

Windows 在进入程序入口点（OEP）之前会先执行 PE 的 TLS 回调；若样本把 `CheckRemoteDebuggerPresent`/`IsDebuggerPresent` 等检测放进 TLS 回调并在命中时 `TerminateProcess`，可在静态分析阶段定位 `IMAGE_DIRECTORY_ENTRY_TLS` 与 `AddressOfCallbacks` 指向的回调数组，把回调数组（或 TLS 目录的 RVA/Size）填 0，让加载器认为没有 TLS 回调，从而直接进入正常主逻辑。

## 原理

- **TLS 回调的执行时机**：PE 加载时，系统在处理导入、初始化等步骤前，会遍历 TLS 目录中的回调数组（`AddressOfCallbacks` 指向以 NULL 结尾的函数指针数组），对每个回调以 `DLL_PROCESS_ATTACH` 调用。它早于 `AddressOfEntryPoint`（OEP），所以反调试代码可以在主程序任何断点之前运行。
- **PE 中的位置**：可选头的数据目录索引 9 是 `IMAGE_DIRECTORY_ENTRY_TLS`，指向 `IMAGE_TLS_DIRECTORY` 结构；结构中的 `AddressOfCallbacks` 是回调数组的 VA。原文样本 `ez_re.exe` 中，PEView 的 Optional Header 显示 TLS Table 位于文件偏移 `0x1B0`（RVA `0x3340`，Size `0x18`）；另一示例 `RE4.exe` 的 `IMAGE_TLS_DIRECTORY` 显示 `AddressOfCallbacks = 0x0041D720`，目录中还有 `StartAddressOfRawData/EndAddressOfRawData/AddressOfIndex/SizeOfZeroFill/Characteristics` 等字段。
- **绕过思路**：加载器只认 TLS 目录和回调数组。把回调数组的第一个指针改成 0（数组以 NULL 结尾，遍历立即结束），或把 TLS 目录的 RVA/Size 改成 0（加载器不处理 TLS），都能阻止回调执行；也可以把回调函数体改成 `ret`/跳过检测。
- **为什么有效**：这是静态文件补丁，运行时根本不进入检测代码，不依赖调试器隐藏或 API hook；对“TLS 回调 + 检测到调试就退出”的样本最直接。
- **注意**：如果样本还通过其他线程/延迟检查再次检测，清零 TLS 只解决第一层；需要继续分析主逻辑中的二次检测。

## 触发条件

- 目标 PE 的 TLS 目录存在且 `AddressOfCallbacks` 非空；用 PEView/010/pestudio 能看到 TLS 表与回调数组。
- 反调试逻辑位于 TLS 回调中，且在 OEP 前执行（常见于 CTF 逆向题与恶意样本）。
- 分析者可以修改 PE 文件（静态 patch）或在内存中修改 TLS 目录/回调数组。
- 样本未对 TLS 目录做完整性校验（或校验可一并 patch）。

## 利用步骤

1. 用 PEView/Pestudio/010 查看可选头数据目录，定位 `IMAGE_DIRECTORY_ENTRY_TLS`（索引 9）；记录 TLS 目录 RVA/Size 与文件偏移。
2. 跟随 TLS 目录的 `AddressOfCallbacks`，找到回调数组（通常在 `.rdata`/`.data`），确认每个回调地址与结尾的 NULL。
3. 反汇编回调函数，确认反调试逻辑（如 `CheckRemoteDebuggerPresent`、`IsDebuggerPresent`、`NtQueryInformationProcess`、`TerminateProcess`/`ExitProcess`）。
4. 静态补丁二选一：
   - 把回调数组的所有指针（至少第一个）写成 0；
   - 把 TLS 数据目录的 RVA 和 Size 都写成 0。
   原文在 010 中将 TLS 目录项（文件偏移 `0x1B0` 起）清零；另一示例则把 `RE4.exe` 的 TLS 目录字段（`0xD7A8` 起）清零。
5. 保存副本并用调试器加载，确认程序不再在 TLS 阶段退出，能停在 OEP/主逻辑；若仍退出，检查是否有二次检测或其他 TLS 回调。
6. 也可在调试器中于 TLS 回调处下断点，直接跳过检测/改返回值，避免修改文件。

## PoC

原文未给出脚本化 PoC；核心补丁操作如下（TLS 目录位置来自 `ez_re.exe`、回调地址来自 `RE4.exe` 的两张截图，未在本机执行）：

```text
1) PEView -> IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER
   Data Directory: TLS Table = RVA 0x3340, Size 0x18（文件偏移 0x1B0）
2) 跟随 TLS Directory 的 AddressOfCallbacks（`RE4.exe` 示例为 0x0041D720）
   回调数组形如: [0x00401000, 0x00000000]
3) 在 010 Editor 中:
   - 将文件偏移 0x1B0 起的 TLS 目录项 RVA/Size 置 0（ez_re.exe）；或
   - 将 RE4.exe 的 TLS 目录字段（0xD7A8 起，含 StartAddressOfRawData/EndAddressOfRawData/AddressOfIndex/AddressOfCallbacks）置 0
4) 保存为新文件，调试器加载，确认不再触发 TLS 反调试退出
```

说明：原文通过 PEView 定位、010 修改并截图验证；未给出脚本，PoC 为操作要点整理。

## 变体与关联

- 变体（补丁位置）：清零回调数组、清零 TLS 目录 RVA/Size、把回调函数首字节改为 `ret`、在调试器中跳过回调。
- 变体（检测内容）：`CheckRemoteDebuggerPresent`、`IsDebuggerPresent`、`NtQueryInformationProcess`、时序/PEB 检测；TLS 只是执行时机，检测逻辑可替换。
- 关联：[[code-analysis-reverse-windows-pe-tls-callback-pre-oep]]（TLS 回调在 OEP 前执行、用于加载器/解密）；[[code-analysis-reverse-windows-pe-tls-callback-decoy-main-remote-thread-injection]]（TLS 回调作为诱饵与远程线程注入）；[[code-analysis-reverse-anti-debug-peb-fields-patch]]（回调内常见的 PEB 检测）；[[code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch]]（回调内常见的 API 检测）。
- 边界：TLS 回调被加密/动态注册、回调地址在运行时计算、或样本对 TLS 目录做校验时，静态清零可能失效；需要动态断点或内存 patch。

## 检测与防御

- 检测：PE 存在 TLS 目录且回调在 OEP 前执行；回调函数调用调试检测 API 或 `TerminateProcess`；文件中 TLS 目录/回调数组被改写为 0。
- 防御（反反调试）：对 TLS 目录与回调数组做完整性校验、在多个阶段重复检测、把关键检测放到主逻辑深处；分析侧优先在 TLS 回调下断点动态绕过，或同时 patch 多处检测。
