---
id: code-analysis-reverse-windows-resource-section-embedded-pe-restorator
title: 资源节藏内嵌 PE：Restorator 查 BIN 资源 MZ 头与 DOS stub，导出后用 StudyPE 继续分析 dropper 二阶段
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-resource-section-embedded-pe-extraction
aliases:
- Restorator 资源分析
- 资源节内嵌 exe
- BIN 资源 MZ 头
- dropper 捆绑检测
- StudyPE 看不出异常
- This program cannot be run in DOS mode
tags:
- windows
- pe
- reverse
- static-analysis
- malware-analysis
- resource
- embedded-pe
- dropper
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V665
  verified_at: '2026-11-13T08:23:02+08:00'
  notes: 已对照原文与全部35张截图核对：img10 Restorator 2009 打开 Lab01-04.exe 资源树 BIN→101，十六进制首部 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00（MZ）与 This program cannot be run in DOS mode. 均可见，卡内判据片段逐字节一致；img11 导出(O)→导出为 菜单存在，卡内步骤与原文『导出再放进StudyPE分析』一致。原文把 DOS stub 归因为 Metasploit 特征，卡内已在原理层更正为『所有 PE 的通用 stub，不能仅凭该字符串唯一归因到 MSF』，属必要修正且未歪曲主要结论。dedup：与 .data 段 fwrite 静态缓冲区提取内嵌 PE 卡为 related/new（提取位置 .rsrc BIN 资源与工具 Restorator vs IDA/.data，触发与步骤不同），非同链，保留；dup-scan无涉及本卡pair。原文未标版本。内部链接均存在。样本未运行。
---

## 一句话结论

恶意程序常把第二阶段可执行文件以二进制形式塞进 PE 的资源节（BIN 资源）里，此时 StudyPE 概览与导入表只看到正常外壳、看不出异常；用 Restorator 打开资源树查看 BIN 资源（如 `101`）的十六进制，若开头出现 `4D 5A`（`MZ`）与 `This program cannot be run in DOS mode.` 的 DOS stub，即说明其中内嵌了一个可执行文件，使用导出功能取出后即可用 StudyPE/IDA 继续分析 dropper 的真实载荷。

## 原理

- **PE 资源节**：PE 文件除代码/数据外可包含 `.rsrc` 资源段，保存图标、版本、对话框、字符串表以及任意 BIN 资源（类型 `RT_RCDATA`/BIN）。资源是合法功能，加载它的代码通常通过 `FindResource/LoadResource/LockResource` 取指针。
- **捆绑载荷的动机**：dropper 把真正的恶意 PE 放进资源，运行时释放到磁盘（`fwrite`/`CreateFile` 写出）再执行，或直接在内存加载。这样主 PE 在静态概览里看起来"干净"：导入表只有资源相关 API，Strings 里也未必出现恶意特征，杀软/分析者容易放过。
- **识别依据**：任何 Windows PE 都以 `MZ`（`0x4D5A`）开头，其 DOS stub 中固定出现字符串 `This program cannot be run in DOS mode.`。在资源十六进制里看到这两个特征，基本可断定是内嵌 PE（也可能是内嵌壳代码/载荷，但同样值得导出）。原文样本 `Lab01-04.exe` 的 `BIN\101` 资源即同时显示二者，作者据此判定其为恶意程序（把 DOS stub 归因为 metasploit 特征；准确说这是所有 PE 的通用 stub，Metasploit 生成的 exe 载荷同样包含，不能仅凭该字符串唯一归因到 MSF）。
- **为什么 StudyPE 概览看不出**：整体文件仍是合法 PE（有正常导入表、区段数不多），内嵌 PE 位于资源数据中，不属于主 PE 的代码/导入结构，概览与导入表不会展示资源内容；必须单独审视资源节。

## 触发条件

- 获得可疑 PE 样本，StudyPE/导入表/常规 Strings 未发现明显恶意特征，但样本来源可疑（邮件附件、下载目录等）。
- 样本的 `.rsrc` 中存在较大 BIN 资源（可通过 PE 工具的资源目录大小/熵快速判断，也可直接逐个查看）。
- 分析机装有 Restorator（或 Resource Hacker 等资源编辑器）与 StudyPE/IDA。

## 利用步骤

1. 用 Restorator 打开样本，展开左侧资源树；重点看 `BIN`/`RCData` 类型下的资源项（原文样本为 `BIN → 101`）。
2. 选中资源，右侧「资源查看器」切到十六进制视图；观察开头字节是否 `4D 5A`（`MZ`）以及是否出现 `This program cannot be run in DOS mode.`。
3. 确认内嵌 PE 后，右键该资源 → `导出(O)` → 选择目标格式/路径（原文导出为文件），得到独立的 PE 文件。
4. 把导出的 PE 放进 StudyPE 分析概览/导入表/字符串，再按 [[code-analysis-reverse-windows-pe-static-triage-imports-strings-behavior]] 的流程 triage；必要时用 IDA 分析主程序的资源加载/释放逻辑（`FindResource`→`LoadResource`→写出/内存加载）。
5. 记录内嵌载荷哈希与落盘行为，作为 dropper 检测特征。

## PoC

无 PoC（分析流程，无利用代码）。关键判据：

```text
资源 BIN\101 十六进制首部：
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00   MZ......
...
"This program cannot be run in DOS mode."
→ 内嵌 PE，导出后分析
```

## 变体与关联

- 变体：资源中的载荷被 XOR/压缩/加密时，十六进制看不到 `MZ`，需先按主程序的解密逻辑还原（见 [[code-analysis-reverse-windows-native-resource-xor-dotnet-ransomware-loader]]、[[code-analysis-reverse-windows-redline-native-multistage-shellcode-clr-resource-loader]]）。
- 变体：内嵌载荷不是完整 PE 而是 shellcode（资源中无 MZ），按 shellcode 提取/加载器分析处理。
- 关联：[[code-analysis-reverse-unpacking-fwrite-static-buffer-embedded-pe]]（在 `.data` 段按长度提取内嵌驱动的同类 dropper 分析）。
- 边界：资源中 BIN 数据也可能是合法程序的自定义数据（如皮肤、配置），必须结合主程序如何加载/使用该资源判断；`MZ` + DOS stub 是最强信号。

## 检测与防御

- 检测（分析/查杀侧）：检查 `.rsrc` 中 BIN 资源的熵与大小；对资源内出现 `MZ` 头的样本提高评分；按导出载荷的哈希建立家族特征。
- 防御（主机侧）：监控进程从资源释放可执行文件到 `%TEMP%`/`AppData` 并执行的行为（`CreateFile`+`WriteFile` 后 `CreateProcess`）；限制用户目录执行；邮件网关拦截含内嵌可执行资源的附件。
- 分析安全：样本在隔离虚拟机中处理，资源导出文件同样按恶意文件对待（可能被直接执行）。
