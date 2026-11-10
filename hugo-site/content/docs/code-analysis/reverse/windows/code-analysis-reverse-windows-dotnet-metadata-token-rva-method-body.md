---
id: code-analysis-reverse-windows-dotnet-metadata-token-rva-method-body
title: .NET Metadata Token 定位方法体：表类型+RID、RVA/文件偏移换算与 Tiny/Fat 方法头解析
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dotnet-metadata-token-rva-method-body-locate
tags:
- dotnet
- metadata
- token
- methoddef
- rva
- il
- tiny-header
- fat-header
- reverse
- dnspy
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V434
  verified_at: '2026-11-09T20:14:37+08:00'
  notes: 已对照原文与图06/07/08/09/10/11/12/14/15/16/17核对：token 0x060005FA表0x06 MethodDef RID1530、Name指向#Strings偏移0x1EC15=Start、RVA0x23B28/FileOffset0x21D28、Tiny(低2位10，高6位长度)与Fat(低2位11，例0x1B=MoreSects|InitLocals)头结构及IL操作码均与原文一致；原文0x58D66实为MethodDef行字段偏移而非方法代码文件偏移，卡内未沿用该错误。PoC为文本换算关系、未实机验证；原文未写组件版本
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-dotnet-metadata-token-rva-method-body/
draft: false
kb_aliases:
- 元数据令牌
- Metadata Token
- MethodDef 表
- Tiny 头 Fat 头
- RVA 文件偏移换算
- IL 指令定位
---

## 一句话结论

.NET 元数据令牌的高字节是表类型、低 24 位是 RID（如 `0x060005FA` = MethodDef 表第 1530 行）；MethodDef 行给出方法的 RVA 与名字在 `#Strings` 的偏移，RVA 按 PE 节映射换成文件偏移后即为方法体起始：首字节低 2 位 `10` 表示 Tiny 头（单字节，高 6 位为代码长度），低 2 位 `11` 表示 Fat 头（带 flags/size/maxstack/codesize/局部变量令牌），头后就是 IL 指令字节。

## 原理

- **令牌结构**：元数据令牌是 CLR 引用元数据表项的唯一标识。高字节是表编号：0x02 TypeDef、0x04 Field、0x06 MethodDef、0x0A MemberRef、0x20 Assembly、0x23 AssemblyRef 等；低 24 位 RID 是该表的行号，可容纳百万级条目。
- **MethodDef 行字段**：Name（指向 `#Strings` 流的偏移，而非直接内联字符串）、Signature（指向 `#Blob` 的签名偏移）、RVA（方法 IL 相对模块基址的地址）、ImplFlags/Flags（可见性、hidebysig、静态等）。dnSpy 在方法声明上方直接打印 `Token / RID / RVA / File Offset`，省去手工换算。
- **RVA → 文件偏移**：RVA 是按内存布局的偏移，磁盘文件里要按节表换算：`文件偏移 = RVA - 节VirtualAddress + 节PointerToRawData`。dnSpy 注释同时给 RVA 与 File Offset（示例 `RVA 0x00023B28` / `File Offset 0x00021D28`），也可用 PEStudio/PE 解析器计算，用于在十六进制编辑器中直接跳到方法体。
- **方法体头**：
  - Tiny：1 字节，低 2 位 `10`，高 6 位为代码字节数（最大 63）；适用于小于 64 字节、栈深 ≤8、无局部变量与异常处理的小方法。
  - Fat：首字节低 2 位 `11`，其后字段包含头大小（以 4 字节为单位）、maxstack、codesize、localvarsigtok（有局部变量时）；flags 还可指示 MoreSects（附异常处理等附加节）与 InitLocals。示例方法体首字节 `0x1B`（低 2 位 `11`）即 Fat，工具提示 `IMAGE_COR_ILMETHOD_FAT.Flags = FatFormat | MoreSects | InitLocals`。
  - 头之后的字节即 IL 指令；把文件偏移交给 dnSpy/ILDasm 可还原为 `.method ... ldarg.1 / callvirt / brfalse / ldstr / call ...` 的可读 IL，交给 IDA 则能看到对应操作码字节（如 `0x72` ldstr、`0x28` call、`0x6F` callvirt、`0x7E` ldsfld、`0x39` brfalse）。
- 为什么这条路径可靠：CLR 的 JIT、反射与所有 .NET 反编译器都依赖同一套元数据表与令牌；手工按 token→RID→RVA→文件偏移走一遍，就能在“反编译视图、元数据表、十六进制/IDA”三者之间任意对齐，尤其适合被混淆/局部损坏、反编译器视图不可信时做底层核对。

## 触发条件

- 目标为 .NET 程序集且保留可用元数据（非全 native AOT/强混淆破坏）。
- 需要定位某个具体方法的 IL（分析恶意行为、核对反编译结果、做 IL 补丁）。
- 有 dnSpy（含元数据窗口/十六进制编辑器）、ILSpy 或自写解析器。

## 利用步骤

1. 在 dnSpy 中找到目标方法，记录注释行：`Token: 0x060005FA RID: 1530 RVA: 0x00023B28 File Offset: 0x00021D28`（示例方法名 `Start`）。
2. 拆 token：高字节 `0x06` = MethodDef 表；RID `0x5FA` = 1530。元数据窗口按 `Method` 表第 1530 行查看 Name 偏移（如 `0x1EC15`）、Flags、RVA。
3. 验证名字：跳到 `#Strings` 流偏移 `0x1EC15`（dnSpy 十六进制编辑器“转到偏移量”处选择流内 RVA），应看到 `Start`；十六进制视图的悬浮提示会显示 `Method[0x5FA].Name = ... ("Start")`。
4. 计算/读取文件偏移：使用 dnSpy 给出的 File Offset，或按节表把 RVA 换算为文件偏移；在十六进制编辑器跳到该偏移。
5. 读首字节判断方法头：低 2 位 `10` → Tiny（长度在高 6 位），`11` → Fat（解析头字段与可选附加节）；记录 codesize 与 IL 起点。
6. 头后字节即 IL：用 dnSpy/ILDasm 查看可读 IL，或按操作码表在 IDA 中核对字节；对 `ldstr`（0x72）等指令继续追 `#US` 字符串，对 `call/callvirt`（0x28/0x6F）追 MemberRef/TypeRef 解析目标。

## PoC

无 PoC（结构定位流程）。可复用的换算关系：

```text
token      = 0x060005FA
table      = token >> 24          = 0x06 (MethodDef)
rid        = token & 0x00FFFFFF   = 0x5FA (1530)

file_off   = method_rva - section.VirtualAddress + section.PointerToRawData

Tiny header: first_byte & 0x3 == 0x2 ; code_size = first_byte >> 2
Fat  header: first_byte & 0x3 == 0x3 ; flags/size/maxstack/codesize/localvarsigtok 随其后
```

## 变体与关联

- 关联 [[code-analysis-reverse-windows-dotnet-pe-clr-header-metadata-streams]]：先定位 CLR Runtime Header 与 `#~`/`#Strings`/`#US`/`#Blob` 流，才能按本卡解析 token 与偏移。
- 关联 [[code-analysis-reverse-windows-dnspy-constructor-field-init-patch]]、[[code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass]]：定位到方法体后的 IL 补丁/绕过应用。
- 关联 [[code-analysis-reverse-windows-dotnet-batch-ilspycmd-config-regex-extract]]：批量反编译/字符串提取的上层流程。
- 变体：`0x0A` MemberRef 与 `0x01` TypeRef 用于解析跨程序集调用；`0x02` TypeDef 定位类；抽象/外部/PInvoke 方法的 RVA 可能为 0，无方法体；Fat 头的 MoreSects 需继续解析异常处理子句。
- 边界：混淆器可能伪造/重排 token、破坏 RID 与表一致性；ReadyToRun/AOT 下方法可能已是本机代码，需改为原生分析。

## 检测与防御

- 分析侧：当 dnSpy 反编译结果与运行行为不符时，回到 token→RVA→文件偏移的底层核对，可发现被篡改的元数据或 IL 补丁。
- 检测侧：异常的方法头（如 Fat 头 codesize 与实际不符）、token/表不一致、指向 `#Blob` 的畸形签名，是 .NET 加壳/混淆样本的常见特征。
- 防御：强名称签名与哈希校验增加篡改成本；对 .NET 程序集做发布前完整性检查；终端检测关注可疑程序集的反射加载与内存补丁行为。
