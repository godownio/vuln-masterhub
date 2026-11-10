---
id: code-analysis-reverse-windows-dotnet-pe-clr-header-metadata-streams
title: .NET PE 定位 CLR Runtime Header 与元数据流：BSJB 签名、#~/#Strings/#US/#GUID/#Blob 流与 IL-Only 标志
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dotnet-pe-clr-header-metadata-streams-locate
tags:
- dotnet
- pe
- metadata
- clr
- reverse
- malware-analysis
- dnspy
- ilspy
- pestudio
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V434
  verified_at: '2026-11-09T20:14:35+08:00'
  notes: 已对照原文全文与17张图（含GIF首帧）核对：data directory第15项.NET/CLR Runtime Header、BSJB 0x42534A42、#~/#Strings/#US/#GUID/#Blob流、IL-Only/32-bit-required/strong-name-signed与PEStudio/ILSpy展示均与原文及截图一致。注意（原文简化，卡沿用）：严格PE结构中IL-Only等标志属CLI header(COR20) Flags，BSJB为其后元数据根；GUID不在元数据根固定字段，来自#GUID堆/程序集Guid，解析时按CLI header→metadata root顺序。未实机解析样本。原文未写组件版本，未设affected_versions
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-dotnet-pe-clr-header-metadata-streams/
draft: false
kb_aliases:
- CLR Runtime Header
- .NET 元数据头
- BSJB 签名
- 元数据流
- null
- Cor20 头
---

## 一句话结论

.NET 程序集的 PE 可选头 data directory 第 15 项（CLR Runtime Header）指向元数据头：它以固定签名 `BSJB`（0x42534A42）开头，随后列出 `#~`、`#Strings`、`#US`、`#GUID`、`#Blob`（可选 `#Pdb`）各流的大小与偏移，还带有 IL-Only、32-Bit Required、Strong Name Signed 等标志；CLR 与 dnSpy/ILSpy/PEStudio 都靠这张“流目录”定位元数据，分析 .NET 恶意样本应从这一步开始。

## 原理

- **PE 中的入口**：PE 可选头的 data directory 是一张索引表，第 15 项为 CLR Runtime Header（.NET 目录），给出该头的 RVA 与大小。CLR 加载时据此找到元数据；分析工具（PEStudio 的 `.NET` 条目、ILSpy 的 Cor20 头）也是同一路径。
- **元数据头结构**：开头是 4 字节签名 `BSJB`（0x42534A42），随后是结构版本、GUID（MVID 相关）、标志位与流数量；流表每项记录“偏移 + 大小 + 名字”，名字是 4 字节对齐的 ASCII，如 `#~`、`#Strings`。
- **各流的分工**：
  - `#~`（主元数据流）：压缩编码的元数据表（Module/TypeDef/MethodDef/Field/TypeRef/MemberRef/Assembly/AssemblyRef 等）。
  - `#Strings`：类型名、方法名、字段名等标识符字符串；元数据表中的 Name 列存的是该流内的偏移。
  - `#US`（User Strings）：代码中的字符串字面量，UTF-16 编码——恶意样本的 URL、互斥体名、配置键常先在这里露头。
  - `#GUID`：GUID 列表（如模块版本 ID）。
  - `#Blob`：签名、字段默认值、自定义属性等二进制数据。
  - `#Pdb`（可选）：调试信息；Release 样本常见其缺失。
- **标志位的判断价值**：`IL-Only` 为真表示纯托管代码（可放心交给 dnSpy 反编译）；`32-Bit Required` 影响加载环境；`Strong Name Signed` 影响程序集身份与完整性校验；混合模式（含本机代码）或 ReadyToRun/AOT 样本的 IL-Only 可能为假/IL 不完整，分析策略要相应调整。
- 为什么工具之间“看得不一样”：dnSpy、ILSpy、PEStudio 对同一元数据头的呈现方式不同（树形/表格/十六进制），但底层流与偏移一致；按流名和偏移核对即可在工具间对齐。

## 触发条件

- 目标文件是 .NET 程序集（PE 中存在 CLR Runtime Header / `.NET` data directory，元数据头以 `BSJB` 开头）。
- 需要判断样本是纯托管还是混合模式、是否强命名、运行时版本等。
- 手头有 PEStudio、ILSpy、dnSpy 或自写 PE 解析器之一。

## 利用步骤

1. 用 PEStudio 打开样本，查看 `directories` 列表中的 `.NET` 项（第 15 项），记录其大小、RVA 与所在节（常见 `.text`）。
2. 双击 `.NET`/`.NET (version > ...)` 进入元数据视图：确认签名 `BSJB`、运行时版本、GUID，以及 `IL-Only`、`32-bit-required`、`strong-name-signed` 等标志。
3. 读取流表：`#~`（元数据表）、`#Strings`、`#US`、`#GUID`、`#Blob` 的大小与文件比例；异常大的 `#US`/`#Blob` 往往意味着大量字符串/资源或混淆。
4. 用 ILSpy 打开同一文件，展开 `PE → Cor20 头 → 存储签名/存储标题/存储流`，与 PEStudio 的流表交叉核对。
5. 后续按需进入 `#~` 表（找类型/方法）或 `#Strings`/`#US`（找名字/字符串字面量），再结合 Metadata Token 定位方法体（见关联卡）。

## PoC

无 PoC（工具操作型分析流程，原文未提供代码）。关键核对点：

```text
PEStudio -> directories -> .NET (index 15) -> metadata header
  签名: 42 53 4A 42 ("BSJB")
  flags: IL-Only / 32-bit-required / strong-name-signed
  streams: #~ / #Strings / #US / #GUID / #Blob (/ #Pdb)
ILSpy -> PE -> Cor20 头 -> 存储流 #~ / #Strings / #US / #GUID / #Blob
```

## 变体与关联

- 关联 [[code-analysis-reverse-windows-dotnet-metadata-token-rva-method-body]]：从本卡的 `#~` 表继续用 Metadata Token 与 RVA/文件偏移定位具体方法体与 IL。
- 关联 [[code-analysis-reverse-windows-pe-header-layout-locate]]：普通 PE 头/节表定位；本卡是其 .NET 扩展（data directory 第 15 项之后的部分）。
- 关联 [[code-analysis-reverse-windows-dotnet-batch-ilspycmd-config-regex-extract]]、[[code-analysis-reverse-windows-redline-dotnet-aes-resource-dropper]]：拿到 .NET 结构后的批量反编译与配置/资源提取。
- 边界：混合模式程序集同时含托管与非托管代码；ReadyToRun/单文件发布/AOT 可能缺失或裁剪元数据；加壳/混淆样本的流表可能被篡改，需先用工具修复或动态 dump。

## 检测与防御

- 蓝队/检测：静态判定 .NET 样本可看 CLR data directory 与 `BSJB` 签名；异常流大小（如超大 `#US`）与缺失 `#Pdb` 可作为混淆/打包线索。
- 分析侧防御：在隔离环境用 dnSpy/ILSpy 打开样本，避免直接执行；对疑似恶意程序集优先读 `#US` 字符串与 `#Blob` 自定义属性。
- 开发者/防御：强命名与签名校验能提高篡改门槛；发布时避免在 `#US` 中硬编码密钥/内网地址。
