---
id: tools-ida-flirt-flair-custom-library-signature
title: IDA FLIRT/FLAIR 自定义静态库签名：从 .lib/.a 生成 .pat/.sig 恢复库函数名
type: scenario
domain: tools
path: tools/ida
technique: ida-flirt-flair-custom-library-signature
aliases:
- FLIRT 签名
- FLAIR 工具集
- sigmake 生成 sig
- pcf/pelf/pobj/par
- .pat 模式文件
- .exc 冲突处理
- IDA 库函数识别
- 静态库符号恢复
tags:
- ida
- flirt
- flair
- sigmake
- reverse
- static-library
- signature
- symbol-recovery
- tools
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T23:17:27+08:00'
  notes: 已对照原文及图01-17核对：pcf/pelf/pobj/par、sigmake COLLISIONS 164、.exc 的 +/- 规则、sig 加载路径均一致；知识库正文已修正加载前函数为sub_140127E32/sub_1401296B5，并注明sigmake输出对应原文无-n命令。工具技巧非漏洞；未在本机执行FLAIR/sigmake。
---

## 一句话结论

当目标二进制静态链接了 OpenSSL 等第三方库且符号被剥离时，IDA 只能显示 `sub_140127E32` 之类的地址名；用 FLAIR 的 `pcf`/`pelf`/`pobj`/`par` 从对应版本的 `.lib`/`.a`/`.o` 提取函数指令模式生成 `.pat`，再用 `sigmake` 处理冲突生成 `.sig`，放入 IDA `sig` 目录并通过“File → Load file → FLIRT signature file”加载，IDA 就能按模式匹配把 `RC4_set_key`、`RC4`、`AES_*` 等库函数名和参数信息恢复出来，省去逐个逆向库函数的成本。

## 原理

- **FLIRT（Fast Library Identification and Recognition Technology）** 通过比较二进制代码段的指令字节序列与签名库中的函数模式来识别编译器/静态库生成的标准函数；匹配成功后把函数重命名为库函数名、标记为外部库函数并默认折叠反汇编。
- **FLAIR 生成签名**：FLAIR 为不同库格式提供解析器——`pelf`（ELF `.a`）、`pcf`/`pcoff`（COFF `.lib`）、`pobj`（单个 `.o`）、`par`（ar 归档）——它们提取每个函数的指令序列，忽略地址常量和填充字节，生成文本格式 `.pat` 文件。
- **`.pat` 内容**：每个函数模式包含函数起始字节序列（最长 32 字节）、校验码（CRC/Hash）、函数长度、在文件中的偏移、函数名。重定位入口的字节用 `.` 补全，短于 32 字节的函数用点填充到 32 字节；因此模式对地址变化不敏感，但对编译器的指令选择/优化敏感。
- **`sigmake` 生成 `.sig`**：`sigmake libcrypto.pat libcrypto.sig` 把 `.pat` 打包为 IDA 可读的 `.sig`。若不同函数的模式相同/相近（例如仅函数名不同），`sigmake` 会生成 `.exc` 冲突文件并报告 `COLLISIONS`。
- **`.exc` 冲突处理**：在 `.exc` 中，行首 `+` 表示匹配时应用该函数名，`-` 表示添加注释但不应用名称，不加符号表示忽略该模式；编辑后重复运行 `sigmake` 直到生成 `.sig`。也可以删掉 `.exc` 注释后不处理（所有冲突函数被忽略）。
- **IDA 加载**：把 `.sig` 放到 `IDA/sig` 目录（或任意位置用 `Load SIG File` 手动选择），通过菜单“File → Load file → FLIRT signature file”选择；IDA 重新分析时用模式匹配替换函数名。IDA 自带 `sig` 目录下按架构分文件夹（arm、c166、mips、pc、sh3、tms320c6 等）及常见库签名（libc、MFC、Go 标准库等）。
- **为什么有效**：静态库函数在链接时被原样复制进目标，编译器生成的指令序列在同一编译器版本/优化选项下高度一致；模式匹配不需要符号表，因此能在 stripped 二进制上恢复名称。局限是编译器版本、优化等级、LTO/内联、不同库版本都会改变指令序列，导致匹配率下降或误匹配。

## 触发条件

- 目标二进制静态链接了某个第三方库（如 OpenSSL `libcrypto`、MFC、CRT），且 IDA 中该库函数显示为 `sub_*`。
- 能获得与目标同版本/同编译器/同优化选项的静态库文件；文章建议使用 **Debug** 版本（保留符号，解析器能识别函数），Release 版本若保留符号也可能可用。
- FLAIR 工具集可用（IDA 安装目录 `IDA/utils/flair` 或 flair70/flair90 等），且按库格式选对解析器（COFF/ELF/OMF）。
- IDA 能把 `.sig` 放入 `sig` 目录或手动 `Load SIG File`。

## 利用步骤

1. 获取 FLAIR 工具集（IDA 安装目录下的 `utils/flair`，或下载 flair70/flair90），确认 `pcf`/`pelf`/`pobj`/`sigmake` 可执行。
2. 准备与目标同版本、同编译器、Debug 编译的静态库；Windows 下通常是 `.lib`（COFF），Linux 下是 `.a`（ELF）。
3. 用对应解析器生成 `.pat`：
   ```bash
   pelf libcrypto.a > libcrypto.pat      # Linux/ELF
   pcf libcrypto.lib > libcrypto.pat     # Windows/COFF
   pobj libcrypto.o > libcrypto.pat      # 单个 .o
   par libcrypto.a > libcrypto.pat       # ar 归档
   ```
   观察输出中的 `skipped N, total M`，确认大部分函数被解析。
4. 生成 `.sig`：
   ```bash
   sigmake.exe libcrypto.pat libcrypto.sig
   # 需要保留详细函数名/调试时
   sigmake.exe -n libcrypto.pat libcrypto.sig
   ```
5. 若输出 `COLLISIONS: N` 并生成 `.exc`，打开 `.exc`：对需要应用名称的函数行首加 `+`，只加注释加 `-`，忽略则不加符号；保存后重复 `sigmake`，直到生成 `.sig`（或删除 `.exc` 注释后忽略全部冲突）。
6. 把 `.sig` 复制到 `IDA/sig` 目录（或记住路径），重新加载二进制，选择“File → Load file → FLIRT signature file”，在列表中选择该签名或点 `Load SIG File` 加载本地文件。
7. 加载后检查函数窗口：原本的 `sub_140127E32` 应变为 `j_RC4_set_key`，`sub_1401296B5` 应变为 `j_RC4`，其他地址对应 `AES_*`、`SHA256` 等库函数名；未识别的函数继续手动分析或调整 `.exc`/库版本。
8. 如需更多签名，可使用开源 FLIRTDB（如 `Maktm/FLIRTDB`、`PlatyPew/ida-flirtdb`）中的 `.sig`，放入 `sig` 目录或手动加载。

## PoC

```bash
# 1) 从静态库提取模式
pcf libcrypto.lib libcrypto.pat
# 输出示例：skipped 196, total 7900

# 2) 生成签名
sigmake.exe libcrypto.pat libcrypto.sig
# 原文截图输出：libcrypto.sig: modules/leaves: 4082/7378, COLLISIONS: 164
# 如需保留详细函数名可加 -n：sigmake.exe -n libcrypto.pat libcrypto.sig
# 按提示编辑 libcrypto.exc 后重复 sigmake

# 3) 放入 IDA/sig，加载：
#    File -> Load file -> FLIRT signature file -> libcrypto
```

```text
# 效果（文章示例 CryptoTest.exe，静态链接 OpenSSL）：
# 加载前：sub_140127E32(v8, 16LL, v4);  sub_1401296B5(v8, 17LL, v5, v6);
# 加载后：j_RC4_set_key(v8, 16LL, v4);  j_RC4(v8, 17LL, v5, v6);
```

## 变体与关联

- 变体：按库格式选择解析器；COFF 用 `pcf`/`pcoff`，ELF 用 `pelf`，单对象用 `pobj`，ar 归档用 `par`；选错解析器会得到空/错误的 `.pat`。
- 变体：Release 库去符号/优化后解析器可能跳过大量函数；优先 Debug 库；若 Release 保留符号也可尝试。
- 变体：编译器版本/优化选项不一致会导致匹配率下降；尽量使用与目标完全相同的编译器、库版本和编译选项；LTO/内联会使函数边界变化。
- 关联：[[code-analysis-reverse-go-binary-layout-symbol-recovery]]（Go 二进制的 pclntab/类型信息与 go_parser/redress 符号恢复，和 FLIRT 互补）、[[tools-ida-bison-flex-parser-table-struct-recovery]]（IDA 中批量重命名/结构恢复的另一种符号修复）。
- 边界：FLIRT 只匹配“库函数”；用户代码、被内联的库函数、不同编译器生成的同功能代码无法可靠识别；误匹配时需要人工核对指令序列。

## 检测与防御

- 逆向方：优先用同版本 Debug 静态库生成签名；对冲突函数用 `.exc` 显式选择；结合 `.pat` 中的字节模式与反汇编人工确认，避免误匹配。
- 防御方（提高逆向成本）：发布时剥离符号并启用 LTO/内联/优化，减少可匹配的库函数边界；使用与公开库不同的编译器版本/编译选项；对关键逻辑做混淆/虚拟化，避免直接静态链接可识别的标准库；但 FLIRT 对常见 CRT/MFC/OpenSSL 仍有较高识别率，不能作为唯一防护。
- 检测：二进制中出现大量已识别的库函数名、导入表缺失但函数体与标准库一致、`.sig` 加载后的浅蓝色库函数块；这些是逆向者使用 FLIRT 的痕迹（对防御方而言说明符号已被恢复）。
- 注意：本卡是逆向分析工具技巧，severity 标 info；不涉及漏洞利用。
