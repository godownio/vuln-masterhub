---
id: code-analysis-reverse-windows-mz-less-scrambled-import-memory-dll-loader
title: 无 DOS 头 + 打乱导入表的内存 DLL 加载器：shellcode 尾部内嵌 DLL，loader 补全头、复原导入顺序并 call 入口
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: mz-less-scrambled-import-memory-dll-loader
aliases:
- 无 MZ 内存 DLL
- 去除 DOS 头 DLL
- 打乱导入表顺序
- Import Directory 复原
- 尾部内嵌 DLL loader
- 内存加载 DLL shellcode
- PE 头裁剪免杀
tags:
- windows
- shellcode
- pe
- dll
- loader
- import-directory
- memory-loading
- evasion
- malware-analysis
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V528
  verified_at: '2026-11-11T15:09:55+08:00'
  notes: 已对照原文与img11/12/17/18核对：call $+5取址+DB7偏移、缺MSDOS头不填MZ magic注释、sub_32加载DLL并call eax、xo.had call RunDll均一致；原文明确Import Directory顺序被打乱并由loader复原。未验证点：未dump内嵌DLL验证导入表重排。dedup候选为保留MZ改PE签名/反射加载等卡，静态对抗点不同，非重复。
---

## 一句话结论

shellcode 尾部内嵌一个被裁剪的 DLL：去掉 DOS 头（没有 `MZ`/DOS stub）、把 Import Directory 条目顺序打乱。shellcode 自身是专用加载器，在内存中按偏移定位内嵌 DLL，补全头部与节映射、按内置记录恢复导入表原始顺序并填充 IAT，最后 `call` DLL 的 entry point 执行——文件层面看不到完整 PE，静态特征（MZ、标准导入表顺序）也被破坏。

## 原理

- **为什么去掉 DOS 头**：正常的 PE 以 `4D 5A`（MZ）+ DOS stub 开始，`e_lfanew` 指向 `PE\0\0`。恶意载荷去掉 DOS 头后，静态扫描按 `MZ`/DOS stub 搜索 PE 的规则失效；加载器自己知道内嵌数据的起始偏移与结构，可直接按 NT 头/节表布局映射，不需要 MZ。
- **为什么打乱导入表**：Windows Loader 按 Import Directory 的条目顺序加载 DLL/填充 IAT；安全的加载器会按原顺序解析。作者把条目顺序打乱后，普通 PE 解析工具按原偏移读到的 DLL/函数名是错位的，静态签名与自动化分析得到错误结果；专用 loader 内部保存了原始顺序（或按某种规则重排），运行时还原后再 `LoadLibrary`/`GetProcAddress` 填充 IAT。
- **加载器流程**（原文 opk.txt / xo.had）：shellcode 通过 `call $+5; pop` 取当前地址，按硬编码偏移定位尾部 DLL；`VirtualAlloc`/`VirtualProtect` 准备内存，复制头与节，`sub_32` 负责加载 DLL 并 `call eax` 跳到 DLL 的 entry point。原文注释明确："DB7 处是一个 PE 文件，缺 MSDOS 头；加载的时候补，但不填充 MZ magic"。
- **执行衔接**：entry point 被调用后进入 DLL 的 DllMain/导出逻辑；原文这一级内存 DLL 负责结束前一进程、持久化、下载下一级与启动宿主，最后由 shellcode 调用 `RunDll` 导出进入最终 payload。
- **为什么有效**：恶意 DLL 不以完整 PE 文件形式存在，静态引擎只能看到 shellcode + 一段"非 PE"数据；即使内存扫描发现 PE 结构，头部也缺少 MZ、导入表顺序异常，需要专用解析器才能还原。
- **边界**：加载器必须精确知道裁剪/打乱规则；DLL 依赖的导入 DLL 必须可用；重定位（ASLR）需 loader 处理；若入口依赖 TLS 回调或异常目录，裁剪头部可能导致缺失。

## 触发条件

- 外层 shellcode 已获得执行（栈溢出、loader、脚本等），且能在进程内分配可执行内存。
- 尾部内嵌 DLL 与 shellcode 同架构，加载器与 DLL 版本匹配（偏移/打乱规则固定）。
- 目标进程可加载 DLL 依赖（系统 DLL、运行库）；loader 有权限写/执行内存。
- 分析者拿到 shellcode 与加载器（或内存 dump）才能还原内嵌 DLL。

## 利用步骤

（按样本分析链描述，非本机复现。）

1. 反汇编 shellcode 入口：`call $+5; pop eax` 取基址，随后按 `add eax, offset` 定位尾部数据；记录加载器传入的长度/偏移。
2. 在尾部数据中定位 PE 结构：没有 MZ 时按 NT 头特征（`PE\0\0` 或节表/可选头字段）搜索；确认 `NumberOfSections`、`SizeOfImage`、`AddressOfEntryPoint`。
3. 还原导入表：按加载器内的顺序表重排 Import Directory 条目，或用调试器在 `LoadLibrary`/`GetProcAddress` 调用处记录 (DLL, 函数) 对，重建正确 IAT。
4. 在 `VirtualAlloc`/`memcpy`/`call eax` 处下断点，dump 映射后的内存镜像；修正头部（补 MZ/DOS stub）后用 IDA 作为 DLL 分析。
5. 跟进导出函数（如 `RunDll`）与后续行为：持久化、下载、C2。
6. 提取内嵌 DLL 的哈希/导出名作为 IOC，并对同源样本比对加载器偏移规则。

## PoC

```python
# 在 shellcode 尾部搜索"没有 MZ 的 PE"（按 NT 头/节表特征），示意
import struct
data = open('opk.bin', 'rb').read()
for i in range(len(data) - 0x400):
    # 无 MZ 时直接找 PE\0\0；若连 PE 签名也被改，需按 e_lfanew/节表合法性判断
    if data[i:i+4] == b'PE\x00\x00':
        machine = struct.unpack_from('<H', data, i + 4)[0]
        nsec = struct.unpack_from('<H', data, i + 6)[0]
        opt_size = struct.unpack_from('<H', data, i + 20)[0]
        if machine in (0x14c, 0x8664) and 0 < nsec < 0x20:
            print(f'candidate NT header at {i:#x}: machine={machine:#x}, sections={nsec}, opt={opt_size}')
```

```text
# 原文加载器行为（伪代码）
base = get_rip()                       # call $+5; pop
dll  = base + 0xDB7                    # 尾部内嵌 DLL（无 DOS 头）
mem  = VirtualAlloc(...)
copy_headers_and_sections(mem, dll)    # 不填充 MZ magic
restore_import_directory(mem)          # 按内置顺序恢复被打乱的导入表
fill_iat(mem)                          # LoadLibraryA/GetProcAddress
call entry_point(mem)
```

## 变体与关联

- 变体一：连 `PE\0\0` 也改掉（如改 `NO`），加载器按 MZ+NO 双特征定位，见 [[code-analysis-reverse-windows-mz-no-embedded-pe-xor-shellcode]]。
- 变体二：把内嵌 DLL 拆成多个文件/片段（两字节 `MZ` 与主体分开存放，运行时 `copy /b` 拼接），见原文 CNM.exe 的 `1.txt`+`2.txt` 组合。
- 变体三：手动映射 PE（DarkGate 式）复制节、解析导入、处理重定位后 `jmp eax`，见 [[code-analysis-reverse-windows-darkgate-marker-xor-keyindex-manual-pe-loader]]；本卡差异是"去 DOS 头 + 打乱导入表顺序"的静态对抗。
- 关联：[[code-analysis-reverse-windows-pe-import-table-encrypt-unpack-section-iat-rebuild]]（导入表加密 + stub 重建 IAT 的壳）、[[code-analysis-reverse-windows-valleyrat-staged-shellcode-codemark-reflective-pe]]（反射 PE 加载）。
- 边界：加载器偏移/规则不匹配时无法定位；DLL 的 TLS/异常目录/延迟导入需额外处理；内存扫描按 PE 结构仍可能发现。

## 检测与防御

- 检测：进程内存出现无 `MZ`/DOS stub、导入表顺序异常或 IAT 指向手工填写地址的 PE 结构；shellcode 中出现 `call $+5; pop` 取址 + 硬编码偏移 + `VirtualAlloc` + `call eax` 组合；非模块内存被执行。
- 防御：EDR 对私有内存中的 PE 结构做内存扫描（不依赖 MZ，按节表/NT 头特征）；监控 `VirtualAlloc(RWX)` 后 `call` 非模块地址；禁止从非 PE 文件映射执行。
- 加固：W^X、CFG/CET；对加载器常见指令序列做 YARA/行为规则；限制进程可执行内存分配。
