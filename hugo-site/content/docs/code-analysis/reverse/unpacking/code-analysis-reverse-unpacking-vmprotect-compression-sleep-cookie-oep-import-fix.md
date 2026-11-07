---
id: code-analysis-reverse-unpacking-vmprotect-compression-sleep-cookie-oep-import-fix
title: VMProtect 压缩壳手动脱壳：Sleep 断点 + MSVC security cookie 定位 OEP + VMPImportFixer 修复导入
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: vmp-compression-oep-locate-import-fix
tags:
- reverse
- unpacking
- vmprotect
- packer
- oep
- import-rebuild
- x64dbg
- malware-analysis
- windows
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:53+08:00'
  notes: 已对照原文与 40 张图片核对；修正 .text VirtualSize 为 0x108D98；未对样本执行脱壳
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-vmprotect-compression-sleep-cookie-oep-import-fix/
draft: false
kb_aliases:
- VMP 压缩壳脱壳
- VMProtect 手动脱壳
- VMPImportFixer
- security cookie 定位 OEP
- 4EE640BB
- 0BB40E64E
- VMP dump
---

## 一句话结论

对采用 VMProtect 压缩模式（非虚拟化）加壳的 Windows PE，可以借沙箱 API 线索或 Sleep 兜底断点停在解包完成时刻，用 MSVC `__security_init_cookie` 的 `mov edi, 0BB40E64Eh`（字节序列 `4E E6 40 BB`）在已回填的 `.text` 中定位原始入口附近，栈回溯确定 OEP，再用 VMPImportFixer 在活进程中 dump 并修复导入表，得到可供 IDA 静态分析的镜像。

## 原理

- VMProtect 压缩模式把原始各节压缩/加密存放，磁盘上 `.text`、`.rdata`、`.data` 等节出现 `RawAddr=0` 而 `VirtualSize>0` 的异常；运行时由外壳解压并按虚拟地址回填，内存中的 `.text` 变为可执行可写（ERW）。因此磁盘镜像中的代码几乎不可读，必须在内存回填之后取镜像。
- VMP 的导入保护使磁盘 IAT 不可直接使用：API 在运行时解析，直接 dump 下来的镜像中大量 call 目标仍指向外壳运行时地址或未命名的间接调用。VMPImportFixer 这类工具在活进程中按调用点解析真实 API，并把 dump 中的调用修复为具名导入，从而恢复静态可分析性。
- 定位 OEP 的依据：MSVC 编译的程序入口链包含 `__security_init_cookie`，其函数体开头为 `mov edi, 0BB40E64Eh`，机器码 `BF 4E E6 40 BB`。该特征稳定且靠近原始入口，在解包后的 `.text` 中搜索 `4E E6 40 BB` 即可找到锚点；在锚点下断点重跑并通过调用栈回溯外层跳转，就能确定壳跳回原始入口的位置（OEP）。
- dump 时机决定镜像质量：越早越接近未被运行时修改的原始镜像，越晚则 IAT、全局变量与自修改代码积累的差异越多。因此应在 OEP 附近 dump，而不是等程序完全跑起来。
- Sleep 断点为何必中：HackingTeam 泄露源码中的 VMProtectDumper 在 `kernel32` 加载时用 `WriteProcessMemory(hProcess, Sleep, "\xcc", 1)` 把 Sleep 首字节改成 `int3`，因此断在 Sleep 必然命中；当沙箱报告中的 `NtReadFile` 等 API 因解析方式或时序无法下断时，Sleep 是稳定的兜底点。
- 适用边界：本流程针对 VMP 的压缩/加壳模式；被虚拟化（Virtualization/Ultra）的函数在内存中仍是私有字节码，dump 不会还原为原始 x86 逻辑，需另做 VM 逆向。

## 触发条件

- Windows PE，DIE/PE-bear 识别为 VMProtect（本例识别为 3.2.0-3.5.0），存在 `.vmp0`/`.vmp1` 等段。
- 节表中 `.text`/`.rdata`/`.data` 等 `RawAddr=0`、`VirtualSize>0`，IDA 打开时这些节内容为空或未知，入口落在 `.vmp` 段。
- 样本可在隔离虚拟机中运行（恶意样本，禁止在主机执行）；调试器（x64dbg）可附加。
- 目标载荷由 MSVC 编译（存在 security cookie）；其他编译器需要换用别的 OEP 锚点。
- 具备 VMPImportFixer 或等价的 dump + 导入修复工具。

## 利用步骤

1. 静态确认壳与节表：用 DIE、PE-bear 查看段名、Raw/Virtual 地址与大小；本例 `.text` 的 RawAddr=0、VirtualSize=0x108D98，`.vmp0`/`.vmp1` 存在，入口位于 `.vmp1`。
2. 从沙箱行为报告取 API 线索：例如报告显示 `NtCreateFile` 在 %TEMP% 创建 `.bat`；在 x64dbg 对 `NtCreateFile`/`ZwCreateFile` 下断。若某些 API（如 `NtReadFile`）断不下来，不要死磕，换兜底方案。
3. 设置 Sleep 兜底断点：在系统断点后对 `kernel32!Sleep` 下断（或按泄露源码的 VMProtectDumper 思路把 Sleep 首字节写成 `0xCC`）。命中时 `.text` 已被回填。
4. 搜索 OEP 锚点：在 `.text` 的内存范围搜索字节 `4E E6 40 BB`（`mov edi, 0BB40E64Eh`）；命中处即 `__security_init_cookie`。对该地址下断点，关闭 ASLR 后重启，保证地址稳定。
5. 栈回溯确定 OEP：断在 security cookie 后查看调用栈，向上找到外壳代码的返回地址与跳转/调用目标；结合 IDA 确认入口形态（本例反编译为 `start(){ sub_75351B(1205884515); __asm { retn } }` 一类包装）。
6. 在 OEP 时机 dump 并修复导入：执行 `VMPImportFixer.exe -p <pid>`，产物为 `Soldier.exe.fixed`；日志会逐条打印被修复的调用（本例包括 `KERNEL32.DLL!MultiByteToWideChar`、`IsProcessorFeaturePresent`、`RtlUnwind` 等）。
7. 校验与补洞：检查 dump 的入口点是否恢复、IAT 是否完整；未修复的 API 可在动态调试中到调用点确认参数与目标后手工标注；必要时修复节属性与入口，再转入 IDA 静态分析并提取配置。

## PoC

```text
# 环境：隔离 Windows 虚拟机 + x64dbg；样本 SHA-256:
# ccb3c0462bb50d2c3c5c80ff828f75ec7997e66b4c8096de0f98fa019de6a002
# 以下为流程命令示意，未在本机对样本执行

# 1) 识别壳与段
diec Soldier.exe                 # 期望: VMProtect(3.2.0-3.5.0)

# 2) x64dbg 系统断点后
bp Sleep                         # 或 bp kernel32.Sleep（兜底必断点）
#    命中后在 .text 范围搜索 OEP 锚点
findall mem, "4E E6 40 BB"
#    对命中的 __security_init_cookie 地址下断，重启（关闭 ASLR），栈回溯找 OEP

# 3) 在 OEP 时机 dump 并修复导入
VMPImportFixer.exe -p <pid>      # 产物: dumps/Soldier.exe.fixed
```

## 变体与关联

- 变体：沙箱 API 断点法（`NtCreateFile` 等）与 Sleep 兜底断点法可组合；无沙箱报告时直接用 Sleep/`kernel32` 加载断点。
- 变体：解包后也可按 `.text` 变为 ERW、`VirtualProtect`/`WriteProcessMemory` 写自身代码段等内存行为定位回填时刻，再搜 OEP 锚点。
- 变体：其他商业压缩壳（ASPack、Themida 的压缩模式）可复用“找 OEP → dump → 重建导入”的框架，但 OEP 锚点与壳特征不同。
- 关联：[[code-analysis-reverse-vm-vmprotect-identification-behavior-analysis]]（VMProtect 虚拟化保护识别；本卡处理压缩模式，二者边界不同）、[[code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump]]（VirtualAlloc/VirtualProtect 断点定位解包）、[[code-analysis-reverse-windows-pe-import-reloc-parser]]（导入表与重定位解析）。
- 边界：VMPImportFixer 的修复不完整（示例中入口点未恢复、部分 API 未修复），dump 只用于静态分析，不保证可执行；若关键函数被虚拟化，dump 后仍需 VM 逆向。

## 检测与防御

- 检测（静态）：节表 `RawAddr=0` 且 `VirtualSize>0`、`.vmp` 段、入口偏后、导入表稀疏；YARA 可匹配段名与 `BF 4E E6 40 BB` 之外的壳特征。
- 检测（动态）：进程内存中 `.text` 由不可执行变为可写可执行、出现对自身代码段的写入、Sleep/API 断点被反复命中、临时目录落地 `.bat`/PE 等，可作为沙箱与 EDR 的加壳行为信号。
- 防御（分析侧）：恶意样本只在隔离环境运行；dump 前后比对内存与磁盘节内容，确认回填完成；修复后校验导入与入口，避免把壳代码当业务代码分析。
- 防御（防守侧）：EDR 不依赖静态哈希，结合 API 序列、内存权限变化与落地文件行为检测；软件保护场景中 VMP 压缩壳只提高静态分析成本，并不等于不可分析。
