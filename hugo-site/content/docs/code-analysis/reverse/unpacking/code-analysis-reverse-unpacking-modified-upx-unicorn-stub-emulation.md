---
id: code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation
title: 改版 UPX x64 无执行脱壳：节表异常识别 + Unicorn 仿真 stub dump
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: modified-upx-unicorn-stub-emulation
tags:
- reverse
- unpacking
- upx
- unicorn
- pe
- emulation
- nrv
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:06+08:00'
  notes: 已对照原文 §ColorfulArray 核对：PE32+ .text RawSize=0、入口 0x1403fe7d0 落数据区、导入仅 LoadLibraryA/GetProcAddress/VirtualProtect/ExitProcess 等、lea rsi/rdi 与 NRV 解压/E8E9 修复/IAT 重建、Unicorn hook 仿真 dump 均一致；未本机复跑。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation/
draft: false
kb_aliases:
- ColorfulArray
- 改版 UPX
- UPX x64 脱壳
- Unicorn 仿真脱壳
- .text Raw Size 0
- 入口在 .data
- NRV 解压
---

## 一句话结论

当 PE 出现 `.text` 的 Raw Size 为 0、入口点落在 `.data` 末端、导入表只有 `LoadLibraryA/GetProcAddress/VirtualProtect/ExitProcess` 等少量 API 时，应怀疑改版 UPX：`UPX!`/`UPX0/UPX1` 特征可能被抹掉，但从入口的 `lea rsi,[压缩数据]; lea rdi,[解压目标]` 与 NRV 解压循环可识别；用 Unicorn 只仿真解压 stub、hook 导入 API，在跳转 OEP 前 dump 解压后的 `.text` 即可无执行脱壳。

## 原理

- UPX x64 的典型结构：原 `.text` 被压缩到另一个节，stub 在入口处解压到原虚拟地址，修复 `E8/E9` 相对调用与导入表，`VirtualProtect` 恢复权限，最后跳到 OEP。
- 题目可以修改节名、抹掉 `UPX!` 字符串、调整入口/节表，使 `upx -d` 或字符串识别失效；但解压 stub 的行为特征仍在：
  - 入口附近 `lea rsi, [压缩数据]`、`lea rdi, [rsi - 0x33e000]`（目标为原 `.text`）；
  - 位流驱动的 LZ/NRV 循环：`add ebx,ebx`/`adc` 读位、literal 写入、负偏移 match 复制；
  - 解压后扫描并修复 `E8/E9` 相对调用；
  - `LoadLibraryA`/`GetProcAddress` 重建导入，`VirtualProtect` 改权限，跳 OEP。
- 直接运行未知样本有风险；Unicorn 可以在不执行最终业务逻辑的前提下，只让解压 stub 工作：
  1. 按 `ImageBase` 映射完整镜像与栈/TEB/PEB 最小内存；
  2. 把文件节复制到对应 VA；
  3. 对 `LoadLibraryA`、`GetProcAddress`、`VirtualProtect` 等 API 设 hook，返回可控假句柄/地址；
  4. 从入口开始仿真，检测到跳转到原 `.text`/OEP 时停止；
  5. dump 解压后的代码区。
- dump 后按 PE 节表/内存布局重建 Import Address Table（或直接用调试器附加到重建后的镜像），即可在 IDA/Ghidra 中分析原始程序。

## 触发条件

- PE32+ x64，节表异常：`.text` virtual size 很大但 raw size 为 0，入口在 `.data`/`.rsrc` 末端。
- 导入函数极少，主要是 `LoadLibraryA`、`GetProcAddress`、`VirtualProtect`、`ExitProcess`、`strlen`、`memset`。
- 入口处有压缩数据指针、解压目标指针与位流循环。
- 样本可能被修改过 UPX 特征，`upx -d` 失败。

## 利用步骤

1. 用 `file`、`objdump -x`、PE 解析库查看 ImageBase、Entry RVA/VA、节表 Raw/Virtual Size 与节权限。
2. 反汇编入口附近，确认 `lea rsi/rdi` 的压缩源与解压目标、NRV 位流循环、E8/E9 修复、导入重建、VirtualProtect、跳 OEP。
3. 用 Unicorn 映射镜像与栈，复制节数据；对 `LoadLibraryA`/`GetProcAddress`/`VirtualProtect` 设 hook，返回假句柄/函数地址。
4. 从入口 `emu_start`，设置指令计数/内存写监控；当 RIP 进入原 `.text` 范围或命中 OEP 时停止。
5. dump 解压后的 `.text`（以及修复后的 IAT/数据段），按 PE 布局写回或直接在调试器中加载。
6. 在 IDA/Ghidra 中分析 OEP 后的主逻辑；若后续还有 VM/解释器，再单独逆向。

## PoC

```python
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP

IMAGE_BASE = 0x140000000
ENTRY      = 0x1403FE7D0
STACK      = 0x0000000070000000

uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(IMAGE_BASE, 0x500000)
uc.mem_map(STACK, 0x200000)

# 1) 将 PE headers 与各节按 VirtualAddress 写入
# 2) hook LoadLibraryA/GetProcAddress/VirtualProtect，返回假句柄/地址
# 3) 设置栈与入口
uc.reg_write(UC_X86_REG_RSP, STACK + 0x1f0000)
uc.reg_write(UC_X86_REG_RIP, ENTRY)
uc.emu_start(ENTRY, 0)

# 4) stub 解压完成/跳到 OEP 后 dump 原代码区
unpacked = uc.mem_read(IMAGE_BASE, 0x401000)
open("unpacked.bin", "wb").write(unpacked)
```

说明：实际实现需处理 PE 重定位、TLS、异常目录与 API hook 返回值；案例用该方法 dump 出正常 MSVC C++ 程序，随后发现内嵌 FlipJump `.fjm` 与 RV32 校验器。

## 变体与关联

- 变体：UPX 变种可能修改解压算法（LZMA/NRV2E）、增加反调试/CRC 校验；先定位 stub 的 API 调用与跳转 OEP。
- 变体：其他壳（Themida/VMProtect/ASPack）也可用 Unicorn/Qiling/Speakeasy 仿真，但需处理更多反调试与虚拟化。
- 变体：dump 后 IAT 未修复时，可用 `Scylla`/`ImpRec` 或手动按 `GetProcAddress` 调用记录重建。
- 关联：[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（UPX 自定义 VM）、[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（VM 校验器）、[[code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key]]（导入混淆）。

## 检测与防御

- 防御：不要仅依赖 UPX 特征识别；对样本做节表/入口/导入异常与熵分析，结合行为沙箱。
- 防御：生产软件使用正规签名与完整性校验；加壳不能替代代码签名与安全更新。
- 检测：PE 中出现 `.text` raw size 0、入口在数据节、极少导入、RWX 段、入口处解压循环；Unicorn 仿真时对 `VirtualProtect`/`LoadLibraryA` 的调用序列。
- 响应：确认壳类型后按 OEP dump 分析；对未知样本在隔离环境仿真，不直接运行。
