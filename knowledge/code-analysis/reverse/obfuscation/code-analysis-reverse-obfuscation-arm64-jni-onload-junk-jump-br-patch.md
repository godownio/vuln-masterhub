---
id: code-analysis-reverse-obfuscation-arm64-jni-onload-junk-jump-br-patch
title: ARM64 花指令批量修复：JNI_OnLoad 的 ADR/STR/LDP/BR 跳板用 keystone 模拟求目标后改 B
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: arm64-junk-jump-indirect-br-patch
aliases:
- ARM64 去花
- JNI_OnLoad JUMPOUT
- BR X9 跳转修复
- keystone patch B
- flare_emu 模拟取跳转目标
- so 花指令批量处理
tags:
- reverse
- arm64
- obfuscation
- ida
- keystone
- flare-emu
- android
- native
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-15
  verified_at: '2026-11-08T08:11:15+08:00'
  notes: 已对照原文核对。图26 JNI_OnLoad 仅 JUMPOUT(0x4631C)；图27 汇编为 STP X0,X1 / STP X2,X3 / ADR X1,dword_462EC / SUBS X1,#0xC / MOV X0,X1 / ADDS X0,#0x3C / STR X0 / LDP X2,X9 / LDP / BR X9，地址 462C4-462E8；图28-29 Keypatch 把 462E8 的 BR X9 改为 B 0x4631C（0x4631C 处为标准函数序言 SUB SP,SP,#0xC0），与图32 F5 成功一致；图30-31 重新分析并 Apply patches。原文正文一处把 X9 写成 0x4632C，同段又写 B 0x4631C，图27/29 可判定 0x4631C 正确，卡内未沿用错误数值。卡内脚本与原文一致（bin_search 模式 E0 07 BE A9 E2 7B 01 A9、flare_emu 读 X9、keystone 生成 B、9 个 NOP）。次要偏差：原文跳板实为 10 条指令/40 字节，emulateRange 只覆盖前 36 字节（已足够读到 X9），卡内『10 条指令/36 字节可覆盖』表述不严谨，建议改为『36 字节（至 LDP X2,X9）即可取到 X9，整段 40 字节一并 patch』；不影响方法有效性。未验证点：未在本地复跑 patch 脚本；原文未给样本名与版本，affected_versions 为空正确。
---

## 一句话结论

so 把 `JNI_OnLoad` 换成一段"小栈 + 用 `ADR/SUBS/MOV/ADDS` 算出目标地址、经 `STR/LDP` 搬到 `X9`、再 `BR X9`"的跳板，跳转目标在静态分析里是计算值，于是 IDA 只显示 `JUMPOUT` 且 F5 失败；把 `BR X9` 改写成 `B <真实地址>`、其余指令 NOP 掉即可恢复反编译，配合 `bin_search` + `flare_emu` 模拟读 `X9` + `keystone` 汇编可批量处理全 so。

## 原理

- **花指令的本质是破坏静态可判定性**：`BR X9` 是寄存器间接跳转，`X9` 的值由前面几条算术指令在运行期算出，IDA 的栈平衡与跳转目标分析都拿不到常量，函数尾部落在"未知目标"，于是生成 `JUMPOUT` 伪代码并把整函数标记为不可反编译。
- **识别特征**：函数开头不是标准的 `STP x29,x30,[sp,#-N]!` 栈帧，而是"只开很小栈空间"且保存 `X0-X3`（ARM64 调用约定里 `X0-X7` 无需保存）；随后 `ADR X1, dword_xxx` → `SUBS X1,#0xC` → `MOV X0,X1` → `ADDS X0,#0x3C` → `STR X0,[SP,#var_8]` → `LDP X2,X9,[SP,#var_10]` → `BR X9`。中间那句 `ADDS` 的立即数与 `SUBS` 的差值决定了真实入口偏移，属于可人工心算、也可交给模拟器的形式。
- **为什么必须模拟而不能只靠模式匹配**：跳板里的常数会随样本变化（`ADR` 基址、`SUBS/ADDS` 的立即数都可能不同），用 unicorn/flare-emu 只执行这 36 字节再读 `X9`，比硬编码算术更稳。
- **patch 后为什么恢复**：把 `BR X9` 换成 `B target`（ARM64 的 `B` 是 PC 相对 26 位立即数，keystone 直接汇编即可），IDA 就有了显式控制流，`target` 处是标准函数序言（`SUB SP,SP,#0xC0` + `STP X28,X27,…`），栈帧与 CFA 随之恢复，F5 正常。
- **批量处理的前提**：这类跳板的机器码模式固定（本例 `E0 07 BE A9 E2 7B 01 A9` 即 `STP X0,X1,[SP,#-0x20]!` + `STP X2,X3,[SP,#0x20+var_10]`），可以全库搜索后逐个模拟取目标、逐个 patch，再 `auto_wait` 重新分析。

## 触发条件

- 目标为 ARM64 ELF（多为 Android so），IDA 中 `JNI_OnLoad` 或其它导出函数显示 `JUMPOUT`、F5 报栈不平衡/无法反编译。
- 花指令形如"算术算地址 → 存栈 → LDP 取回 → BR"的固定模式，且跳板长度固定（本例 10 条指令/36 字节可覆盖）。
- IDA 环境具备 `keystone`（汇编）、`flare_emu`（unicorn 模拟）插件与 Python 脚本执行权限。
- 允许修改文件（patch 后需保存，后续 unidbg/静态分析都用 patch 版）。

## 利用步骤

1. 观察 `JNI_OnLoad` 伪代码只剩 `JUMPOUT(0x…)`，切到汇编确认是"小栈 + `ADR/SUBS/MOV/ADDS/STR/LDP/BR`"模式。
2. 手工验证一次：按 `ADR` 基址减 `SUBS` 立即数、加 `ADDS` 立即数算出目标，确认目标处是标准函数序言。
3. 手工 patch：`BR X9` → `B 0x<target>`，其余 9 条改 `NOP`；`C`/`P` 应用 patch，重新分析，确认 F5 成功。
4. 批量：`bin_search` 搜 `E0 07 BE A9 E2 7B 01 A9`，对每个命中 `emulateRange(addr, addr+36)` 读 `X9`，`keystone` 汇编 `B target` 写到首条、9 个 `nop` 写到其后。
5. `idc.auto_wait()` 后重新分析程序（Edit → Plugins → 重新分析），保存 patched 文件。
6. 用 IDA 打开 patch 后的 so，确认 `JNI_OnLoad` 可 F5，再进入签名逻辑分析。

## PoC

```python
import keystone, ida_bytes, idaapi, idc, flare_emu

def binSearch(start, end, pattern):
    out, addr = [], start
    end = idc.BADADDR if end == 0 else end + 1
    while True:
        addr = ida_bytes.bin_search(addr, end, bytes.fromhex(pattern), None,
                                    idaapi.BIN_SEARCH_FORWARD, idaapi.BIN_SEARCH_NOCASE)
        if addr == idc.BADADDR:
            break
        out.append(addr); addr += 1
    return out

eh = flare_emu.EmuHelper()

def patch(addr):
    eh.emulateRange(startAddr=addr, endAddr=addr + 36)
    target = eh.getRegVal("X9")                     # 跳板算出的真实入口
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    b, _ = ks.asm(f"B {hex(target)}", addr)
    nop, _ = ks.asm("nop", 0)
    ida_bytes.patch_bytes(addr, bytes(b))
    ida_bytes.patch_bytes(addr + 4, bytes(nop) * 9)

for a in binSearch(0, 0, "E0 07 BE A9 E2 7B 01 A9"):
    idc.create_insn(a); idc.auto_wait()
    patch(a)
```

```text
; patch 前（跳板）
STP  X0, X1, [SP,#var_20]!
STP  X2, X3, [SP,#0x20+var_10]
ADR  X1, dword_462EC
SUBS X1, X1, #0xC
MOV  X0, X1
ADDS X0, X0, #0x3C
STR  X0, [SP,#0x20+var_8]
LDP  X2, X9, [SP,#0x20+var_10]
LDP  X0, X1, [SP,#0x20+var_20],#0x20
BR   X9
```

## 变体与关联

- 变体：跳板指令数不固定时，把 `emulateRange` 的结束地址改为"直到命中 `BR`"或按 `BR` 指令长度动态算。
- 变体：同类花指令也见于 `init_array` 构造函数、`JNI_OnLoad` 前后的 `pthread_once` 包装；模式串随编译变化，需先人工确认再批量。
- 变体：若跳板里包含反调试（`ptrace`/`read` 系统调用）判断，直接 patch 成 `B` 会跳过检测，反而更利于后续 unidbg 复现。
- 关联：[[code-analysis-reverse-obfuscation-tcc-junk-controlflow-idc-deobfuscation]]（x86 侧的控制流花指令批量修复）、[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]（jz 跳过式花指令）。
- 关联：[[mobile-android-sig3-unidbg-trace-crc32-whitebox-aes-hmac]]（本文 patch 后的 so 用于该签名逆向）。

## 检测与防御

- 防御（App 侧）：花指令只能拖延静态分析，需与运行时保护（完整性校验、反调试、白盒化）组合；单纯跳板花指令在模拟器面前成本很低。
- 检测（分析侧）：无。
- 注意：patch 后必须保留原始样本与 patch 记录，避免后续对不上偏移；批量脚本务必先在小样本验证 `X9` 取值，误 patch 会导致 so 无法运行。
