---
id: code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida
title: VirtualProtect 运行时解密代码的 IDA 动态还原：断点执行解密后 U/C/P 重建函数
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: virtualprotect-runtime-code-decrypt-ida-recover
tags:
- reverse-engineering
- ida
- dynamic-debugging
- virtualprotect
- self-modifying-code
- smc
- unpacking
- windows
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V79
  verified_at: '2026-11-05T16:34:08+08:00'
  notes: 已对照原文与 19 张截图核对；修正关联链接为已存在的 anti-debug-sandbox-environment-checks，补全逆推 PoC 常量并写明两层解密；未在本机运行 shadow-code.exe，PoC 未实际执行，地址/偏移以样本为准；按原文公式与常量复算得到 8 字节输入 8qFcjsMm（未在样本上验证）。
  unverified:
  - PoC 未实际执行；样本为 CTF shadow-code.exe，具体地址/偏移以样本为准
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida/
draft: false
kb_aliases:
- VirtualProtect 自修改代码
- 运行时解密代码还原
- IDA U C P 重建函数
- SMC 自修改代码逆向
- 内存解密函数动态调试
- FlushInstructionCache 逆向
---

## 一句话结论

Windows PE 把函数体以密文形式存放、运行时用 `VirtualProtect` 改成 RWX、调用解密函数写回明文、再恢复保护并 `FlushInstructionCache` 时，静态 IDA 只能看到乱码；在调试器里让解密 stub 跑完、断在解密后的函数入口，再用 `U`/`C`/`P` 把数据重新识别为代码，即可恢复真正的校验逻辑。

## 原理

- 典型的运行时解密 stub：
  ```c
  VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE /*0x40*/, &old);
  crypto1(...); crypto2(...);              // 把密文解密到 addr
  VirtualProtect(addr, size, old, &old);   // 恢复原保护
  FlushInstructionCache(GetCurrentProcess(), addr, size);
  ((void (*)(...))addr)(...);              // 调用解密后的函数
  ```
- 文件在磁盘上时，目标区域是密文；IDA 的递归下降反汇编会把它当数据/无效指令，F5 也可能给出无意义结果。只有在进程运行、stub 执行后，该内存才变成合法指令。
- 动态调试时，先把断点打在解密调用之后或解密后的函数入口；命中后，IDA 调试器已能看到写入的明文机器码。若 IDA 没有自动重新分析，选中该区域依次按 `U`（undefine，清除旧数据/代码定义）、`C`（强制按代码反汇编）、`P`（创建函数），即可恢复函数边界与交叉引用。
- 另一种方式是直接把解密后的内存 dump 出来，重新用 IDA 以二进制/PE 方式加载分析；对多层解密或反调试较强的样本更稳。
- 原文的 `password_input` 先调用 `deal1`（`sub_...A0`）把 `loc_...480` 解密为 `deal2` 并调用；`deal2` 内部再次调用 `deal1` 解密第二个函数（`lpAddress_`）后跳入。静态看两处都是密文，动态跟进去后 IDA 识别出核心校验（异或、循环移位、加减），从而可以 patch 分支或逆推输入。
- 该手法与“脱壳”同源：壳/保护器在运行时解密代码，区别只是这里解密的是单个函数而不是整个节区。

## 触发条件

- 目标是 Windows PE，存在 `VirtualProtect`/`VirtualProtectEx` + 写内存 + `FlushInstructionCache` + 间接调用的组合。
- 静态 IDA 在目标函数处显示为数据、乱码或无法 F5；调用目标是通过函数指针/计算地址而非直接 call。
- 可以在本地或受控环境运行样本，并附加 IDA/x64dbg 调试器。
- 调试器能在解密 stub 之后、目标函数执行之前下断点（必要时用硬件断点）。

## 利用步骤

1. 用字符串/导入表定位入口：`Shift+F12` 搜索 `password` 等提示，`X` 查交叉引用，`F5` 看输入逻辑。
2. 找到“先解密再调用”的模式：`VirtualProtect(...,0x40,...)` → 写内存 → 恢复保护 → `FlushInstructionCache` → `call [addr]`。
3. 在解密调用之后、目标函数调用之前下断点；`F9` 运行到断点，确认目标区域已被写成明文。
4. `F7` 进入解密后的函数；若 IDA 仍显示数据，选中区域按 `U` → `C` → `P`，重建代码与函数。
5. 命名函数、梳理校验逻辑；必要时按 `F5` 重新反编译。
6. 两条利用路径：
   - Patch：运行到比较/分支处，选中 `RIP` 按 `E` 改成成功分支地址，继续运行拿到成功输出。
   - 逆算法：把校验公式反向（如 `ROL8` 取反为 `ROR64`，异或/加减逆序）求出输入。
7. 若动态分析不稳定，dump 解密后的内存段，另存为二进制/PE 重新加载，做静态分析。

## PoC

```c
// 运行时解密 stub 的关键模式
BOOL deal1(void *addr, SIZE_T size, ...) {
  DWORD old;
  VirtualProtect(addr, size, 0x40 /* PAGE_EXECUTE_READWRITE */, &old);
  crypto1(...);
  crypto2(...);                       // 解密到 addr
  VirtualProtect(addr, size, old, &old);
  FlushInstructionCache(GetCurrentProcess(), addr, size);
  return TRUE;
}
```

```text
IDA 操作：
1. Shift+F12 → 搜索 password → X 交叉引用 → F5
2. 在解密调用后 / 目标函数入口 F2 下断点
3. F9 运行，F7 进入；选中目标区域
4. U（undefine）→ C（code）→ P（function）
5. 分析校验；或选中 RIP → E → 改跳到成功分支
```

```python
# 逆推示例：target = (ROL64(src ^ A, 21) - D) ^ B
# 常量取自原文（0x6E4EA9AABAEB2EB4 为比较目标）
target = 0x6E4EA9AABAEB2EB4
A = 0x819173B095485D69
D = 0x1E277ACA3E3B2E23
B = 0xF216C53D78B72357

def ROR64(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF

src = ROR64(((target ^ B) + D), 21) ^ A
print(src.to_bytes(8, byteorder="big").decode("ascii"))
```

## 变体与关联

- 变体：多层解密（外层解密内层 stub）时，按相同方法在每层解密后下断点，逐层 `U/C/P` 或 dump。
- 变体：用 x64dbg + Scylla/PE dump 插件在内存中 dump 解密后的模块，再交给 IDA 静态分析。
- 变体：用 IDAPython 脚本在调试事件到达时自动对目标区域 `del_items`/`create_insn`/`add_func`，适合批量处理。
- 变体：若 `VirtualProtect` 被 hook 或反调试阻止，可用硬件执行断点、内核调试或 QEMU 跟踪替代。
- 关联：[[code-analysis-reverse-unpacking-upx-manual]]（整节区脱壳）、[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]（反调试/反沙箱）、[[code-analysis-vuln-discovery-javap-decompiler-reachability]]（反编译结果需字节码复核）。
- 边界：解密依赖硬件/环境（CPUID、时间、输入）导致动态与静态不一致、调试器被反调试拦截、目标函数只在特定分支解密时，需要构造触发条件或改用模拟执行。

## 检测与防御

- 检测（分析/防御视角）：监控 `VirtualProtect` 把私有内存改为 RWX、随后写入并 `FlushInstructionCache` 的行为；对同一内存页先写后执行的序列做告警；定期扫描进程内存中的可执行私有页。
- 检测（逆向视角）：静态发现 `VirtualProtect/FlushInstructionCache` 导入与间接调用；动态在写内存 API 上下断点，定位解密后的代码区域。
- 加固：软件保护可使用代码完整性/签名校验，但运行时解密本质可被调试器绕过；对恶意样本，EDR 应结合内存扫描与 API 序列检测，而不是只看磁盘文件。
