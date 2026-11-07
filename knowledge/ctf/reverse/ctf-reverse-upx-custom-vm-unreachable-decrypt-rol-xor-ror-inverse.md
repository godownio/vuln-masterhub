---
id: ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse
title: UPX 自定义 VM 逆向：PE 段表 VA 映射补零 + 不可达解密路径的 rol/xor/ror 求逆
type: scenario
domain: ctf
path: ctf/reverse
technique: upx-custom-vm-unreachable-decrypt-inverse
aliases:
- UPX 自定义虚拟机
- PE VirtualSize 零填充
- setjmp 不可达路径
- rol/xor/ror 求逆
- 字节码 VM 逆向
tags:
- reverse
- upx
- pe
- virtual-machine
- bytecode
- setjmp
- rotation
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:46:21+08:00'
  notes: 已对照原文核对；PE VirtualSize 补零、setjmp 不可达路径、rol/xor/ror 求逆与四组验算一致
---

## 一句话结论

样本是 UPX 加壳的 PE32 自定义字节码 VM：脱壳后必须按 PE 段表把虚拟地址映射到文件偏移并对 `VirtualSize` 超出 `SizeOfRawData` 的部分补零，否则字节码尾部会短 16 字节；程序用 `setjmp` 把解密函数锁在运行期不可达的除零异常路径里，只能在静态还原解释器后用 `rol/xor/ror` 的逆变换解出 flag。

## 原理

- **UPX 识别**：段名 `UPX0/UPX1/UPX2` 齐全、UPX 魔数在位，版本串被改成 3.96；`upx -d` 仍能识别，从 6158 字节解到 11278 字节。脱壳后出现 `.eh_frame`，编译标识 `GCC: (tdm-1) 5.1.0`，为 mingw 交叉编译。
- **PE 段映射陷阱**：`.data` 的 `VirtualSize` 为 0x1f0，而 `SizeOfRawData` 对应的映射只到文件内 0x31d0；虚拟地址超出 raw 数据的部分在加载时被零填充，文件里本来没有。直接按文件偏移读字节码会少 16 字节，必须按段表计算 `rva → raw_ptr + (rva - s.rva)`，缺失部分补零。
- **不可达解密路径**：`main` 把 `ctx+0x120/0x124/0x128` 设为 0/0/1，`ctx+0x12c` 指向字节码，然后 `setjmp`；正常返回 0，`xor_pass` 一次都不会执行。结尾 0x4019da 的除法除数是 `ctx[0xfc]`（对应 `buf[0xec]`），而输入只有 38 字节有效内容，恒为零；真机上除零直接终止进程，`longjmp` 回不去。程序在任何实机上都走 wrong 分支。
- **解释器结构**：解释器在 0x40137a，指令从 `ctx[0x12c] + pc` 取，操作数是 1 字节寄存器号，寄存器堆在 `ctx + 0x40 + 4*idx`；共 12 条指令。
- **旋转指令误读**：反编译器会把 0x22/0x23 渲染成双寄存器操作数，实际第二个字节是立即数；需要按汇编语义修正。
- **变换公式**：单组正向变换为 `out = ror32(rol32(in, 8) ^ (keys[i % 7] + i), 8)`。不能把 `ROL 8` 与 `ROR 8` 当成互逆抵消，因为异或夹在中间，旋转与异或不满足交换律；必须按“先反 ROR、再异或、再反 ROL”三步求逆。

## 触发条件

- 目标为 UPX 等可自动脱壳的 PE/ELF，脱壳后包含自定义字节码解释器。
- 解释器数据段存在 `VirtualSize > SizeOfRawData`，按文件偏移直接读取会缺尾部数据。
- 解密/校验逻辑被 `setjmp`、异常、反调试或条件分支锁在不可达路径，动态执行无法到达。
- 变换由可逆的线性/旋转/异或运算组成，密钥常量可从 `.text` 立即数或数据段提取。

## 利用步骤

1. 识别并脱壳：`upx -d` 解出原始 PE，记录段表；用 `va_to_off` 按 `max(virt_size, raw_size)` 计算映射，raw 之外补零。
2. 定位 `main`：`scanf("%99s")`、长度 `0x26` 判断、`memset(ctx, 0, 0x14C)`、`setjmp`、`memcmp_target` 等特征。
3. 确认不可达路径：`setjmp` 正常返回 0 跳过 `xor_pass`；检查异常路径的除数是否为 0，确认动态调试无法进入解密函数。
4. 反汇编解释器：从 0x40137a 提取 12 条指令语义、寄存器堆布局、pc 推进规则、越界跳过行为、ADD 的无符号回绕、CMP 无符号比较、CJMP 的 DWORD 绝对地址。
5. 还原字节码：从 `ctx[0x12c]` 指向的 0x403180 读取；目标密文在 0x403140；七个密钥常量在 `.text` 连续的 `mov dword [esp+disp], imm32` 指令中。
6. 求逆：对每组先 `t = rol32(out, 8)`，再 `plain_rol = t ^ ((key + i) & 0xffffffff)`，最后 `in = ror32(plain_rol, 8)`。
7. 交叉验证：按汇编逐条复刻解释器，把解出的 flag 灌进去，比对输出与 0x403140 的 40 字节目标密文逐字节一致；脚本不写死常量，换样本也能跑。

## PoC

VA 到文件偏移映射（含零填充）：

```python
def va_to_off(pe, va):
    rva = va - pe.image_base
    for s in pe.sections:
        span = max(s.virt_size, s.raw_size)
        if s.rva <= rva < s.rva + span:
            off = s.raw_ptr + (rva - s.rva)
            return off if off < len(pe.data) else None  # 缺失部分按 0 处理
    raise KeyError(hex(va))
```

求逆：

```python
def ror32(x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff
def rol32(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff

t         = rol32(out, 8)
plain_rol = t ^ ((keys[i % 7] + i) & 0xffffffff)
in        = ror32(plain_rol, 8)
```

原文前四组验算得到 `flag`、`{c6e`、`cb7c`、`0afa`，证明求逆正确；最终 flag 由七个密钥常量拼接而成。未在本机复跑样本。

## 变体与关联

- **旋转/异或组合**：`rol(a,8) ^ k != rol(a ^ k,8)`，遇到“看起来互逆”的旋转对时，必须先画清运算顺序再求逆。
- **不可达路径**：`setjmp`/`longjmp`、异常处理、反调试分支、除零、条件永不成立等，都是把核心算法藏在动态执行之外的手法；静态还原后仍需用目标密文验证。
- **脱壳后数据缺失**：不只在 PE，ELF 的 `p_filesz < p_memsz`、资源段、压缩段也有同类零填充问题。
- **关联**：与“字节码 VM 逆向”“自定义虚拟机的指令表还原”同类；本卡强调 UPX + PE 映射 + 不可达路径三个坑的组合。

## 检测与防御

- 逆向侧：先脱壳、再按段表修正数据；对不可达路径优先静态还原，不要只依赖动态调试。
- 防护侧：不要用输入长度不足导致的恒零除数来“锁”逻辑，这类路径可被静态分析绕过；对关键算法使用白盒/混淆时仍需保证可验证性。
- 检测特征：UPX 段名与魔数、`VirtualSize > SizeOfRawData`、`setjmp` 后紧跟解密函数、字节码解释器大跳转表、连续 `mov dword [esp+disp], imm32` 密钥常量。
