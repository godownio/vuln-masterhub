---
id: ctf-reverse-smc-runtime-attach-xxtea-same-var-double-shift-mix
title: SMC 自解密 + 魔改 XXTEA：mix 改成同一变量双移位项，运行时 Attach 取真代码后逆轮
type: scenario
domain: ctf
path: ctf/reverse
technique: smc-runtime-decrypt-attach-custom-xxtea-same-variable-double-shift-mix
tags:
- ctf
- reverse
- smc
- self-modifying-code
- xxtea
- custom-mix
- debugger
- unpacking
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:47:34+08:00'
  notes: 已对照原文核对：SMC 计时/Attach dump 流程、0x61C88647 累减、((p<<4)^(p>>3))+((p<<2)^(p>>5)) 同变量双移位 mix、((p^key)+(p^num))^mix(p) 组合方式、key 索引 ((num>>2)&3)^e、12 个密文字与 4 个 key 字、32 轮(52/n+6 在 n=2 时=32)均与正文一致；原文未给版本/CVE，未设 affected_versions；本次核对未读取图片，仅依据正文。未验证点：PoC 未在本机执行
url: /docs/ctf/reverse/ctf-reverse-smc-runtime-attach-xxtea-same-var-double-shift-mix/
draft: false
kb_aliases:
- SMC 题目运行时 Attach
- 魔改 XXTEA mix
- 同一变量双移位项
- (p<<4)^(p>>3) + (p<<2)^(p>>5)
- delta 0x61C88647 累减
- 补环境后 dump 解密后代码
---

## 一句话结论

题目把真正的校验函数用 SMC（自修改代码）在运行时解密后再执行，静态反汇编看到的是一段无意义字节；做法是补齐运行环境直接运行程序、在解密完成处 Attach 调试、把内存里已成形的代码 dump 出来再看——识别出是 XXTEA 家族后，仍不能照抄标准实现，因为它的 `mix` 把标准的两变量交叉移位换成了**同一变量的两组移位相加**（`((p<<4)^(p>>3)) + ((p<<2)^(p>>5))`）且 `num` 以 `-0x61C88647` 累加，逆轮时必须逐字减掉这个混合值、并按原始轮数与 key 索引式子回退。

## 原理

- **SMC 的本质**：一段代码在磁盘上是密文/错误指令，入口处（如 `call sub_41136B`）用密钥就地解密到同一地址，之后才跳到那里执行。静态反汇编工具读的是文件里的原始字节，因此看到的是垃圾；只有运行时内存中才是真代码。
- **为什么必须「补环境后运行 + Attach」**：如果程序带反调试或在解密完成后立刻校验环境，静态 dump 文件拿不到解密结果；直接在真实进程中 Attach（或在解密函数返回处下断点）能拿到**已解密、未执行**的字节，既能 dump 又不会触发后续校验。
- **识别 XXTEA 家族的特征**：`num` 每轮加减 `0x61C88647`（`-delta`，因为 `0x9E3779B9` 的补码即为它）、`(num >> 2) & 3` 选 key 索引、`key[(p & 3) ^ e]`、每轮处理两个 32 位字、固定 32 轮、最后与明文/密文数组逐字累加。
- **魔改点在 mix**：标准 XXTEA 的混合值是 `((z>>5) ^ (y<<2)) + ((y>>3) ^ (z<<4))`（两个变量交叉移位）；本例是 `((p<<4) ^ (p>>3)) + ((p<<2) ^ (p>>5))`，**两项都只对同一个字 p 做移位**，等于把「交叉耦合」改成「自身非线性变换」，并且与 `(p ^ key) + (p ^ num)` 的组合关系是**异或**而非相加。这意味着加解密仍可逆（每一轮只是从目标字里减去一个只依赖源字的量），但**照抄标准 XXTEA 库解不出来**。
- **逆轮顺序**：加密是 `p[0] += m(p[1]); p[1] += m(p[0])`（`m(x) = ((x ^ key) + (x ^ num)) ^ mix(x)`），因此解密要从最后一轮往回：先 `p[1] -= m(p[0])`，再 `p[0] -= m(p[1])`，且 `num` 的初值必须是加密结束时的值（`0 - 32 * 0x61C88647`），每轮回退加回 `0x61C88647`。
- **key 索引的位运算必须逐字照抄**：`k[(((num >> 2) & 3) ^ 0) & 3]` 与 `k[(((num >> 2) & 3) ^ 1) & 3]` 这种多重 `&3` 看似冗余，但 `num` 是有符号/无符号混用的 32 位值，随意化简会改变索引。
- **为什么这道题还要「补环境」**：SMC 解密函数可能依赖运行时初始化（全局表、TLS、异常处理），未补环境时直接在调试器加载会因初始化缺失而跑不到解密分支。

## 触发条件

- 目标程序存在 SMC/自解密：入口附近有对代码段的写操作（`VirtualProtect`/`mprotect` 后循环异或/加法写回），静态反汇编在该区域无有效指令。
- 能在可控环境中运行程序（补齐依赖、跳过联网校验），并允许 Attach 调试或使用支持「运行到某地址再 dump」的调试器。
- 解密后的校验逻辑为对称加密（XXTEA/TEA/魔改变体），密文与 key 可从数据段或栈上取得。
- 允许修改内存/寄存器以绕开反调试（否则 Attach 会被检测）。

## 利用步骤

1. 静态粗看：找入口处的解密调用（如 `call sub_41136B` 紧跟 `nop`），确认解密目标是一个代码段地址（`offset unk_41F0F3` 之类）。
2. 补齐环境：安装依赖、把校验所需的输入/参数准备好，先让程序能正常跑到输入处。
3. Attach 调试：在解密函数返回处下断点（或在解密循环结束后单步），确认目标区域已变成有效指令。
4. dump 代码段：把解密后的区域按原始基址写回文件（或用调试器的 dump 功能），重新反汇编即可看到真实逻辑。
5. 识别算法：看 `0x61C88647`、`(num>>2)&3`、`key[(p&3)^e]`、32 轮常量，判定为 XXTEA 家族；仔细比对 mix 表达式是否与标准库一致。
6. 抄写 key 与密文数组（本例 12 个 32 位字、key 4 个 32 位字，含 `0x5201314`/`0x52013140` 这种成对常量）。
7. 按二进制中的 mix 写解密：逆轮顺序、`num` 初值、每轮回加 `0x61C88647`、索引位运算原样保留；解出的字节按小端打包成字符串。
8. 用原程序验证解出的 flag；若结果乱码，优先怀疑 mix 抄错（尤其是两个移位项作用在哪个变量上）或轮数不对。

## PoC

```python
MASK = 0xFFFFFFFF

def mix(p):
    # 两个移位项都作用在同一个字 p 上，再与 (p<<4)^(p>>3) 那一项做加法拼接
    return (((p << 4) ^ (p >> 3)) + ((p << 2) ^ (p >> 5))) & MASK

def dec(c, k, rounds=32):
    num = (0 - rounds * 0x61C88647) & MASK
    for _ in range(rounds):
        # 注意：组合方式是 [(p ^ key) + (p ^ num)] ^ mix(p)，是异或而非相加
        c[1] = (c[1] - (((c[0] ^ k[(((num >> 2) & 3) ^ 1) & 3]) + (c[0] ^ num)) ^ mix(c[0]))) & MASK
        c[0] = (c[0] - (((c[1] ^ k[(((num >> 2) & 3) ^ 0) & 3]) + (c[1] ^ num)) ^ mix(c[1]))) & MASK
        num = (num + 0x61C88647) & MASK
    return c

ct  = [0x5A764F8A, 0x005B0DF77 & MASK, 0xF101DF69, 0xF9C14EF4,
       0x27F03590, 0x7DF3324F, 0x2E322D74, 0x8F2A09BC,
       0xABE2A0D7, 0x0C2A09FE, 0x35892BB2, 0x53ABBA12]
key = [0x05201314, 0x052013140 & MASK, 0x05201314, 0x052013140 & MASK]

out = []
for i in range(0, len(ct), 2):
    out += dec(ct[i:i + 2], key)
import struct
print(struct.pack('I' * len(out), *out))
```

```text
要点：每轮是「(p ^ key_entry) + (p ^ num)」再与 mix(p) 异或，然后从目标字里减去；
mix 的两个移位项都作用于同一个字；num 以 -0x61C88647 起算、每轮回加；
key 索引的 ((num>>2)&3)^e 不能化简。解出后按小端打包成字节串即明文。
```

## 变体与关联

- 变体（其他魔改点）：`delta` 换成别的常量、轮数改成 42、key 先做 `rol32(key ^ const, 7)` 派生、末尾追加/去掉固定字节异或——每一处都会让标准库解密失败，判据是「结构像 XXTEA 但结果不对」。
- 变体（SMC 的其它形态）：入口逐字节异或、按页 `mprotect` 后再解密、只在特定分支解密；不变的是「运行时 dump 才能看到真代码」。
- 变体（脱壳替代方案）：若不方便调试，可用模拟执行（Unicorn/Qiling）跑过解密段再 dump，或用静态仿真脚本复刻异或循环。
- 关联：[[ctf-reverse-xxtea-custom-delta-derived-key]]（同族 XXTEA 魔改，但那道题自定义 `delta` 与密钥派生、mix 结构仍是标准交叉移位；本题改的是 mix 本身——两个移位项作用在同一变量，且从 SMC 运行时代码中取得）、[[code-analysis-reverse-windows-legit-dll-modification-bindiff]]（同类「静态看到的不是真实字节」的比对思路）。
- 边界：若 SMC 解密后立即校验自身哈希并自毁，需在解密与校验之间 dump；若程序在虚拟机/壳中运行且反调试很强，Attach 会被杀，改用模拟执行。

## 检测与防御

- 防御（题目/软件侧）：SMC 只是提高静态分析成本，不能阻止运行时 dump；可叠加解密后自校验、分段解密、指令级混淆（OLLVM）与反调试，但都只能延缓。
- 检测视角：进程对自身 `.text` 区域申请写权限并修改（`VirtualProtect`+写+`FlushInstructionCache`）是 SMC 的强特征；结合「写后立即跳转执行」可精准定位解密点。
- 逆向建议：先确认段权限变化，再在跳转目标处下断点；不要一开始就追解密循环，容易陷入几百行的异或运算里。
