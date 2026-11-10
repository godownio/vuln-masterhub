---
id: ctf-reverse-per-char-hex-ciphertext-argv-prefix-brute
title: 程序把 argv 里的 flag 前缀逐字符加密后按 hex 打印：每位密文互相独立，直接对每一位枚举可打印字符、比对目标 hex 对即可还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: per-char-hex-ciphertext-argv-prefix-brute
tags:
- ctf
- reverse
- brute-force
- oracle
- argv
- hex
- xor
- ctypes
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:39:39+08:00'
  notes: 已对照原文核对；本次核对未读取图片；re.exe f/fl/fla 输出 2329/23291e/23291e24 的递增回显、ENCRYPTED_VALUES=[35,41,30,36,56,14,...] 与 hex 对一一对应（0x23=35 等）、start_index=5（flag{ 前缀）、逐位枚举 printable 比对 output[idx*2:idx*2+2] 的做法均与正文脚本一致；原文只给脚本未给最终 flag，卡片亦未编造 flag；
url: /docs/ctf/reverse/ctf-reverse-per-char-hex-ciphertext-argv-prefix-brute/
draft: false
kb_aliases:
- dump 逐字符异或爆破
- argv 传 flag 前缀爆破
- 逐字节独立加密
- hex 输出比对爆破
- 长度递增输出即进度条
---

## 一句话结论

当目标程序把命令行参数当 flag（`re.exe flag{...}`）并对每个字符**独立**做单字节变换，然后把整串密文按 hex 打印时，这个 hex 输出就是最直接的 oracle：先用 `re.exe f`、`re.exe fl`、`re.exe fla` 观察「输出每多 2 个 hex 字符 = 又解对一位」，再对外层已知下标 `idx` 枚举可打印字符，取「第 `idx` 位那对 hex 等于目标数组对应项」的字符逐位推进，即可还原整串，无需逆出加密公式。

## 原理

- **逐字节独立加密 = 每位都能单独求解**：变换若形如 `enc[i] = f(plain[i], i)`（不含前一位状态、不做分组链接），则第 `i` 位明文只影响第 `i` 位密文。于是「比对目标数组的第 `i` 项」就能唯一确定 `plain[i]`，无需知道 `f` 的表达式。
- **hex 输出使位数对齐关系可见**：每字节固定打印 2 个 hex 字符，第 `i` 位对应输出串的 `[2i, 2i+2)`。脚本切 `output[idx*2 : idx*2+2]` 与目标比较，正好对齐。
- **argv 传参让每次尝试无状态**：程序每次运行都从 `argv` 读取前缀重新加密，天然适合「每位起一个新进程」。若换成 stdin 交互、或加密依赖上一次运行的内存状态，就不能这样逐位独立枚举。
- **长度递增的输出本身就是进度条**：输入 `f`/`fl`/`fla` 时输出分别为空/`2329`/`23291e`，说明程序只对「已正确匹配的前缀」继续加密——这既确认了 oracle，也给出了 flag 的已知前缀（通常是 `flag{`）。
- **为什么不用反编译**：伪代码过于复杂（本例为混淆后的窗体程序）时，把「加密器当黑盒 oracle」比自己复刻公式更快；前提是必须验证「逐位独立」这一性质，否则会陷入错误假设。

## 触发条件

- 目标程序从 `argv`（或等价的「整串输入」入口）读取待校验字符串。
- 加密对每个字符独立（无分组链接、无前一位依赖、无随机盐），可用「同前缀不同末位字符 → 只有末位密文变化」验证。
- 程序把密文按 hex 或其它可定长切分的形式输出；且目标密文数组能从二进制/内存 dump 中取得。
- 每次运行状态干净（无状态残留、无超时惩罚），否则逐位枚举成本过高。

## 利用步骤

1. **确认入口与输出**：`./re.exe f`、`./re.exe fl` 观察输出是否随输入长度增长，确认「输出即密文、每字节 2 个 hex 字符」。
2. **验证逐位独立**：固定前缀长度，换一个末位字符再跑，确认只有最后 2 个 hex 变化；若整串都变，说明有链接/分组，不能用本方法。
3. **取目标密文数组**：从 `.data`/`.rdata` 常量、或调试时在 `memcmp` 处 dump 得到 `ENC[i]`（本例 22 项）。
4. **确定已知前缀**：按题目格式先填 `flag{`，令 `idx` 从 5 开始。
5. **逐位枚举**：对 `idx` 从 5 到 `len-1`，遍历可打印字符，跑一次程序取 `output[idx*2 : idx*2+2]`，与 `ENC[idx]` 比较，命中即固定该字符并推进。
6. **收尾校验**：最后一位通常是 `}`，可用于反证前面没有错位；再用完整 flag 跑一次程序，确认输出 hex 与目标数组逐项相等。

## PoC

```python
import subprocess
from string import printable

ENC = [35, 41, 30, 36, 56, 14, 21, 32, 55, 14, 5, 32, 0, 14, 55, 18, 29, 15, 36, 1, 1, 57]

def brute(prefix="flag{", start=5, total=22):
    flag = prefix
    for idx in range(start, total):
        for ch in printable:
            out = subprocess.run(["./re.exe", flag + ch],
                                 capture_output=True, text=True).stdout.strip()
            try:
                # 第 idx 位对应输出里的两个 hex 字符
                if int(out[idx * 2: idx * 2 + 2], 16) == ENC[idx]:
                    flag += ch
                    print("hit", idx, repr(ch), flag)
                    break
            except (IndexError, ValueError):
                continue
        else:
            raise SystemExit(f"no candidate at index {idx}")
    return flag

print(brute())
```

`ENC` 是「密文字节」而非 hex 字符串，所以比较前要把输出的两个 hex 字符 `int(..., 16)`；若目标数组本身存的就是 hex 字符串，直接字符串比较即可（省掉转换）。`total` 取目标数组长度，`start` 取已知前缀长度。

## 变体与关联

- oracle 形态变体：输出长度（打印 `*` 个数）、退出码（`exit(i)`）、耗时、标准输出逐位回显，本质都是「让程序自己告诉你对了几个字节」，见「输出前缀 oracle」「exit-code 下标 oracle」两类卡；本卡的区别是**输出即密文**，比对对象是目标数组而不是长度/返回码。
- 加密形态变体：`enc = plain ^ k`、`enc = (plain + i) & 0xff`、`enc = sbox[plain]`、单字节 RSA/查表；只要逐位独立都能套，且**不需要知道 `k`/`sbox`**。
- 有链接时变体：`enc[i] = plain[i] ^ enc[i-1]` 这类链式结构不能逐位独立枚举，但可「从第 0 位正序枚举」——因为前一位密文已知，仍能逐位推进。
- 关联：与「gdb 黑盒逐字节爆破」手法一致，区别是本卡不用调试器、纯靠程序自身输出；与「VM 指令数爆破」的区别是本卡 oracle 精度是「字节」而非「指令计数」。

## 检测与防御

- 校验逻辑不要输出中间密文，也不要让输出长度/内容随「已匹配字节数」变化——任何形式的进度反馈都可被当作 oracle。
- 若必须逐字节比较，先做 HMAC/整体哈希再常量时间比较，且失败时只返回统一的「失败」，不泄露位置信息。
- 加最小化反调试与运行次数限制只是延缓手段；根本做法是让「部分正确的输入」不产生任何可区分的外部可观测差异。
- 分析侧自检：拿到一个待逆向的校验器时，先做「同前缀换末位」测试判断是否逐位独立，能省掉大量反编译工作。
