---
id: ctf-reverse-output-prefix-oracle-byte-brute
title: 输出回显当进度条：程序打印的递增字符/星号数量即前缀匹配长度，逐字节枚举还原 flag（含 VM 双字节变体）
type: scenario
domain: ctf
path: ctf/reverse
technique: output-prefix-oracle-byte-brute
aliases:
- 回显爆破
- 输出长度 oracle
- 打印星号当进度
- VM 双字节爆破
- 逐位回显判断 flag
tags:
- ctf
- reverse
- brute-force
- oracle
- vm-obfuscation
- stdout
- multi-byte
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:44:51+08:00'
  notes: 已对照原文核对；ezvm 回显 chr(star) 判定、repeat=2 双字节粒度、flag vMp_1s_r0u9h_ORZ 与原文/img16 一致；未运行 ez_vm.exe
---

## 一句话结论

当校验程序在每匹配一个正确字节时就多打印一个字符（星号、数字、递增字符，或直接把"当前已匹配长度的字符"回显），这个回显本身就是进度条：脚本每轮枚举某一位的候选值，取"回显变长/回显字符变化"的那个候选固定下来，即可从第 0 位逐位推进；对 VM 类题目只要确认 op 是连续两次执行同一比较，则每次推进 2 字节，枚举空间为 94² 但仍可线性推进。

## 原理

- **回显即 oracle**：程序把"已匹配字节数 k"映射为输出（打印 k 个 `*`、输出字符 `chr(base+k)`、或把 `k` 位字符回显）。脚本无需理解算法，只需比较输出是否比上一轮"更靠后"，或是否等于期望值 `chr(base+step*(i+1))`。
- **为什么脚本可以直接读 stdout**：`subprocess` 拿到完整输出后按提示串（如 `Please input your flag :`）切分，取提示之后的部分作为"回显值"，避免把程序欢迎语误当结果。
- **VM 题的双字节粒度**：VM 题目里比较操作常由两个 op 组成（如先取值再比较），动态调试会看到"同一操作连续执行两次"；这说明一次校验覆盖 2 个输入字节。此时不是逐字节枚举，而是 `itertools.product(alp, repeat=2)` 枚举二元组，命中后 `star += 2`，仍然线性推进（最多 94² 次/组）。
- **为什么仍然可行**：这类题目的校验往往是"逐段加密后逐段比较"，段与段之间不互相影响（每段只依赖自身下标与固定常量），所以固定前缀后，当前段的正确值必然让回显推进；枚举空间再大也只是常数倍。
- **边界**：若回显只有二值（成功/失败）、或校验有全局耦合（校验和、整块哈希），则无法逐位推进，需要改用其它 oracle（退出码、时间侧信道、gdb 断点）。

## 触发条件

- 程序对输入做分段校验，并输出与"已匹配进度"相关的信息（星号数量、递增字符、回显前缀）；
- 段内校验只依赖该段自身（无跨段扩散），或可按段/块枚举；
- 能本地反复运行程序（原文为 Windows PE，路径 `ez_vm.exe`）；
- 字符集已知/可猜（原文用可打印字符集，含大小写、数字与符号）。

## 利用步骤

1. 运行程序看提示语与输出格式，确定"进度回显"的具体形态（星号数量？递增 ASCII 字符？回显前缀？）。
2. 动态调试确认校验粒度：在比较处下断，观察一次校验覆盖几个输入字节；若同一操作连续执行两次即为 2 字节粒度。
3. 构造占位输入（如全 `!`），按段枚举候选（1 字节或 2 字节），每轮运行并解析输出。
4. 判定命中：回显比上一轮"推进"（长度 +step、或字符等于期望值），采纳该候选并固定；同时检查是否出现成功提示（如 `You did it! Flag is ...`）。
5. 全部段完成后拼接得到 flag（原文结果为 `vMp_1s_r0u9h_ORZ`）。
6. 若某段枚举完所有候选仍未推进，检查：字符集是否漏字符、粒度是否更大、是否需按整块（>2 字节）枚举。

## PoC

```python
import itertools, subprocess

alp = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
       "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
input_data = "!" * 17
exe = "./ez_vm.exe"            # 目标程序
star = ord('A') + 2            # 期望回显的起点（按实际观察调整）
ans = ""

for i in range(len(input_data) // 2):            # 2 字节粒度
    for chars in itertools.product(alp, repeat=2):
        cand = input_data[:i * 2] + "".join(chars) + input_data[(i + 1) * 2:]
        p = subprocess.Popen(exe, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        out, _ = p.communicate(input=cand)
        prompt = "Please input your flag :"
        tail = out.split(prompt, 1)[-1].strip() if prompt in out else ""
        if tail == chr(star):                     # 回显推进到期望字符
            ans += "".join(chars)
            input_data = cand
            star += 2
            break
        if "You did it! Flag is " in tail:        # 最后一段
            ans += "".join(chars)
            print("flag:", ans)
            raise SystemExit(0)
```

## 变体与关联

- 变体：回显形态换成"打印 `*` 数量"（`puts` 循环 k 次），判定条件改为 `out.count("*") >= 上一轮`。
- 变体：一次校验 3+ 字节时枚举 `repeat=3`（94³ ≈ 8e5 次，仍可接受但建议先逆向缩小字符集）。
- 变体：把回显解析换成"响应长度/时间"侧信道（打印越多耗时越长），判定改为比较执行时长。
- 关联：[[ctf-reverse-exit-code-index-oracle-byte-brute]]（同族 oracle，那条用进程返回码、需 patch 二进制；本卡不需要 patch，只需读 stdout）。
- 关联：[[ctf-reverse-gdb-blackbox-bytewise-plaintext-brute]]（不改程序、靠 gdb 断点读密文的黑盒爆破）。
- 边界：回显仅二值或校验全局耦合时失效；VM 题若 op 之间共享状态（寄存器/内存被后续 op 修改）导致段间耦合，需要先逆向 VM 结构再决定粒度。

## 检测与防御

- CTF/逆向：多字节粒度先用动态调试确认（同一 op 连续两次是典型信号），再用二元组枚举线性推进。
- 软件保护（防守视角）：校验输出只给二值结果、不要打印与"已匹配长度"相关的任何信息（星号/进度/回显字符）；比较用常量时间整块；对 VM/混淆仍保留这些原则即可显著提高爆破成本。
