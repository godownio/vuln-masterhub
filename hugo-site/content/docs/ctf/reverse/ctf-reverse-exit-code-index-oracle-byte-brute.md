---
id: ctf-reverse-exit-code-index-oracle-byte-brute
title: exit(code) 返回下标当 oracle：把比较失败改成 exit(i)，用子进程返回码逐字节爆破 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: exit-code-index-oracle-byte-brute
tags:
- ctf
- reverse
- brute-force
- oracle
- exit-code
- patching
- ida
- subprocess
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:44:47+08:00'
  notes: 已对照原文核对；exit(i) 泄露失败下标、子进程 returncode 当 oracle、单字节加密前提与原文一致；已修正悬空 wiki 链接指向 idc 卡实际 id；未运行原文样本与脚本
url: /docs/ctf/reverse/ctf-reverse-exit-code-index-oracle-byte-brute/
draft: false
kb_aliases:
- 退出码爆破
- exit 返回下标免爆破
- returncode oracle
- 逐字节 exit 爆破
- subprocess returncode 爆破 flag
---

## 一句话结论

校验循环里逐字节比较失败时若只打印一句 "failed"，攻击者无法得知"对了几个字节"；把它 patch 成 `exit(i)`（i 为失败下标），进程返回码就直接等于"已匹配的字节数"，脚本每轮枚举当前字节的全部候选字符、取 `returncode` 最大（或达到期望值）的那个字符即可逐位推进，最终不逆向加密算法也能还原完整 flag。

## 原理

- **把"进度"泄成返回码**：原程序 `if (l[i] != enc[i]) { puts("Flag verification failed."); exit(1); }` 只给二值结果；改成 `exit(i)` 后，输入前 k 个字节正确、第 k 个错误时返回码为 k，于是"返回码递增"就等于"前缀匹配变长"。
- **字节独立性是前提**：原文题目的加密是单字节运算（`*(8*v6+i) = v7 ^ a1[i]` 之后一串加减/异或/乘除，每字节只依赖自身下标与固定常量），因此改第 i 字节不会影响第 i-1 及之前的匹配结果，才可以按位置独立枚举。若加密有跨字节扩散（分组密码/依赖前一字节的链式），该 oracle 仍可用但需按块枚举。
- **为什么改 exit 而不是改打印**：`exit` 的参数直接进进程返回码，脚本用 `subprocess.Popen(...).returncode` 即可读取，无需解析 stdout；比"打印匹配长度"更稳（不受缓冲/编码/日志干扰）。
- **枚举成本**：字符集 94 个可打印字符 × flag 长度（原文从第 6 位到倒数第 1 位，约 20 次），每次一次进程启动，秒级完成。
- **patched 汇编要点**：原文把 `exit(1)` 处改成从比较循环的 `i` 取值并 `call _exit`（Interrupt 里用 `mov edi, [rsp+status]` 之类取当前下标，必要时用 `nop` 填充腾出的指令空间），再保存 patched 副本供脚本反复调用。

## 触发条件

- 二进制包含"输入 → 逐字节加密 → 与硬编码数组逐字节比较 → 失败即退出"的结构；
- 加密按字节独立（或可按块枚举），无随机密钥/IV；
- 能修改程序并保存副本（IDA/Ghidra 的 patch 或直接二进制改写）；
- 能在本地反复运行程序（Linux/WSL/容器皆可，原文注明需 Linux 环境运行 ELF）。

## 利用步骤

1. 在 IDA 里定位校验循环：找到比较指令（如 `cmp [l+i], [v8+i]` 或 `cmp sil, [rbx+rax]`）与失败分支（`puts("Flag verification failed.")` + `exit(1)`）。
2. 先恢复到可分析状态：若目标代码段被逐字节 XOR 加密（原文两个区间用 0x43/0x44 异或加密），先用 IDC/IDAPython `PatchByte` 把区间还原，再反编译出校验逻辑。
3. patch 失败分支：把 `exit(1)` 的参数改成当前下标 `i`（寄存器或栈变量），腾出的字节用 `nop` 填充；保存 patched 可执行文件。
4. 写爆破脚本：构造占位输入（如 `WuCup{` + 若干 `a` + `}`），对位置 i 枚举字符集，每次 `Popen` 运行 patched 程序、`communicate(input=候选)`，比较 `returncode`；返回码超过当前记录即采纳该字符并固定。
5. 同时监听 stdout 的 `Congratulations`，命中即结束；全部位置完成即得 flag。
6. 若返回码始终不变，检查：patch 是否真的改了 exit 参数、程序是否要求特定长度/前缀、字符集是否漏字符、加密是否跨字节。

## PoC

```python
import itertools, subprocess

alp = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
       "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
input_data = "WuCup{" + "a" * 20 + "}"
exe = "./love_patched"          # 已把 exit(1) patch 成 exit(i) 的副本
best = 0
ans = ""

for i in range(6, len(input_data) - 1):
    for ch in itertools.product(alp, repeat=1):
        cand = input_data[:i] + "".join(ch) + input_data[i + 1:]
        p = subprocess.Popen(exe, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        out, _ = p.communicate(input=cand)
        if p.returncode > best:          # 返回码 = 已匹配字节数
            best = p.returncode
            input_data = cand
            ans += "".join(ch)
            break
        if "Congratulations" in out:
            print("flag:", cand)
            raise SystemExit(0)
    print(i, input_data, best)
```

## 变体与关联

- 变体：不改 `exit`，改为把比较改成"匹配长度写入全局变量并在结束时打印"，同样得到线性 oracle，但需额外处理输出。
- 变体：把 `exit(i)` 换成 `exit(i*16)`/`exit(ord(enc[i]))`，返回码可携带更多信息（如直接泄露期望字节的哈希）。
- 变体：Windows 下 `ExitProcess(code)` 或 `int 3`/异常码，返回码同样可读；脚本改用 `subprocess` 的 `returncode` 即可。
- 关联：[[ctf-reverse-output-prefix-oracle-byte-brute]]（同族 oracle，那条不改 exit，靠程序打印的星号/字符数量判断前缀正确）。
- 关联：[[ctf-reverse-gdb-blackbox-bytewise-plaintext-brute]]（不改二进制，改用 gdb 断点读密文比对；本卡靠 patch 获得更廉价的外部 oracle）。
- 关联：[[ctf-reverse-idc-patch-xor-encrypted-code-segment]]（前置：先把被 XOR 加密的代码段还原，才能定位比较与 exit）。
- 边界：只有能 patch 且能反复运行才成立（远程服务需可重复连接，且返回码要能观测到）；若加密跨字节扩散，需要按块枚举或结合前缀差分。

## 检测与防御

- CTF/逆向：看到"逐字节比较 + 失败即 exit"，优先评估返回码/输出 oracle，通常比逆算法快。
- 软件保护（防守视角）：校验不要用"逐字节比较后立刻退出"的结构，改为常量时间整块比较并只给二值结果；返回码统一为 0/1；避免把内部下标写进 `exit`/日志；配合反调试与完整性校验。
