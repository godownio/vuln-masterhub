---
id: ctf-reverse-fnv1a-jumptable-base131-hash
title: FNV-1a 取模跳表分发 + 131 进制哈希反解：剔除假 flag 分支
type: scenario
domain: ctf
path: ctf/reverse
technique: fnv1a-jumptable-base131-hash
aliases:
- Ragebait
- FNV-1a
- 跳表分发
- 1009
- 131 进制哈希
- 假 flag 分支
tags:
- reverse
- fnv1a
- jump-table
- hash
- base131
- decoy
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:08:49+08:00'
  notes: 已对照原文核对：strlen==0x20、前 9 字符 FNV-1a（0x811c9dc5/0x1000193）、%1009、跳表 0x44e080、4 个 64 位常量、h*131+c 反解与 flag texsaw{VVhYd_U_M4k3_mE_s0_4n6ry} 均一致。未验证点：无二进制附件，PoC 未复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

stripped ELF 用输入前 9 字符的 FNV-1a 32 位哈希对 1009 取模，从跳表里选一个函数执行；绝大多数分支打印假 flag/回显输入/退出/喂 `/bin/sh`，只有 `0x42fe9c` 做真校验：把 32 字符按 `i%4` 分成 4 组，每组 8 字符做 `h = h*131 + c`，与 4 个常量比较；因为字符 < 131，直接按 131 进制取余即可反解。

## 原理

- **入口限制**：`main` 检查参数存在且 `strlen == 0x20`（32 字符）。
- **跳表分发**：取前 9 字符调用 `0x401216`（FNV-1a 32：offset basis `0x811c9dc5`、prime `0x1000193`），结果 `% 1009`，从 `0x44e080` 的表里取函数指针并调用。
- **假分支**：`.rodata` 里有 `texsaw{nope_not_here}`、大量 `[SUCCESS] Flag: %s`、`/bin/sh`；跳表分支会打印假 flag、把输入当成功回显、直接 exit，或把输入喂给 `/bin/sh -c`。只看输出会被误导。
- **真校验**：`0x42fe9c` 初始化 4 个 64 位变量为 0，循环 `h[i%4] = h[i%4]*131 + input[i]`，最后与：
  `c0=0x0112996d9ae479fd`、`c1=0x00efb70b2a601818`、`c2=0x011c799cc5063ac2`、`c3=0x01100d35eadc1177` 比较。
- **反解**：32 字符按 `i%4` 分组，每组正好 8 个字符；`h = ((...(0*131+s0)*131+s1)...)*131+s7` 就是 8 位 131 进制数。因为 ASCII < 131，反复 `divmod(h,131)` 得到 8 个字符（逆序），再按组交错拼回原串。
- **结果**：`texsaw{VVhYd_U_M4k3_mE_s0_4n6ry}`。

## 触发条件

- stripped ELF/PE，输入长度固定，存在“哈希 → 取模 → 函数表调用”的分发结构。
- 表项数量较大（本题 1009），大量分支是假 flag/回显/exit/shell 等诱饵。
- 真校验分支使用可逆的线性哈希（`h = h*base + c`）和固定常量比较。
- 字符集范围小于 base（如 ASCII < 131），保证进制反解唯一。

## 利用步骤

1. 用 `file`/`checksec` 确认架构与保护；运行观察输入长度/提示。
2. 定位 `strlen` 比较、哈希函数（FNV-1a 常量 `0x811c9dc5`/`0x1000193`）、取模常量（`0x3f1=1009`）和跳表地址。
3. 枚举/反编译跳表分支，标记假 flag/回显/exit/shell；找真正做完整比较的函数。
4. 在真校验里提取 4 个目标常量和哈希公式 `h[i%4]=h[i%4]*base+c`。
5. 对每个常量反复 `divmod(_, base)` 取 8 个字符，反转；按 `i%4` 交错拼回。
6. 用程序本地验证/重新计算哈希，确认 flag。

## PoC

```python
consts = [
    0x0112996d9ae479fd,
    0x00efb70b2a601818,
    0x011c799cc5063ac2,
    0x01100d35eadc1177,
]

groups = []
for x in consts:
    s = []
    for _ in range(8):
        x, r = divmod(x, 131)
        s.append(chr(r))
    groups.append("".join(reversed(s)))

flag = "".join(groups[j][i] for i in range(8) for j in range(4))
print(flag)  # texsaw{VVhYd_U_M4k3_mE_s0_4n6ry}
```

## 变体与关联

- **哈希变体**：FNV-1a 32/64、djb2、CRC32；取模常量/表大小不同。
- **分发变体**：函数指针表、switch jump table、虚表；假分支可能打印假 flag、回显输入、`system`、`exit`。
- **校验变体**：`h = h*base + c` 的 base-N 哈希、滚动哈希、分组交错；只要 base > 字符范围就可反解。
- **关联卡片**：[[web-java-deser-fastjson2-fnv-collision-autotype-bypass]]（FNV-1a 碰撞）、[[ctf-reverse-upx-vm-rolling-hash-per-char-inversion]]（滚动哈希反推）、[[ctf-reverse-z3-constraint-equation-solve]]（约束求解）。
- **边界**：若 base ≤ 字符范围、或哈希含异或/取模等不可逆操作，不能直接 divmod；需要额外约束/爆破。假 flag 不能直接提交。

## 检测与防御

- **防御**：不要用“输入前缀哈希 + 跳表”做校验；使用服务端/加密 MAC；去除调试/假 flag/`/bin/sh` 分支。
- **检测信号**：大量 `[SUCCESS] Flag: %s` 字符串但只有一个真比较；FNV-1a 常量 + 取模 + 函数表；`/bin/sh` 被当命令执行。
- **CTF 技巧**：先识别假分支，再找真校验；看到 `h*131+c` 就想 base-131 反解。
