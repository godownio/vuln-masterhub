---
id: ctf-reverse-md5-prefix-crack-byte-permute-xor-dfs
title: HNCTF 2022 findit 逆向：6 位口令 MD5 爆破 + 字节置换异或链多解 DFS 还原
type: scenario
domain: ctf
path: ctf/reverse
technique: md5-prefix-crack-byte-transform-dfs
tags:
- ctf
- reverse
- md5
- dfs
- xor
- bruteforce
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V635
  verified_at: '2026-11-13T01:09:11+08:00'
  notes: 已对照原文与 25 张图核对。独立复算：md5('HN_CTF')=32cbe93f1dd4f2f3be1c85983d6994c1 与原文常量一致；按卡内 DFS 复跑得到 32 个候选解，其中唯一有语义的 24 字符明文为 th1s_3ncryt_is_s0_e@sy!1（末尾分组为非打印字节），与原文输出一致。已修正原卡'只有一组合法明文'为'多解中按可打印性与语义筛出唯一有意义明文'。PoC 未在题目二进制上复现（未取得样题）。dedup：与同类 MD5 爆破/字节变换卡非同链；dup-scan 无 pair。
url: /docs/ctf/reverse/ctf-reverse-md5-prefix-crack-byte-permute-xor-dfs/
draft: false
kb_aliases:
- HNCTF 2022 findit
- HN_CTF 爆破
- 字节置换 XOR key
- 链式 XOR 多解 DFS
- v21 递推逆推
---

## 一句话结论

题目的 key 校验是“输入前 6 字符的 MD5 == `32cbe93f1dd4f2f3be1c85983d6994c1`”，爆破得 `HN_CTF`；flag 校验由两段可逆变换组成——先把 32 字节按 4 字节分组用 key 字符异或并置换字节序，再对每个字节做 `v[i] ^= (i+18) ^ ((v[i]+12)%24) ^ v[i+1]` 的链式异或；由于链式逆推每字节可能多解，需要从已知尾部向前 DFS，再对每个候选分组用 key 解置换，最终得到 `th1s_3ncryt_is_s0_e@sy!1`。

## 原理

- **第一段：MD5 短口令爆破**：程序把输入前 6 字节送 MD5，与内存常量 `32cbe93f1dd4f2f3be1c85983d6994c1` 比较；6 位可打印字符空间可控，字典/掩码爆破得到 `HN_CTF`。
- **第二段：4 字节分组置换异或**：`do_something` 先把输入补齐到 4 的倍数（补 `Q`），然后按 4 字节块处理，key 为 `HN_CTF` 按 `i%6` 取字符；输出块的 4 个字节是原块字节按 `[3,0,2,1]` 顺序分别与 key 字符异或（由反汇编 `BYTE1/HIBYTE/中字节/低字节` 的写入顺序可确认）。逆运算：对每个候选块用同一 key 异或并还原顺序。
- **第三段：链式 XOR 递推**：`for (i=0; i<31; ++i) v21[i] ^= (i + 18) ^ ((v21[i] + 12) % 24) ^ v21[i+1];`。它把第 i 字节与下一字节、下标常量、`(v[i]+12)%24` 耦合；正向不可直接反解，但已知 `v21[31]`（以及长度 32）时可以逐字节向前枚举。
- **多解与 DFS**：给定 `v[i+1]` 和目标值 `enc[i]`，方程 `enc[i] = (i+18) ^ ((x+12)%24) ^ x ^ v[i+1]` 对 x（0..255）可能有多个解；从末尾向前 DFS 到 0，每个完整解再经过 4 字节置换异或解密，多解中按可打印性与语义筛出唯一有意义明文（`th1s_3ncryt_is_s0_e@sy!1`）。
- **边界**：若分组长度/补齐字符、key 长度、递推常量与顺序不同，需按反汇编调整；多解时用明文可打印性/flag 格式剪枝。

## 触发条件

- CTF 逆向题中存在短输入 MD5 比较（可爆破）与自定义逐字节/分组变换。
- 变换链可写成一维递推，且初值/末值已知或有界。
- 解密结果可打印或符合 flag 格式，用于筛掉多解分支。

## 利用步骤

1. 定位 MD5 常量与比较，确认比较的是输入前 6 字节；爆破/字典得到 `HN_CTF`。
2. 阅读 `do_something`：确认补齐规则、4 字节块、key 索引与字节置换顺序。
3. 逆置换：对每块 `out = [in3, in0, in2, in1] ^ key`，得到变换后的 32 字节。
4. 实现链式递推逆推 DFS：从 `v[31]` 已知值开始，对 `i=30..0` 枚举满足 `enc[i] == (i+18) ^ ((x+12)%24) ^ x ^ v[i+1]` 的 x。
5. 对每个完整 32 字节候选跑第 3 步解密，按可打印/flag 格式筛选，得到 `NSSCTF{th1s_3ncryt_is_s0_e@sy!1}`。

## PoC

```python
mid = [32,59,121,60,125,45,32,17,38,0,43,45,48,48,28,42,11,20,49,100,63,119,103,53,173,46,136,158,49,78,78,176]
enc = [29,70,92,84,87,19,61,43,62,60,29,9,18,63,6,6,42,14,124,110,109,60,105,191,7,162,64,104,92,61,223,179]
key = [ord(c) for c in 'HN_CTF']
flag = [0] * 32
flag[31], flag[30] = 179, 223

def decrypt(arr):
    for i in range(len(arr) // 4):
        t = arr[4*i:4*i+4]
        st = ''.join(chr(t[k] ^ key[i % 6]) for k in (3, 0, 2, 1))
        print(st, end='')

def dfs(deep):
    if deep == 0:
        decrypt(flag); return
    for x in range(0x100):
        if enc[deep-1] == (0x12 + deep - 1) ^ ((x + 12) % 24) ^ x ^ flag[deep]:
            flag[deep-1] = x
            dfs(deep - 1)

dfs(31)  # th1s_3ncryt_is_s0_e@sy!1
```

## 变体与关联

- 变体：链式异或可直接正向加密、逆推用 Z3 约束求解（不必手写 DFS）。
- 变体：4 字节置换可换成列转置/表驱动 S 盒，逆向时按表反查。
- 关联：[[ctf-reverse-md5-digest-even-xor1-birthday-crack]]（MD5 短口令爆破 + 位级变换还原）、[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（Hash 识别与爆破总览）、[[ctf-reverse-pe-driver-4byte-xor-repair-chained-xor-z3]]（链式 XOR 的 Z3 逆推）。

## 检测与防御

- CTF/开发视角：客户端校验不要依赖 MD5 短口令；字节变换不是安全边界，密钥会随程序泄露。
- 逆向视角：先在纸上/脚本里写出正向公式，再机械求逆；多解时用已知明文格式剪枝。
