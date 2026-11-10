---
id: crypto-side-channel-sage-is-prime-timing-oracle-crt
title: Sage is_prime 计时侧信道：用小于 103 的小素因子快速失败分支做“整除预言机”，CRT 恢复明文
type: scenario
domain: crypto
path: crypto/side-channel
technique: sage-isprime-timing-small-factor-oracle-crt
tags:
- crypto
- side-channel
- timing-attack
- sage
- pari
- bpsw
- primality-test
- crt
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T09:20:19+08:00'
  notes: 已对照原文核对：图03 实测 101*prime 0.51s vs 103*prime 2.71s（含 <103 小因子被 BPSW_psp 预检短路），图01 的 0.12/0.12/0.15s 对应 Sage 层奇偶+小素数表分支，图02 proof.arithmetic()=True 说明大数确实走 APR-CL/ECPP，卡内 BPSW_psp/BPSW_isprime 源码引用与原文一致。未验证点：原文只给出 oracle 标定与完整 exp（本地 process 起 server.sage，FLAG 为 flag{12345oo8901}），没有任何一次实际恢复 flag 的输出截图，故 CRT 合模与 2^10 枚举这一步属未复现；exp 中 0.001/0.005s 阈值在远程网络下是否成立原文亦未讨论。
url: /docs/crypto/side-channel/crypto-side-channel-sage-is-prime-timing-oracle-crt/
draft: false
kb_aliases:
- is_prime 计时侧信道
- 小素因子整除预言机
- Sage 素性测试侧信道
- BPSW 小因子快速返回
- 素性测试时间差恢复 flag
- 侧信道 + CRT 恢复明文
---

## 一句话结论

Sage `is_prime()` 对「有小于 103 的小素因子的合数」会在 BPSW 的互素预检阶段立即返回 0，对没有小因子的数才进入昂贵的 APR-CL/ECCP 证明，于是函数的**运行时间**成了一个「n 是否能被 p<103 整除」的预言机；若服务端允许攻击者在明文高位上叠加可控整数并返回素性测试耗时，就能对每个小素数 p 求出明文模 p 的剩余类，CRT 拼出明文模 ∏p（约 2^126），再枚举少量候选即可还原完整明文。

## 原理

- **时间差从哪来**：PARI 的 `isprime()` 是 `BPSW_psp(N) && BPSW_isprime(N)`。`BPSW_psp` 在 64 位平台上先用两个「小素数乘积」与 N 求 gcd（乘积覆盖 3–53 与 59–101），只要有任一小于 103 的素因子就立刻返回 0；只有通过这一步才会进入 `isprimeAPRCL`/`isprimeECPP` 这类真正耗时的素性证明。原文实测：`101*prime` 跑 100 万次用 0.51 s，`103*prime` 用 2.71 s——同一量级的数，差 5 倍。
- **更浅的一层时间差**：对能装进 `unsigned long` 的数，Sage 先判奇偶，再查小于 1000 的素数表（`_small_primes_table`），之后才交给 PARI。这条路径的差异更小（原文 100 万次 0.12 s vs 0.15 s），实际利用价值低，主要用来说明「实现分层导致时间可区分」。
- **为什么能变成「整除预言机」**：给定未知明文整数 $f$，攻击者能构造 $n = f + x$（题目把可控输入限制在明文之上的高位，异或等价于加法）。若取 $x = k\cdot p$ 的某个等价形式，则 $n \bmod p = (f + x) \bmod p$ 只由 $x$ 的剩余类决定；对 $p$ 的每个剩余类各测一次耗时，「快」的那个类就满足 $f \equiv -x \pmod p$。逐个 $p$ 求出剩余类，就得到 $f$ 的一组同余方程。
- **为什么要放大**：单次 `is_prime` 的时间差只有微秒级，网络抖动完全淹没。题目每次查询执行 $7^7 = 823543$ 次 `is_prime`，把微秒差累加成可观测的秒级差，这是把侧信道从「本地」搬到「远程」的关键。
- **为什么要防「假快」**：并非只有含小因子的数才快——有些数在 BPSW 早期就被排除。因此每个候选要重复测多次，并把测试点错开到 $x + i\cdot p\cdot p'$（保持模 $p$ 的剩余类不变、改变数值本身），只有「稳定地快」才判定为该剩余类，否则剔除。
- **CRT 与枚举**：把 25 个小素数（3–101，去掉 2）的剩余类用 CRT 合并，模数 $P=\prod p \approx 1.16\times10^{38}$（约 $2^{126}$）。若明文长度约 136 bit，则候选只有 $2^{136}/P \approx 2^{10}$ 个，逐个按格式（如 `flag{...}`）筛选即可定位。
- **为什么成立**：密码实现的安全性通常假设「算法正确性」与「执行时间」无关；一旦素性测试在小因子上短路，时间就泄露了「这个数有没有小因子」这一比特级信息，而明文高位可控又让攻击者能对任意模数逐位提问——这是典型的「实现分层 + 可控输入」组合成的预言机。

## 触发条件

- 目标把用户可控整数与秘密做加法/异或（且可控部分在秘密之上，异或退化为加法），并把结果送进 `is_prime()` 之类的素性测试。
- 每次查询会对该结果做**大量**重复素性测试（原文 $7^7$ 次），使时间差可被远程观测；查询次数足够（每个剩余类数十次）。
- 素性测试实现存在「有小因子则快速返回」的分支（PARI/Sage 的 BPSW 预检即是），且未做常数时间化处理。
- 秘密的长度与已知前缀/格式（如 `flag{` + 固定字符集）允许在 CRT 结果上做小范围枚举。
- 网络抖动可控：本地或低延迟环境最佳，远程需要足够大的放大倍数与统计判别。

## 利用步骤

1. 读被测实现的素性测试源码，确认「小因子快速失败」分支及其覆盖的素数范围（此处为 <103）与阈值。
2. 本地标定：分别测「含小因子」与「不含小因子」的样本耗时，确定判别阈值（原文用 0.005 s / 0.001 s 两级阈值）。
3. 构造可控高位基数 `base = 2^(len(flag)*8+1)`，使 `flag ^ x = flag + x`，并为每个小素数 $p$ 预计算一组「只影响模 p 剩余类、且落在允许输入空间内」的乘子。
4. 先找一个能让响应时间明显变长的 `additional_num`（确认基数构造正确、能命中非快速分支）。
5. 对每个 $p$：枚举剩余类 $r=0..p-1$，对每个候选重复测量；把测试点错开到 `x + i*p*p'` 以排除偶发快速返回，保留唯一「稳定不快」的类，换算成 $f \bmod p$。
6. 用 CRT 合并所有同余式，得到 $f \bmod P$。
7. 在 $[0, 2^{bit})$ 内以步长 $P$ 枚举候选，按明文格式筛选，得到完整明文。

## PoC

```python
# 计时预言机（本地/远程同构）：n 是否“没有小于 103 的素因子”
import time
def slow_probe(n, rounds=7**7, thr=0.005):
    t = time.time()
    for _ in range(rounds):
        is_prime(n)          # sage.all.is_prime
    return (time.time() - t) > thr   # True = 走完 APR-CL/ECCP，说明无小因子

# 对素数 p 求 flag mod p：找出唯一“稳定快”的剩余类
def flag_mod_p(p, base, probes=40):
    cands = list(range(p))
    for r in cands:
        x = base * r
        # 错开到同余类不变、数值不同的点，排除偶发快速返回
        fast = all(not slow_probe(x + i * p * base) for i in range(3))
        if fast:
            return (-x) % p
    raise RuntimeError("need more probes / adjust threshold")

primes = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101]
mods = [flag_mod_p(p, base) for p in primes]
f_mod_P = crt(mods, primes)          # P = prod(primes) ≈ 2^126
# 枚举 P 的倍数，按格式筛选
x = f_mod_P
while x < 2**136:
    if long_to_bytes(x).startswith(b"flag{"):
        print(long_to_bytes(x)); break
    x += prod(primes)
```

说明：`base`、阈值、重复次数需按目标每次查询的放大倍数与网络延迟标定；原文 exp 用 `additional_num` 与 `primes_le_103_1` 乘子把候选限制在允许的输入空间内，本卡只保留可迁移的骨架。

## 变体与关联

- 变体：素性测试换成任何「先做小因子试除、再做重活」的实现（OpenSSL `BN_is_prime`、GMP `mpz_probab_prime_p`、部分 Java `BigInteger.isProbablePrime` 在特定路径上都有分层），时间差同样可观测。
- 变体：不只是素性测试，任何「按秘密值提前返回」的分支（字符串比较、Base64 解码失败、padding 校验、签名验证的短路）都能构成同类的计时预言机，只是可提取的信息从「模 p 剩余类」变成「前缀是否匹配」。
- 变体：若可控输入不限于高位，可直接对 $f+x$ 做更灵活的构造；若只能异或低位，则需要先恢复低位再逐段推进。
- 关联：[[crypto-side-channel-aes-cpa-hamming-weight]]、[[crypto-side-channel-whitebox-aes-dfa-round8-fault]]（同属「实现层泄露」而非算法数学缺陷）。
- 边界：每次查询只做一次素性测试时微秒差无法远程观测；服务端加入随机延迟、常数时间实现、或对查询频率限流，都会让攻击失败。原文为 CTF 题解，未给出远程实测数据，confidence 取 medium。

## 检测与防御

- 检测：同一会话对同一接口高频提交结构相似的大整数（高位固定、低位变化）；响应时间呈双峰分布且与输入的同余类相关；单次请求 CPU 时间异常长（大量素性测试）。
- 防御：素性测试改为常数时间或固定开销（先做固定轮数的 Miller-Rabin，无论结果如何都跑满）；不要在秘密参与的值上暴露「提前返回」分支；对单次请求的重复次数与总时长做上限和抖动。
- 加固：不要在「秘密 + 用户输入」的表达式上调用带数据相关分支的库函数；服务端对相同来源做速率限制与响应时间归一化；对密码学接口做远程计时审计（黑盒测量同一操作在不同输入下的方差）。
