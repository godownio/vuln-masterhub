# RSA

## 这层是什么

共模、低指数、广播、Wiener、填充与实现缺陷。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AMM（Adleman-Manders-Miller）在模 p 下开 e 次方根：e^t·s 分解迭代、单位根枚举与 CRT 组合](crypto-rsa-amm-nth-root-mod-p-unit-roots-crt.md) | verified | high | 2026-11-09 |
| [Bleichenbacher PKCS#1 v1.5 填充预言机：反复查询逐位恢复 RSA 明文](crypto-rsa-bleichenbacher-pkcs1v15-padding-oracle.md) | verified | medium | 2026-11-06 |
| [Boneh-Durfee 攻击：d < n^0.292 时用格基约减恢复 RSA 小私钥](crypto-rsa-boneh-durfee-small-private-exponent.md) | verified | high | 2026-11-06 |
| [Coppersmith p 高位攻击不满足界：按 unknown/p_bits≈0.44 判界，爆破邻近 8-10 位并下调 epsilon=0.015 强行求解](crypto-rsa-high-bits-insufficient-brute-epsilon-tuning.md) | verified | high | 2026-11-11 |
| [Desmedt-Odlyzko 签名伪造：用签名预言机线性组合伪造目标消息的 RSA 签名](crypto-rsa-desmedt-odlyzko-signature-forgery.md) | verified | medium | 2026-11-06 |
| [dp 与 dq 同时泄露：m1=c^dp mod p、m2=c^dq mod q 后用 CRT 重组明文，不需要 e 与私钥 d](crypto-rsa-dp-dq-both-leak-crt-recombine-without-e.md) | verified | medium | 2026-11-08 |
| [dp 高位泄露（hint = dp>>180）：二元 Coppersmith 求低位与 k 后分解 n](crypto-rsa-dp-high-bits-bivariate-coppersmith.md) | verified | high | 2026-11-08 |
| [dq 低位泄露 + qinvp：用 qinvp·q²−q≡0 mod n 构造一元多项式，枚举 k 恢复 dq 并分解 n](crypto-rsa-dq-low-bits-qinvp-univariate-coppersmith.md) | verified | high | 2026-11-11 |
| [Dual RSA 共模多模数：构造格同时求解小私钥 d 与各模数 φ](crypto-rsa-dual-rsa-lattice-small-d.md) | verified | medium | 2026-11-06 |
| [e 与 φ(n) 不互素：用 e/t 的模逆解得 m^t 再开 t 次方根，单条密文即可恢复明文](crypto-rsa-e-not-coprime-phi-reduced-inverse-root.md) | verified | medium | 2026-11-08 |
| [Franklin-Reiter 相关明文攻击：同一模数下仿射相关明文的 RSA 多项式 GCD](crypto-rsa-franklin-reiter-affine-related-message.md) | verified | high | 2026-11-06 |
| [funny_rsa：用两组乘积表达式 gcd 恢复 n，再对 p+q+rand(−1025,+1025) 枚举扰动解二次方程分解 n](crypto-rsa-funny-gcd-recover-n-sum-with-random-perturbation-brute.md) | verified | high | 2026-11-07 |
| [hint = n + noise·(p+q+noise) 的小噪声泄露：分解 hint-n 恢复 p+q 并解二次方程](crypto-rsa-noise-hint-p-plus-q-factorization.md) | verified | high | 2026-11-08 |
| [LCG 状态与 RSA 幂泄露：power sums/Newton identities 恢复 d + Franklin-Reiter 恢复 x1](crypto-rsa-lcg-exponent-leak-power-sums-franklin-reiter.md) | verified | high | 2026-11-06 |
| [Manger RSA-OAEP 首字节零预言机：三步区间压缩恢复明文](crypto-rsa-manger-oaep-first-byte-oracle.md) | verified | high | 2026-11-06 |
| [Pell 方程生成 RSA 素数：x²-2y²=1 的解空间把 p、q 退化成 N 的唯一函数](crypto-rsa-pell-equation-prime-generation.md) | verified | high | 2026-11-05 |
| [Rabin 加密 e=2 解密：已知 p/q 用 (p+1)/4 或 Tonelli-Shanks 求模平方根，CRT 组合四个根并按明文筛选](crypto-rsa-rabin-e2-four-roots-crt-shanks.md) | verified | high | 2026-11-12 |
| [Rabin 随机平方根预言机：两次 sqrt(a²) 查询用 gcd(a-y,N) 分解 1023 位模数](crypto-rsa-rabin-random-square-root-oracle.md) | verified | high | 2026-11-05 |
| [RSA dp 泄露：e·dp−1 为 p−1 的倍数，枚举小 k 分解 n 并恢复私钥解密](crypto-rsa-dp-leak-enumerate-k-factorization.md) | verified | high | 2026-11-07 |
| [RSA e=3 已知前后缀：中间 32 字节未知的 Coppersmith 小根恢复](crypto-rsa-e3-known-prefix-suffix-coppersmith.md) | verified | high | 2026-11-06 |
| [RSA e=3 明文过短：密文未模约减时直接整数立方根恢复](crypto-rsa-e3-small-plaintext-integer-cube-root.md) | verified | high | 2026-11-06 |
| [RSA hint 值差值 GCD 分解：多组提示同余于同一素因子时直接取公因子](crypto-rsa-hint-difference-gcd-factorization.md) | verified | medium | 2026-11-06 |
| [RSA LSB 奇偶预言机：乘 2^e 查询 m mod 2 二分恢复明文](crypto-rsa-lsb-parity-oracle.md) | verified | high | 2026-11-06 |
| [RSA n=p·q² 的二项式提示分解 + 二次剩余逐位还原（(p±q)^e 与欧拉判别式）](crypto-rsa-binomial-hints-pq-squared-quadratic-residue-bits.md) | verified | high | 2026-11-11 |
| [RSA next_prime 近邻素数：费马分解用平方差快速分解 N](crypto-rsa-fermat-close-prime-factorization.md) | verified | high | 2026-11-05 |
| [RSA p+1 光滑：Williams p+1 用 Lucas 序列分解 p+1 光滑素数](crypto-rsa-williams-p-plus-1-smooth-factor.md) | verified | high | 2026-11-06 |
| [RSA Pell 方程 hint 攻击：已知 x·p+y·q 且 x²-D·y²=1，用韦达定理求 xp/yq 后连分数解 Pell 还原 p、q](crypto-rsa-pell-hint-linear-combination-factorization.md) | verified | high | 2026-11-12 |
| [RSA Wiener 攻击：公开指数 e 异常大、私钥 d 过小，连分数收敛恢复 d](crypto-rsa-wiener-small-private-exponent-large-e.md) | verified | high | 2026-11-06 |
| [RSA 三素数 + 威尔逊定理：p=nextprime((B!)%A)，用 (A−1)!≡−1 mod A 反推 B! 后分解 n](ctf-crypto-rsa-wilson-factorial-mod-prime-nextprime.md) | verified | high | 2026-11-11 |
| [RSA 两个线性 hint 都是 p、q 的小系数组合：枚举 ≤211 的系数让一边系数抵消，差值即素因子倍数，gcd 直接分解 n](crypto-rsa-two-linear-hints-small-coefficient-gcd.md) | verified | medium | 2026-11-08 |
| [RSA 低位非线性泄漏 bit-lifting：逐位枚举 p/q 使 N 与 leak 的低位同时一致](crypto-rsa-low-bit-nonlinear-leak-bitlifting.md) | verified | high | 2026-11-06 |
| [RSA 共享素数 + 已知明密文对恢复小 e：gcd(n1,n2) 分解后遍历 e 匹配 pow(294,e,n)](ctf-crypto-rsa-known-pair-recover-e-shared-prime.md) | verified | high | 2026-11-11 |
| [RSA 共模攻击](common-modulus.md) | draft | high | 2026-11-04 |
| [RSA 十进制逆序 nextprime 素数：低/高位泄露与两端逐位剪枝分解](crypto-rsa-decimal-reversal-nextprime-two-end-pruning.md) | verified | high | 2026-11-11 |
| [RSA 只给 e,d,c：ed−1=k(p−1)(q−1) 按位数差缩小 k 枚举，iroot + prevprime/nextprime 恢复相邻素数](ctf-crypto-rsa-ed-minus-one-bitlength-k-prevprime.md) | verified | high | 2026-11-11 |
| [RSA 复合模数 P=m^p mod n、Q=m^q mod n 泄露 dp：枚举 k 分解 N，再用二次多项式 Coppersmith 还原 m](crypto-rsa-dp-leak-composite-modulus-power-coppersmith.md) | verified | high | 2026-11-07 |
| [RSA 多段密文（RSAROLL）：同一个 n 下一列 c 逐段解密，按序拼接还原 flag](ctf-crypto-rsa-roll-multi-ciphertext-concat.md) | verified | high | 2026-11-11 |
| [RSA 大 e 小 d 变体：连分数枚举 e·g/n 恢复 λ(n) 并用平方根法分解 N](crypto-rsa-continued-fraction-lambda-factorization.md) | verified | high | 2026-11-06 |
| [RSA 小参数古典题：n=2537/e=13/d=937 解出 0–25 索引后映射字母表得 flag](ctf-crypto-rsa-small-n-alphabet-index.md) | verified | high | 2026-11-11 |
| [RSA 小指数 e=19 多轮加密 + 相邻素数模数：GF(p)/GF(q) 求根、CRT 组合并按位长回溯（初始 1 轮 + 重复 25 轮，共 26 个模数）](crypto-rsa-small-exponent-multiround-close-prime-crt-backtrack.md) | verified | high | 2026-11-07 |
| [RSA 小明文多项式泄露：c=m³+a2m²+a1m+a0 的高精度求根与低 16 位爆破](crypto-rsa-small-message-polynomial-root.md) | verified | high | 2026-11-06 |
| [RSA 小私钥 + d 的小素数 CRT 残差：构造 (k1,1,k2) 格恢复 d](crypto-rsa-crt-hints-small-d-lattice-wiener-like.md) | verified | medium | 2026-11-07 |
| [RSA 已知 m^e 与 m^(p+q)：扩展欧几里得线性组合直接恢复明文](crypto-rsa-m-e-and-m-p-plus-q-linear-combination.md) | verified | high | 2026-11-06 |
| [RSA 广播攻击变种：仿射变换 (a·m+b)^3 与 CRT 合并多项式求小根](crypto-rsa-affine-broadcast-crt-coppersmith.md) | verified | high | 2026-11-06 |
| [RSA 指数 e 隐藏在素数计数中：埃氏筛求 π(N)−1 恢复 e，再分解近邻素数 n](crypto-rsa-hidden-e-prime-counting-close-prime.md) | verified | high | 2026-11-08 |
| [RSA 明文高位泄露：Coppersmith 一元小根恢复 m 的未知低位](crypto-rsa-partial-plaintext-high-bits-coppersmith.md) | verified | high | 2026-11-06 |
| [RSA 有理泄漏 (3p²−1)/(3pq)：由 p/q 近似开方恢复 p、q 并用给定 d 解密](crypto-rsa-rational-leak-p-over-q-recover.md) | verified | high | 2026-11-06 |
| [RSA 模数为完全平方 p²：φ=p(p−1) 直接求 d 并解密](crypto-rsa-perfect-square-modulus-p-squared.md) | verified | high | 2026-11-06 |
| [RSA 模数只有约 128 位：直接用 factordb/sympy 分解 n 求 d，textbook 解密恢复口令（常见于流量包里泄露的 n/e/c）](crypto-rsa-tiny-modulus-128bit-direct-factorization.md) | verified | high | 2026-11-08 |
| [RSA 模数本身是素数时 φ(n)=n-1 直接求 d 解密](crypto-rsa-prime-modulus-phi-n-minus-1.md) | verified | high | 2026-11-08 |
| [RSA 泄露 p²+q²：Cornacchia 两平方和表示直接恢复 p、q 并解密](crypto-rsa-known-p2-plus-q2-cornacchia-factor.md) | verified | high | 2026-11-08 |
| [RSA 私钥 d 低 530 位泄露：枚举 k 与 d 高位，用 s²−4n 完全平方直接分解 n](crypto-rsa-d-low-bits-k-enumeration-perfect-square.md) | verified | high | 2026-11-07 |
| [RSA 私钥 d 低位泄露：solve_mod 求 p 低位候选后 Coppersmith 恢复 p](crypto-rsa-private-exponent-low-bits-partial-p.md) | verified | high | 2026-11-06 |
| [RSA 私钥 d 泄露后只换 e 不换 n：e·d−1 概率分解 N 并解新密文](crypto-rsa-d-leak-factor-n-reuse-modulus-new-e.md) | verified | high | 2026-11-06 |
| [RSA 素数 p-1 光滑：Pollard p-1 在 B=100000 内用 gcd(2^L-1,N) 取因子](crypto-rsa-pollard-pminus1-smooth-prime.md) | verified | high | 2026-11-05 |
| [RSA 素数比特分段残缺：一元/二元/三元 Coppersmith 按未知块数分档求解](crypto-rsa-prime-bit-chunks-multivariate-coppersmith-tiered.md) | verified | medium | 2026-11-08 |
| [RSA 解密值 m>n：用已知 flag 前缀/后缀限定商 k，枚举 n 的倍数恢复真实明文](crypto-rsa-m-greater-than-n-known-prefix-quotient-enumeration.md) | verified | high | 2026-11-08 |
| [RSA 连续素数链模数：n 为 17 个相邻素数之积，已知链中一个素数用 prevprime/nextprime 双向还原](crypto-rsa-consecutive-prime-chain-nextprime-product.md) | verified | high | 2026-11-11 |
| [RSA 隐藏私钥指数 c 的多项式导数泄露：量级差恢复系数 + 枚举 8-bit k](crypto-rsa-polynomial-derivative-hidden-exponent-enum.md) | verified | high | 2026-11-06 |
| [RSA 高位分片泄漏：多个小模数 CRT 还原 p 高 704 位，Coppersmith 小根恢复低 320 位](crypto-rsa-crt-multi-modulus-high-bits-coppersmith-low-bits.md) | verified | high | 2026-11-06 |
| [Schmidt-Samoa 密码系统：已知 N、c、d 用 gcd(a^{Nd}-a,N) 恢复 pq 并解密](crypto-rsa-schmidt-samoa-known-d-factor.md) | verified | high | 2026-11-06 |
| [textbook RSA + 输出字节反转 + 12 进制稀疏多项式分解](crypto-rsa-textbook-byte-reverse-base12-sparse-factor.md) | verified | high | 2026-11-06 |
| [WKCTF2024 fl@g：排列组合计数生成 p 的 RSA——用容斥公式算 real_n 后 nextprime 解 n](crypto-rsa-permutation-count-nextprime.md) | verified | high | 2026-11-08 |
| [三素数 RSA 高位泄露：Coppersmith 小根 + beta 逐档下调恢复 82 位未知低位](crypto-rsa-multiprime-partial-key-coppersmith.md) | verified | high | 2026-11-05 |
| [二元 Coppersmith 小根：两个未知数联立二次多项式恢复 RSA 明文](crypto-rsa-bivariate-coppersmith-two-small-roots.md) | verified | high | 2026-11-06 |
| [只给 c 与 n 的小明文攻击：对候选指数 e 与 k∈[0,10) 枚举 c+k·n 的完全 e 次方根](crypto-rsa-small-message-unknown-exponent-plus-n-root-brute.md) | verified | medium | 2026-11-08 |
| [合数 CM 分解：Hilbert 类多项式构造 CM 椭圆曲线，除法多项式范数 gcd 取因子](crypto-rsa-cm-factorization-hilbert-class-polynomial.md) | verified | medium | 2026-11-06 |
| [同模数多把 RSA 私钥：Coppersmith 补全缺失 e + HGS 小私钥分解 N](crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d.md) | verified | high | 2026-11-06 |
| [四因子近邻素数模数 n=p·q·p1·q1：从 √n 平方差遍历找两组平衡分解，gcd 还原全部素因子](crypto-rsa-fermat-multiprime-close-pair-gcd.md) | verified | high | 2026-11-12 |
| [多素数 RSA 立方提示 p³ mod n + q=7p+i：直接开立方恢复 p 并分解 n](crypto-rsa-multiprime-cube-hint-linear-prime.md) | verified | high | 2026-11-07 |
| [多组 RSA 公钥共用私钥指数 d：LLL 共私钥指数攻击恢复 d 并分解多素数模数](crypto-rsa-common-private-exponent-multiprime-lattice.md) | verified | high | 2026-11-07 |
| [密文 C ≡ p³q mod N：C·n⁻¹ mod N 退化为 p²，整数开方直接分解 n](crypto-rsa-ciphertext-p-cube-q-near-integer-square-root.md) | verified | high | 2026-11-08 |
| [嵌套 RSA p-1 光滑：用内层 n1 的已知因子作光滑数加速分解外层 n](crypto-rsa-nested-smooth-prime-p1-known-factor.md) | verified | high | 2026-11-06 |
| [已知 e | φ(N) 分解 N=P·Q^r：AMM 求根 + Hensel 提升 + Coppersmith 小根](crypto-rsa-phi-divisor-factoring-multiprime-power.md) | verified | high | 2026-11-06 |
| [已知 N 与 p+q：解二次方程分解 RSA 并模小因子解密](crypto-rsa-known-prime-sum-quadratic-factorization.md) | verified | high | 2026-11-06 |
| [用 crypto-attacks 的 complex_multiplication 轮子做 CM 分解：先按判别式 43 拆出 p，再按 67 递归拆 qr，多素数 RSA 分别取模解密](crypto-rsa-cm-wheel-recursive-multiprime-factorize.md) | verified | low | 2026-11-09 |
| [相邻素数双模数 RSA：n1=p1²q1、n2=next_prime(p1)²q2，连分数恢复 q1 与 p1](crypto-rsa-next-prime-square-moduli-continued-fraction.md) | verified | high | 2026-11-06 |
| [矩阵 RSA 私钥 d 偏小：e 约为 n^4 时以 N=n^4 近似隐藏模数跑 Boneh-Durfee 恢复 d](crypto-rsa-matrix-rsa-hidden-phi-n4-boneh-durfee.md) | verified | low | 2026-11-08 |
| [素数域矩阵 RSA：d=e^{-1} mod (p-1) 对密文矩阵求幂还原明文](crypto-rsa-prime-field-matrix-exponent.md) | verified | medium | 2026-11-08 |
| [结构 RSA e=8：N=P(B−1)²+BS² 参数恢复与三层平方根解密](crypto-rsa-structured-modulus-b-minus-one-square-e8-sqrt.md) | verified | high | 2026-11-06 |
| [结构相似双模数 RSA：N1/N2 连分数恢复小参数后 CRT 求 φ 或近似 d 解密](crypto-rsa-structurally-related-moduli-continued-fraction-crt.md) | verified | high | 2026-11-06 |
| [自定义 pow 包装在指数为奇数时少乘一次，实际指数变成 e-1 且与 phi 不互素：分域开 e 次根再 CRT 组合](crypto-rsa-custom-pow-wrapper-odd-exponent-minus-one-root-crt.md) | verified | medium | 2026-11-08 |
| [自造仿射填充 (a·m + b)^3：已知 flag 前后缀时用 Coppersmith 小根恢复中间未知字节](crypto-rsa-affine-padding-cube-known-prefix-coppersmith.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
