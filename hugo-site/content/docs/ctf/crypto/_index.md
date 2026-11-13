---
title: CTF Crypto
weight: 1
---

# CTF Crypto

## 这层是什么

Crypto 题型技巧。

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
| [3 字节短盐循环 XOR + HMAC-SHA256 截断验证：已知前缀恢复盐](ctf-crypto-short-salt-repeating-xor-hmac-trunc4-verify/) | verified | high | 2026-11-06 |
| [3×3 矩阵群上的离散对数：取行列式把非交换问题降到 F_p*，再 Pohlig-Hellman + CADO-NFS 分解阶并用行列式等式定解](ctf-crypto-matrix-group-dlp-determinant-reduce-pohlig-hellman/) | verified | medium | 2026-11-08 |
| [6 轮 ARX 块密码选择明文差分攻击：x^rot(x,a)^rot(x,b) 可逆迭代 8 次撤销末轮，单比特差分旋转定位 + 进位权重奇偶统计逐位恢复 256 位密钥，尾部 6 位与错位暴力修正](ctf-crypto-arx-xor-rot-invert-differential-carry-weight-key-recovery/) | verified | high | 2026-11-08 |
| [AES S-box 重复/缺失字节侧信道：区分随机块与密文 + z3 解双重 Base64 乱序表](ctf-crypto-aes-sbox-duplicate-missing-byte-random-block-z3-base64/) | verified | high | 2026-11-06 |
| [AES-CBC 自定义前置填充 + key⊕首块 hint：已知 flag{ 前缀爆破单字符恢复 key](ctf-crypto-aes-cbc-prefix-padding-key-xor-hint/) | verified | high | 2026-11-06 |
| [AES-GCM nonce 复用：tag 差分在 GF(2^128) 求根恢复 GHASH 子密钥 H](ctf-crypto-aes-gcm-nonce-reuse-ghash-subkey-root/) | verified | high | 2026-11-06 |
| [AES-GCM tag 低 64 位被 GHASH^MT19937 污染：线性方程恢复 H 与种子](ctf-crypto-aes-gcm-tag-fault-mt19937-linear-recovery/) | verified | medium | 2026-11-06 |
| [Asmuth-Bloom 秘密共享 + RSA 加密 share：CRT 重构 zip 密码](ctf-crypto-asmuth-bloom-rsa-share-crt-recovery/) | verified | high | 2026-11-06 |
| [Base32 自定义字母表识别与解码：从二进制取出 32 字符换表后用 CyberChef From Base32 一键还原](ctf-crypto-base32-custom-alphabet-cyberchef-decode/) | verified | high | 2026-11-11 |
| [Berlekamp-Welch 有理函数插值：从带 30 个噪声点的 98 个样本恢复分子分母](ctf-crypto-berlekamp-welch-rational-function-interpolation/) | verified | high | 2026-11-06 |
| [BSGS/EXBSGS 离散对数求解：把 x=kp−q 拆成大小步用哈希表在 O(√n) 内解 a^x≡c (mod n)，gcd(a,n)≠1 时先约简](ctf-crypto-bsgs-exbsgs-discrete-log-sqrt-n/) | verified | high | 2026-11-09 |
| [C 自实现 AES-ECB 用 int[16] 存 state：sbox 越界索引读 0，解密逆字节代换泄露 key⊕0x52，爆破前 3 字节恢复完整密钥](ctf-crypto-aes-int-state-sbox-oob-key-leak/) | verified | high | 2026-11-08 |
| [CDF 注释藏 Kyber 风格 u/v 块：q/2 偏移编码 bit 恢复 AES key 并解 CBC](ctf-crypto-cdf-comments-qhalf-bit-encoding-aes/) | verified | high | 2026-11-06 |
| [DSA 两次签名的 nonce 满足 k2=k1²：消去私钥得 k1 的二次同余方程，用 Tonelli-Shanks 开方解出私钥](ctf-crypto-dsa-square-related-nonce-quadratic-congruence-key-recovery/) | verified | high | 2026-11-09 |
| [DSA 多次签名 nonce 线性相关：构造 q-对角格 + A_i/B_i 关系，LLL 恢复 k0 后伪造 admin 签名](ctf-crypto-dsa-linear-related-nonce-lattice-k0-forgery/) | verified | medium | 2026-11-08 |
| [ECDH 协商点 x/y 低 211 位泄露：曲线方程构造双变量多项式，Coppersmith 求小根恢复完整坐标](ctf-crypto-ecdh-lowbits-bivariate-coppersmith-flatter/) | verified | medium | 2026-11-10 |
| [ECHNP 椭圆曲线隐藏数问题：多次 x 坐标低位泄露恢复 ECDH 共享密钥（低比特改造 + flatter）](ctf-crypto-ecdh-echnp-multi-lowbit-lattice-flatter/) | verified | medium | 2026-11-10 |
| [Feistel 立方轮函数 GF(2^16) 代数攻击：多项式基秩下降恢复 16-bit 轮密钥](ctf-crypto-feistel-gf2-16-cubic-rank-drop-key-recovery/) | verified | high | 2026-11-06 |
| [GF(3) HFE/UOV 公钥超定方程组：msolve F4 逐块直接求解，无需私钥](ctf-crypto-gf3-hfe-uov-msolve-f4/) | verified | high | 2026-11-06 |
| [GF(3) LFSR 已知明文恢复：前 40 输出取初态，模 3 高斯消元解 mask 并解密](ctf-crypto-gf3-lfsr-known-plaintext-state-mask-recovery/) | verified | high | 2026-11-07 |
| [GF(41) 拉格朗日插值还原替换表：已知前缀定多项式 + 反查候选 + SHA-256 约束穷举](ctf-crypto-gf41-lagrange-substitution-inverse-hash-brute/) | verified | high | 2026-11-07 |
| [Hidden Number Problem（HNP）MSB 泄露：pI 与 t 行构造格，Babai 最近平面恢复 α](ctf-crypto-hnp-msb-oracle-babai-nearest-plane/) | verified | high | 2026-11-06 |
| [HNP-2H 连分数降维 + Kannan Embedding：双小未知量模方程恢复大 secret](ctf-crypto-hnp-2h-continued-fraction-kannan-embedding/) | verified | medium | 2026-11-06 |
| [LFSR B-M 算法：仅 504 位连续输出、爆破缺失 8 位后建 256×256 GF(2) 方程恢复 mask 与 KEY](ctf-crypto-lfsr-bm-missing-bits-mask-recovery/) | verified | medium | 2026-11-07 |
| [LFSR 抽头 mask 恢复：initState 与 outputState 前 128 位建 GF(2) 方程](ctf-crypto-lfsr-mask-recovery-output-state/) | verified | medium | 2026-11-06 |
| [LFSR 流密码已知明文恢复：64 比特帧头建立 GF(2) 方程组解初始状态](ctf-crypto-lfsr-known-plaintext-state-recovery/) | verified | medium | 2026-11-06 |
| [LLL 恢复小系数多项式：偏移 B 构造短向量，8 组精确求值还原后 SHA-256 派生 AES-CTR key](ctf-crypto-lll-polynomial-small-coeff-evaluation-recovery/) | verified | medium | 2026-11-06 |
| [LLL 恢复打乱基中的短向量 + Kannan embedding 解小误差 LWE](ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe/) | verified | high | 2026-11-06 |
| [LLL 恢复高精度 sin 背后的整数角：m=arcsin(c)+2kπ 构造三维格，2^320 配平后约出明文整数 m](ctf-crypto-lll-sin-high-precision-angle-recovery/) | verified | medium | 2026-11-09 |
| [LLL 解三角函数整数关系：高精度 sin/cos 与密文构造格恢复小系数 a,b](ctf-crypto-lll-trig-integer-relation/) | verified | high | 2026-11-06 |
| [MT19937 位流状态恢复：中文位才消耗 bit 的错位修正与 getrandbits(50000) 预测](ctf-crypto-mt19937-bitstream-chinese-alignment-state-recovery/) | verified | high | 2026-11-06 |
| [MT19937 截断输出 GF(2) 线性恢复：624×19968 状态矩阵、6 维零空间枚举与 shuffle 逆置换](ctf-crypto-mt19937-truncated-output-gf2-linear-recovery/) | verified | medium | 2026-11-07 |
| [Noise CRT：带噪 CRT 余数用 Pi·inv(Pi) 系数与 2^nbits 对角构造格恢复 N](ctf-crypto-noise-crt-lattice-recovery/) | verified | medium | 2026-11-06 |
| [NTRU 样本模 x+1 投影 LLL 区分：恢复 coin 位后预测 MT19937 解 AES](ctf-crypto-ntru-xplus1-lll-distinguish-mt/) | verified | medium | 2026-11-07 |
| [NTRU 格攻击：构造 [[1,h],[0,p]] 用 LLL 恢复私钥 (f,g) 并解密密文](ctf-crypto-ntru-lattice-lll-private-key-recovery/) | verified | high | 2026-11-09 |
| [Paillier CTF 解密（g=n+1）：分解 n 后用 n 在 φ(n) 上的模逆恢复随机数 r，再按 n 整除取出明文 m](ctf-crypto-paillier-gn1-recover-r-divide-n-decrypt/) | verified | medium | 2026-11-11 |
| [RLWE 挑战：泄露私钥 s 后用 c0+s·c1 解出 delta·m，模 delta 与负噪声修正恢复明文](ctf-crypto-rlwe-leaked-secret-decrypt-delta-noise-correction/) | verified | high | 2026-11-11 |
| [RSA 密文与模数不互素：gcd(N, c) 直接分解模数并解出 AES key](ctf-crypto-rsa-ciphertext-gcd-factor-leak/) | verified | medium | 2026-11-07 |
| [RSA 小指数广播攻击：三组 e=3 同明文 CRT 合成后开立方](ctf-crypto-rsa-hastad-broadcast-e3-crt/) | verified | high | 2026-11-06 |
| [RSA 未知指数 e：小范围暴力解密 + 明文字符集筛选 + 栅栏还原](ctf-crypto-rsa-unknown-e-rail-fence-filter/) | verified | high | 2026-11-07 |
| [RSA 结构化素数 p=(D·V²+1)/4：Jacobi 选判别式后用二次型/类群分解 n](ctf-crypto-rsa-structured-prime-class-group-factor/) | verified | medium | 2026-11-07 |
| [RSA 非互素指数共模攻击：gcdext 得 m^g 后加 n 开 g 次根恢复明文](ctf-crypto-rsa-noncoprime-common-modulus-iroot-wiener-chain/) | verified | high | 2026-11-07 |
| [Semi-ADFGX 5×6 Polybius 方阵 + 爬山/模拟退火替换还原英文贺词](ctf-crypto-semi-adfgx-5x6-polybius-hillclimb-substitution/) | verified | high | 2026-11-06 |
| [Simon 型周期测量恢复隐藏周期：GF(2) 零空间求 80 bit 周期](ctf-crypto-simon-period-measurement-gf2-nullspace/) | verified | high | 2026-11-06 |
| [SM3 链式单次签名伪造：按步长数组逐段收集其他消息的签名拼接目标签名](ctf-crypto-sm3-chain-ots-step-collision-forgery/) | verified | high | 2026-11-07 |
| [UDS 0x27 SecurityAccess 弱 seed-key 算法逆推：XOR/ROL/ADD 从 seed 计算 key](ctf-crypto-uds-securityaccess-seed-key-recovery/) | verified | high | 2026-11-06 |
| [Wagner 广义生日求 SHA3-512 模素数 k-sum：8 路合并构造哈希碰撞过服务端校验](ctf-crypto-wagner-generalized-birthday-sha3-mod-collision/) | verified | medium | 2026-11-07 |
| [Z3 求解 6 字节输入的 128 位状态约束：模乘异或链的逆问题](ctf-crypto-z3-short-input-128bit-state-constraint/) | verified | high | 2026-11-06 |
| [两次维吉尼亚加密同一明文：差分周期恢复密钥流并解 flag](ctf-crypto-vigenere-two-ciphertext-differential-period/) | verified | high | 2026-11-06 |
| [乱序超递增私钥背包：升序排序恢复超递增结构贪心求解，再按原下标把 0/1 位写回打乱前的顺序](ctf-crypto-shuffled-superincreasing-knapsack-reorder-decrypt/) | draft | high | 2026-11-10 |
| [二维格解线性同余双小未知量：[[1,A],[0,M]] 约出 (x,y)，余数/偏移未知时再枚举收尾](ctf-crypto-lll-linear-congruence-two-small-unknowns-2d/) | verified | high | 2026-11-09 |
| [光滑阶素数域离散对数：Pohlig-Hellman 逐因子子群求解 + CRT 合并（DH 私钥恢复）](ctf-crypto-pohlig-hellman-smooth-order-prime-dlp/) | verified | high | 2026-11-11 |
| [公钥系数线性组合的 LLL 明文恢复与无校验私钥伪造](ctf-crypto-lll-public-key-linear-combination-forge-private-key/) | verified | medium | 2026-11-07 |
| [六组模数两两共享素因子 + 同一明文被同一指数连乘两层：gcd 分解后必须按「后加密的先解」逆序解密（先 d_2 再 d_1）才能还原](ctf-crypto-rsa-shared-prime-double-encryption-reverse-order/) | verified | high | 2026-11-09 |
| [半直积群小阶共轭元：枚举 c 的阶后用 BSGS 解离散对数](ctf-crypto-semidirect-product-small-order-discrete-log/) | verified | high | 2026-11-06 |
| [单字节种子递推流密码：已知明文前缀爆破 256 个种子](ctf-crypto-single-byte-seed-recurrence-stream-cipher-bruteforce/) | verified | high | 2026-11-06 |
| [可调 AES 后门：构造 tweak 使每轮轮 tweak 抵消轮常数，单次选择明文恢复主密钥](ctf-crypto-tweakable-aes-round-constant-cancel-key-recovery/) | verified | medium | 2026-11-10 |
| [四元数环离散对数：范数同态降维到素域后 BSGS，MD5(secret) 派生 AES 密钥](ctf-crypto-quaternion-norm-dlp-bsgs/) | verified | medium | 2026-11-07 |
| [四轮 DES 非标准 S 盒线性密码分析：PL[19]⊕PR[9]⊕CL[9]⊕CR[19] 偏差猜 K4 子密钥恢复主密钥](ctf-crypto-4round-des-custom-sbox-linear-cryptanalysis/) | verified | medium | 2026-11-10 |
| [多元对称方程消元：把 a³+b⁶ 与 ac 表示为 b 的多项式，降为单变量高次方程](ctf-crypto-multivariate-elimination-univariate-polynomial/) | verified | high | 2026-11-06 |
| [多层编码链：Base58 → W 型栅栏（3 栏）→ ROT13](ctf-crypto-base58-wrailfence-rot13/) | verified | high | 2026-11-07 |
| [多底数幂 GCD 消元恢复模数 + discrete_log_lambda 小范围离散对数](ctf-crypto-multibase-power-gcd-modulus-lambda-dlp/) | verified | high | 2026-11-11 |
| [天书 + 与佛论禅双层中文编码：64 符号 base64 变体与 128 字表高位标志，套 CryptoJS EVP_BytesToKey AES](ctf-crypto-tianshu-foshuo-double-layer-cryptojs-evp-bytes-to-key/) | verified | high | 2026-11-06 |
| [字符重复 + AES-ECB 块循环移位异或：已知前缀逐字符唯一推出 flag](ctf-crypto-aes-ecb-duplicated-char-circular-xor/) | verified | high | 2026-11-06 |
| [小模数离散对数 + CRT 枚举真通道：从 18 条投影中恢复隐藏整数 x](ctf-crypto-small-discrete-log-crt-channel-selection/) | verified | high | 2026-11-06 |
| [已知格式前后缀的子集和：CVP 格约减恢复 64 位二进制明文](ctf-crypto-subset-sum-known-prefix-lll-cvp/) | verified | high | 2026-11-08 |
| [已知格式前缀的 SHA1 哈希离线爆破：40 位 SHA1 + 11 位手机号前 3 位，枚举后 8 位数字命中即得完整号码](ctf-crypto-known-format-prefix-sha1-offline-brute/) | verified | high | 2026-11-07 |
| [幂塔模合数：三因子分解 + 欧拉降幂逐素数求值 + CRT 后 XOR 解明文](ctf-crypto-power-tower-composite-modulus-crt/) | verified | high | 2026-11-06 |
| [异或密钥流重用：已知一段明文恢复另一段密文（two-time pad）](ctf-crypto-xor-keystream-reuse-known-plaintext/) | verified | high | 2026-11-06 |
| [批量 RSA 模数两两 gcd：共享素因子直接分解并恢复明文](ctf-crypto-rsa-shared-prime-batch-gcd/) | verified | high | 2026-11-06 |
| [挑战响应认证的 XOR 折叠校验：8 字节比较降为单字节，1/256 概率通过](ctf-crypto-challenge-response-xor-fold-checksum-1in256/) | verified | high | 2026-11-06 |
| [模逆隐藏数：data = t·m⁻¹ mod g，2×2 格配平缩放恢复短 t 与明文 m](ctf-crypto-lll-modular-inverse-small-multiplier/) | verified | high | 2026-11-08 |
| [环卷积线性系统恢复稀疏向量：F_65537[x]/(x^70+1) 上的 NTRU 类方程](ctf-crypto-ring-convolution-linear-system-sparse-vector/) | verified | high | 2026-11-06 |
| [用 Hamming 距离线性约束 + 整数规划恢复 256 位密钥：浮点泄露 + SHA-256 哈希对](ctf-crypto-hamming-distance-linear-program-secret-recovery/) | verified | high | 2026-11-07 |
| [稀疏分组指纹覆盖 + meet-in-the-middle：从 7 组告警恢复 14 列异或路径](ctf-crypto-sparse-group-fingerprint-mitm-xor-path/) | verified | high | 2026-11-06 |
| [稀疏错误线性系统：校验矩阵枚举 4 个错误位置并恢复单项式向量](ctf-crypto-sparse-error-linear-system-nullspace-enumeration/) | verified | high | 2026-11-06 |
| [类 Dilithium 签名缺少误差项：t = A·s 精确线性方程组在 Z_q 上直接解出私钥](ctf-crypto-dilithium-like-exact-t-as-linear-system-secret-recovery/) | verified | high | 2026-11-06 |
| [线性模哈希碰撞：把 Σ(2g)^{i-k}g·e_k≡0 mod N 转成 [E|R;0|N] 格，LLL 求短差分向量](ctf-crypto-linear-hash-collision-lll/) | verified | high | 2026-11-06 |
| [结构化素数 p=s²+s+3 与椭圆曲线阶泄露：模平方根枚举 t 恢复 p 并解 AES-CTR](ctf-crypto-structured-prime-squares-plus-s-tonelli-aes-ctr/) | verified | high | 2026-11-07 |
| [维吉尼亚 + 凯撒复合密码：数字位凯撒 +5、字母位维吉尼亚，密钥计数器覆盖整串而非仅花括号内](ctf-crypto-vigenere-caesar-digit-letter-branch-counter-scope/) | verified | high | 2026-11-06 |
| [自参考密钥分组密码：先逆可逆混合层取回密钥，再解 TEA 变体](ctf-crypto-self-referential-key-tea-variant/) | verified | medium | 2026-11-06 |
| [自定义 4 位字符表编码的还原（每位十六进制 → 表内一个字符）+ 认出「连续 MD5(1)/MD5(2)/MD5(3)…」十六进制串作为钥匙，再处理 U2FsdGVkX1 开头的 OpenSSL Salted__ 密文](ctf-crypto-nibble-charmap-hex-md5-sequence-openssl-salted/) | verified | high | 2026-11-09 |
| [自定义 Base64 字符集还原：AA+X 探测第 4 字符反推 64 字符索引表](ctf-crypto-custom-base64-charset-oracle-recovery/) | verified | high | 2026-11-07 |
| [超递增背包密码（Merkle-Hellman）解密：密文乘 n 的模逆元还原 W 后，从最大项倒序贪心还原 0/1 明文](ctf-crypto-superincreasing-knapsack-merkle-hellman-decrypt/) | draft | high | 2026-11-10 |
| [近似 GCD（AGCD）SDA 格攻击：x_i=pq_i+e_i 用小误差差分构造短向量恢复 p](ctf-crypto-agcd-sda-lattice-small-error-recovery/) | verified | high | 2026-11-06 |
| [重复 XOR 密钥恢复：Base32 密文已知前缀反推 4 字节 key，加密 oracle 全零明文直接泄露 key](ctf-crypto-repeating-xor-key-known-plaintext-oracle/) | verified | high | 2026-11-06 |
| [黑盒加密选择明文建表：构造非线性输入让密文保持一一映射，再查表解 flag](ctf-crypto-blackbox-chosen-input-mapping/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
