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
| [AES S-box 重复/缺失字节侧信道：区分随机块与密文 + z3 解双重 Base64 乱序表](ctf-crypto-aes-sbox-duplicate-missing-byte-random-block-z3-base64/) | verified | high | 2026-11-06 |
| [AES-CBC 自定义前置填充 + key⊕首块 hint：已知 flag{ 前缀爆破单字符恢复 key](ctf-crypto-aes-cbc-prefix-padding-key-xor-hint/) | verified | high | 2026-11-06 |
| [AES-GCM nonce 复用：tag 差分在 GF(2^128) 求根恢复 GHASH 子密钥 H](ctf-crypto-aes-gcm-nonce-reuse-ghash-subkey-root/) | verified | high | 2026-11-06 |
| [AES-GCM tag 低 64 位被 GHASH^MT19937 污染：线性方程恢复 H 与种子](ctf-crypto-aes-gcm-tag-fault-mt19937-linear-recovery/) | verified | medium | 2026-11-06 |
| [Asmuth-Bloom 秘密共享 + RSA 加密 share：CRT 重构 zip 密码](ctf-crypto-asmuth-bloom-rsa-share-crt-recovery/) | verified | high | 2026-11-06 |
| [Berlekamp-Welch 有理函数插值：从带 30 个噪声点的 98 个样本恢复分子分母](ctf-crypto-berlekamp-welch-rational-function-interpolation/) | verified | high | 2026-11-06 |
| [CDF 注释藏 Kyber 风格 u/v 块：q/2 偏移编码 bit 恢复 AES key 并解 CBC](ctf-crypto-cdf-comments-qhalf-bit-encoding-aes/) | verified | high | 2026-11-06 |
| [Feistel 立方轮函数 GF(2^16) 代数攻击：多项式基秩下降恢复 16-bit 轮密钥](ctf-crypto-feistel-gf2-16-cubic-rank-drop-key-recovery/) | verified | high | 2026-11-06 |
| [GF(3) HFE/UOV 公钥超定方程组：msolve F4 逐块直接求解，无需私钥](ctf-crypto-gf3-hfe-uov-msolve-f4/) | verified | high | 2026-11-06 |
| [Hidden Number Problem（HNP）MSB 泄露：pI 与 t 行构造格，Babai 最近平面恢复 α](ctf-crypto-hnp-msb-oracle-babai-nearest-plane/) | verified | high | 2026-11-06 |
| [HNP-2H 连分数降维 + Kannan Embedding：双小未知量模方程恢复大 secret](ctf-crypto-hnp-2h-continued-fraction-kannan-embedding/) | verified | medium | 2026-11-06 |
| [LFSR 抽头 mask 恢复：initState 与 outputState 前 128 位建 GF(2) 方程](ctf-crypto-lfsr-mask-recovery-output-state/) | verified | medium | 2026-11-06 |
| [LFSR 流密码已知明文恢复：64 比特帧头建立 GF(2) 方程组解初始状态](ctf-crypto-lfsr-known-plaintext-state-recovery/) | verified | medium | 2026-11-06 |
| [LLL 恢复小系数多项式：偏移 B 构造短向量，8 组精确求值还原后 SHA-256 派生 AES-CTR key](ctf-crypto-lll-polynomial-small-coeff-evaluation-recovery/) | verified | medium | 2026-11-06 |
| [LLL 恢复打乱基中的短向量 + Kannan embedding 解小误差 LWE](ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe/) | verified | high | 2026-11-06 |
| [LLL 解三角函数整数关系：高精度 sin/cos 与密文构造格恢复小系数 a,b](ctf-crypto-lll-trig-integer-relation/) | verified | high | 2026-11-06 |
| [MT19937 位流状态恢复：中文位才消耗 bit 的错位修正与 getrandbits(50000) 预测](ctf-crypto-mt19937-bitstream-chinese-alignment-state-recovery/) | verified | high | 2026-11-06 |
| [Noise CRT：带噪 CRT 余数用 Pi·inv(Pi) 系数与 2^nbits 对角构造格恢复 N](ctf-crypto-noise-crt-lattice-recovery/) | verified | medium | 2026-11-06 |
| [RSA 小指数广播攻击：三组 e=3 同明文 CRT 合成后开立方](ctf-crypto-rsa-hastad-broadcast-e3-crt/) | verified | high | 2026-11-06 |
| [Semi-ADFGX 5×6 Polybius 方阵 + 爬山/模拟退火替换还原英文贺词](ctf-crypto-semi-adfgx-5x6-polybius-hillclimb-substitution/) | verified | high | 2026-11-06 |
| [Simon 型周期测量恢复隐藏周期：GF(2) 零空间求 80 bit 周期](ctf-crypto-simon-period-measurement-gf2-nullspace/) | verified | high | 2026-11-06 |
| [UDS 0x27 SecurityAccess 弱 seed-key 算法逆推：XOR/ROL/ADD 从 seed 计算 key](ctf-crypto-uds-securityaccess-seed-key-recovery/) | verified | high | 2026-11-06 |
| [Z3 求解 6 字节输入的 128 位状态约束：模乘异或链的逆问题](ctf-crypto-z3-short-input-128bit-state-constraint/) | verified | high | 2026-11-06 |
| [两次维吉尼亚加密同一明文：差分周期恢复密钥流并解 flag](ctf-crypto-vigenere-two-ciphertext-differential-period/) | verified | high | 2026-11-06 |
| [半直积群小阶共轭元：枚举 c 的阶后用 BSGS 解离散对数](ctf-crypto-semidirect-product-small-order-discrete-log/) | verified | high | 2026-11-06 |
| [单字节种子递推流密码：已知明文前缀爆破 256 个种子](ctf-crypto-single-byte-seed-recurrence-stream-cipher-bruteforce/) | verified | high | 2026-11-06 |
| [多元对称方程消元：把 a³+b⁶ 与 ac 表示为 b 的多项式，降为单变量高次方程](ctf-crypto-multivariate-elimination-univariate-polynomial/) | verified | high | 2026-11-06 |
| [天书 + 与佛论禅双层中文编码：64 符号 base64 变体与 128 字表高位标志，套 CryptoJS EVP_BytesToKey AES](ctf-crypto-tianshu-foshuo-double-layer-cryptojs-evp-bytes-to-key/) | verified | high | 2026-11-06 |
| [字符重复 + AES-ECB 块循环移位异或：已知前缀逐字符唯一推出 flag](ctf-crypto-aes-ecb-duplicated-char-circular-xor/) | verified | high | 2026-11-06 |
| [小模数离散对数 + CRT 枚举真通道：从 18 条投影中恢复隐藏整数 x](ctf-crypto-small-discrete-log-crt-channel-selection/) | verified | high | 2026-11-06 |
| [幂塔模合数：三因子分解 + 欧拉降幂逐素数求值 + CRT 后 XOR 解明文](ctf-crypto-power-tower-composite-modulus-crt/) | verified | high | 2026-11-06 |
| [异或密钥流重用：已知一段明文恢复另一段密文（two-time pad）](ctf-crypto-xor-keystream-reuse-known-plaintext/) | verified | high | 2026-11-06 |
| [批量 RSA 模数两两 gcd：共享素因子直接分解并恢复明文](ctf-crypto-rsa-shared-prime-batch-gcd/) | verified | high | 2026-11-06 |
| [挑战响应认证的 XOR 折叠校验：8 字节比较降为单字节，1/256 概率通过](ctf-crypto-challenge-response-xor-fold-checksum-1in256/) | verified | high | 2026-11-06 |
| [环卷积线性系统恢复稀疏向量：F_65537[x]/(x^70+1) 上的 NTRU 类方程](ctf-crypto-ring-convolution-linear-system-sparse-vector/) | verified | high | 2026-11-06 |
| [稀疏分组指纹覆盖 + meet-in-the-middle：从 7 组告警恢复 14 列异或路径](ctf-crypto-sparse-group-fingerprint-mitm-xor-path/) | verified | high | 2026-11-06 |
| [稀疏错误线性系统：校验矩阵枚举 4 个错误位置并恢复单项式向量](ctf-crypto-sparse-error-linear-system-nullspace-enumeration/) | verified | high | 2026-11-06 |
| [类 Dilithium 签名缺少误差项：t = A·s 精确线性方程组在 Z_q 上直接解出私钥](ctf-crypto-dilithium-like-exact-t-as-linear-system-secret-recovery/) | verified | high | 2026-11-06 |
| [线性模哈希碰撞：把 Σ(2g)^{i-k}g·e_k≡0 mod N 转成 [E|R;0|N] 格，LLL 求短差分向量](ctf-crypto-linear-hash-collision-lll/) | verified | high | 2026-11-06 |
| [维吉尼亚 + 凯撒复合密码：数字位凯撒 +5、字母位维吉尼亚，密钥计数器覆盖整串而非仅花括号内](ctf-crypto-vigenere-caesar-digit-letter-branch-counter-scope/) | verified | high | 2026-11-06 |
| [自参考密钥分组密码：先逆可逆混合层取回密钥，再解 TEA 变体](ctf-crypto-self-referential-key-tea-variant/) | verified | medium | 2026-11-06 |
| [近似 GCD（AGCD）SDA 格攻击：x_i=pq_i+e_i 用小误差差分构造短向量恢复 p](ctf-crypto-agcd-sda-lattice-small-error-recovery/) | verified | high | 2026-11-06 |
| [重复 XOR 密钥恢复：Base32 密文已知前缀反推 4 字节 key，加密 oracle 全零明文直接泄露 key](ctf-crypto-repeating-xor-key-known-plaintext-oracle/) | verified | high | 2026-11-06 |
| [黑盒加密选择明文建表：构造非线性输入让密文保持一一映射，再查表解 flag](ctf-crypto-blackbox-chosen-input-mapping/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
