# 随机数

## 这层是什么

弱随机、种子预测、MT19937 等。

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
| [/dev/urandom 打开或读取失败导致 srand 种子退化为固定序列](crypto-prng-urandom-open-fail-fixed-srand-sequence.md) | verified | medium | 2026-11-05 |
| [CVE-2023-39910（Milk Sad）：MT19937 32 位时钟种子导致钱包私钥可枚举](crypto-prng-mt19937-clock-seed-wallet-key-recovery.md) | verified | medium | 2026-11-05 |
| [glibc rand() 小种子空间爆破：复现 31/3 状态初始化，逐字节匹配首个输出还原 flag](crypto-prng-glibc-rand-small-seed-bruteforce.md) | verified | high | 2026-11-07 |
| [glibc rand() 连续输出泄露预测下一轮：31/3 线性递推恢复登录密码](crypto-prng-glibc-rand-output-sequence-prediction.md) | verified | high | 2026-11-05 |
| [LCG 参数恢复：连续输出差分 gcd 求模数、乘数与种子](crypto-prng-lcg-parameter-recovery-delta-gcd.md) | verified | high | 2026-11-06 |
| [LCG 状态逐字节恢复：利用后续消息只含数字字符的约束](crypto-prng-lcg-digit-charset-bytewise-state-recovery.md) | verified | high | 2026-11-07 |
| [LCG 高 16 位输出恢复初始状态：枚举低 16 位并用下一输出验证，预测第 100 位](crypto-prng-lcg-high16-state-recovery-enumeration.md) | verified | high | 2026-11-06 |
| [Math.random 生成会话密钥的可预测性：小程序 32 位 shareKey 恢复](crypto-prng-math-random-sharekey-recovery.md) | verified | high | 2026-11-05 |
| [MT19937 624 输出 untemper 恢复内部状态并预测后续随机数（含 GF(2) 矩阵法）](crypto-prng-mt19937-untemper-state-recovery-predict.md) | verified | high | 2026-11-06 |
| [MT19937 状态恢复：异常 oracle 排序 + random_prime 消耗间隙与 B0/B1 约束](crypto-prng-mt19937-random-prime-gap-oracle-recovery.md) | verified | high | 2026-11-06 |
| [MT19937 种子恢复：输出混入 LFSR 干扰与随机批次起点](crypto-prng-mt19937-seed-recovery-lfsr-noise-batch-alignment.md) | verified | medium | 2026-11-06 |
| [srand(time(NULL)) 时间种子 2FA 验证码预测绕过](crypto-prng-srand-time-seed-2fa-code-prediction.md) | verified | high | 2026-11-05 |
| [time()+glibc rand() 生成 RC4 会话密钥：预测并伪造认证报文](crypto-prng-time-seeded-rand-rc4-auth-forge.md) | verified | high | 2026-11-05 |
| [已知模数 2^32 的 LCG：前三输出恢复 A/C/seed，输出作 XOR keystream 解密](crypto-prng-lcg-known-modulus-xor-keystream.md) | verified | high | 2026-11-06 |
| [截断 LCG 状态恢复：Coppersmith 求 p 高位缺失 + 格 CVP 求低 256 位](crypto-prng-truncated-lcg-coppersmith-lattice-cvp.md) | verified | high | 2026-11-06 |
| [条件更新 LFSR 的 SAT 求解：前缀和 one-hot 计数器 + 翻转约束](crypto-prng-conditional-lfsr-sat-onehot-counter.md) | verified | high | 2026-11-06 |
| [滤波 LFSR 非线性输出状态恢复：48 位状态 + 80 位密钥流建模为 Z3 布尔约束](crypto-prng-filtered-lfsr-wg-anf-z3-state-recovery.md) | verified | high | 2026-11-06 |
| [状态接口泄露 pid/uptime：枚举启动时间复现确定性派生密钥并伪造管理 token](crypto-prng-observable-pid-uptime-derived-admin-secret-token-forgery.md) | verified | high | 2026-11-05 |
| [硬编码 PRNG 种子 + 自定义 LCG：按调用顺序预测 session secret 与管理员密码](crypto-prng-hardcoded-seed-custom-lcg-admin-password-predict.md) | verified | high | 2026-11-06 |
| [自定义 4-word ARX PRNG 状态恢复：untemper 逆变换 + 连续输出反推并预测下一次](crypto-prng-custom-arx-state-recovery-predict.md) | verified | high | 2026-11-06 |
| [魔改 _randbelow k=bit_length-1 导致输出截断：Z3 恢复 MT19937 状态并逆转 shuffle](ctf-crypto-mt19937-buggy-randbelow-z3-shuffle.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
