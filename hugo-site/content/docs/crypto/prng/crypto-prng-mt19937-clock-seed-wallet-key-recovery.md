---
id: crypto-prng-mt19937-clock-seed-wallet-key-recovery
title: CVE-2023-39910（Milk Sad）：MT19937 32 位时钟种子导致钱包私钥可枚举
type: scenario
domain: crypto
path: crypto/prng
technique: mt19937-clock-seed-wallet-key-recovery
tags:
- crypto
- prng
- mt19937
- cve-2023-39910
- wallet
- bitcoin
- weak-seed
- key-recovery
- blockchain
cve:
- CVE-2023-39910
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V71
  verified_at: '2026-11-05T16:36:55+08:00'
  notes: 已对照31页PPT核对：弱随机页代码为std::mt19937、get_clock_seed返回static_cast<uint32_t>(high_resolution_clock::now().time_since_epoch().count())、twister.reset(new std::mt19937(get_clock_seed()))，并给出遍历约43亿种子→私钥→公钥/地址→链上交易比对→私钥泄露、MilkSad/Lubian案例，卡片一致且MT19937/secp256k1派生原理正确。PPT未给完整脚本与命中结果，confidence=medium合理；未给受影响钱包版本，未设affected_versions。未实测。
url: /docs/crypto/prng/crypto-prng-mt19937-clock-seed-wallet-key-recovery/
draft: false
kb_aliases:
- Milk Sad
- CVE-2023-39910
- MT19937 弱种子
- 时钟种子钱包
- 比特币私钥枚举
- 32 位种子爆破
---

## 一句话结论

钱包软件若用 `std::mt19937` 生成私钥、并用 `high_resolution_clock::now().time_since_epoch().count()` 截断成 32 位整数作为种子，整个私钥空间就只剩约 2³² 个可能值；攻击者可以遍历种子、逐一代入 PRNG 派生公钥/钱包地址，再与链上地址或目标地址比对，恢复仍在使用该实现的钱包私钥。

## 原理

- MT19937（梅森旋转）是确定性伪随机数生成器：给定相同种子，输出序列完全一致；它不是密码学安全 PRNG，不能用于生成密钥材料。
- 漏洞代码把 `std::mt19937` 的种子设为 `uint32_t(high_resolution_clock::now().time_since_epoch().count())`，即时间的高精度计数被截断为 32 位；种子空间只有 2³²（约 43 亿）个值，且与钱包创建时间高度相关。
- 私钥生成流程通常是：PRNG 输出 256 位随机数 → 作为 secp256k1 私钥 d → 公钥 P = d·G → SHA256 → RIPEMD160 → 版本字节 → Base58Check 地址。整个派生过程公开、确定，攻击者可对每个候选种子复现。
- 攻击者对 seed 从 0 到 2³²-1（或按目标创建时间收窄窗口）逐个生成私钥和地址，与目标地址/链上发生过交易的地址集合比对；命中即得到私钥，可直接签名转走资产。
- 之所以可行：2³² 对现代 CPU/GPU 是可枚举量级；若只针对单个地址并按创建时间窗口搜索，成本更低。公开研究（Milk Sad）用该方法追踪到与 Lubian 相关的钱包地址，说明真实资金受影响。
- 该攻击不需要破解 secp256k1 或 SHA256，只是把“随机性不足”转化为“种子枚举”；因此修复必须改用 CSPRNG（`/dev/urandom`、`getrandom`、`crypto.randomBytes`、硬件 RNG），而不是换更复杂的曲线。

## 触发条件

- 钱包/密钥库由存在 CVE-2023-39910 一类弱种子的实现生成（案例为 C++ Boost `std::mt19937` + 32 位时钟种子）。
- 攻击者知道目标钱包地址，并能估计其大致创建时间（链上首笔交易、钱包文件时间、应用发布版本）。
- 目标私钥仍有效、地址仍有资产或曾用于签名。
- 攻击者有足够的算力/优化实现枚举 2³² 种子（GPU、C++ 多线程或预计算地址库）。

## 利用步骤

1. 识别钱包实现与版本：地址格式、客户端/库版本、是否存在 `mt19937`/`rand()`/`srand(time())` 一类弱随机调用；确认对应 CVE/披露。
2. 收集目标地址与时间线索：链上首笔交易时间、钱包创建时间、应用安装时间；把种子搜索范围收窄到该时间窗对应的 32 位计数区间。
3. 实现种子枚举：使用与目标一致的 MT19937 实现和私钥派生流程（secp256k1、SHA256/RIPEMD160、Base58Check/bech32），对每个 seed 生成候选地址。
4. 比对：单地址直接比较；批量场景可预生成地址集合或使用 Bloom filter/数据库；区块链浏览器 API 可辅助确认余额与交易。
5. 命中后导出私钥，在离线环境验证地址与控制权；不要在联网环境明文保存私钥。
6. 评估影响：同一 PRNG 生成的其他地址、同一钱包的多个账户、同版本软件生成的其他钱包都可能受影响，扩大枚举范围。
7. 对仍在使用弱实现的钱包，迁移到新地址并转移资产；旧地址视为已泄露。

## PoC

```text
# 原理性伪代码：枚举 32 位种子并派生地址
for seed in range(2**32):
    rng = MT19937(seed)                 # 必须与目标实现的 seeding/输出方式一致
    entropy = rng.generate(32)          # 32 字节，具体取法依钱包实现
    priv = int.from_bytes(entropy, 'big') % CURVE_ORDER
    addr = base58check(ripemd160(sha256(secp256k1_pubkey(priv))))
    if addr == target_address:
        print("found", seed, hex(priv))
        break
```

```bash
# 时间窗口收窄思路（示意）
# 1) 从链上首笔交易得到 UTC 时间 T
# 2) 计算 T 前后若干分钟对应的 time_since_epoch().count() 低 32 位区间
# 3) 只枚举该区间，而不是全 2^32
```

## 变体与关联

- 变体：`rand()`/`srand(time(NULL))`、`Math.random()`、`java.util.Random`、PHP `mt_rand` 等非密码学 PRNG；种子可能是秒级时间、进程 ID、MAC 地址或它们的组合。
- 变体：HD 钱包（BIP32/BIP44）若根种子来自弱 PRNG，所有派生地址都受影响；枚举时需按目标 derivation path 派生。
- 变体：攻击者可预计算“种子→地址”数据库，或针对批量泄露的地址做集合交集；GPU/FPGA 可进一步提高速率。
- 关联：[[crypto-prng-math-random-sharekey-recovery]]（Math.random 生成会话密钥）、[[crypto-prng-srand-time-seed-2fa-code-prediction]]（时间种子预测验证码）、[[crypto-prng]] 目录下的其他弱随机案例。
- 边界：钱包使用 CSPRNG、种子空间大于 2³² 且不可收窄、目标地址已迁移/无资产、或派生流程未知时，枚举不可行；文章只给原理与案例，未提供完整利用脚本与命中结果。

## 检测与防御

- **使用 CSPRNG**：私钥/助记词/种子必须来自操作系统 CSPRNG 或硬件 RNG；禁止使用 `mt19937`、`rand()`、`Math.random()`、时间戳作为唯一熵源。
- **代码审计**：检查钱包库的种子初始化、随机数调用与密钥派生；对第三方库做版本与 CVE 核查；对自研代码做熵源评审。
- **迁移**：发现弱随机生成的钱包后，立即生成新钱包并转移资产；旧地址视为已泄露，不要继续使用。
- **监测**：链上监控异常转出；对已知弱 PRNG 地址库做比对；关注 Milk Sad 等披露的受影响地址/工具更新。
- **合规**：只在授权范围内对自有/授权钱包做恢复测试；不要扫描或转移他人资产。

