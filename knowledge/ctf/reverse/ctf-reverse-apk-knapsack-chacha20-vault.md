---
id: ctf-reverse-apk-knapsack-chacha20-vault
title: APK 加密归档逆向：64 维低密度背包 LLL 还原选择向量，派生 ChaCha20 密钥解密 RBV2 归档
type: scenario
domain: ctf
path: ctf/reverse
technique: apk-knapsack-chacha20-vault
aliases:
- 机器人资料审计
- bot_archive_hard.apk
- RBV2 归档
- 低密度子集和 LLL
- CJLOSS 格
- BOTPACK-V2 密钥派生
- ChaCha20-IETF counter=1
- notice_template.bin 背包目标
tags:
- ctf
- reverse
- android
- apk
- knapsack
- lll
- subset-sum
- chacha20
- key-derivation
- jadx
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:40+08:00'
  notes: 对照 Reverse238：64 维 160-bit 背包、NTC2 21B 目标、CJLOSS/LLL、ChaCha20 KDF、96 记录唯一命中一致
---

## 一句话结论

APK 把解密材料分散在 `region_rules.json`（64 个 160-bit 背包权重）、`app_update.json`（RBV2/ChaCha20/KDF 参数）和 `notice_template.bin`（27 字节中的 21 字节大端目标值）；对 64 维、密度 0.4 的低密度子集和做 LLL/CJLOSS 格约减还原 64 位选择向量，按 MSB0 打包后接 `BOTPACK-V2\0` 做 SHA-256 得到 ChaCha20 密钥，即可解密归档并筛选出唯一记录。

## 原理

- `region_rules.json` 声明 64 个 160-bit 大整数权重，参数 `dimension=64`、`weight_bits=160`、`density=0.4`、`bit_order=msb0`，算法名为 `low-density-subset-sum/1`。
- `notice_template.bin` 只有 27 字节：前 4 字节魔数 `NTC2`，第 5-6 字节大端长度 `0x0015=21`，其后 21 字节大端整数即背包目标值；其位长约 165，正好是 64 个 160-bit 权重的部分和量级。这是最容易被忽略的材料。
- 子集和密度 `d = n / log2(max weight) = 64/160 = 0.4`，低于 LLL 可解的经典阈值 0.9408，属于低密度子集和。构造 CJLOSS 格：维度 n+1；前 n 行第 i 行在第 i 列为 2、最后一列为 `N·w_i`；第 n+1 行前 n 列全 1、最后一列为 `N·target`（N 取 2^200）。LLL 约减后扫描“最后一列为 0 且前 n 列全为 ±1”的行，即可还原 64 位选择向量（本题 33 个 1；六组格参数 N∈{1,2,3,7,2^16,2^64} 解一致，交叉验证正确性）。
- APK 反编译（jadx/baksmali）只需关注 4 个类。`RobotVault.decryptArchive` 校验前 4 字节 `RBV2` 后把第 5 字节起当密文；`deriveKey(selectorBits)=SHA-256("BOTPACK-V2\0"+packMsbFirst(selectorBits))`；`packMsbFirst` 把 bit 列表按 MSB0 打包成 8 字节，与 `region_rules.json` 的 `bit_order=msb0` 对应。
- 密钥 = SHA-256(前缀 10 字节 + 8 字节选择向量)，即 32 字节；ChaCha20-IETF 使用 counter=1、nonce 由 `01000000` 与 `d97260b55630b1c863d79863` 组成。解密后明文 SHA-256 与 `app_update.json` 的 `plaintext_sha256` 吻合，说明背包解、打包顺序、KDF、nonce 全链路正确。
- 明文是 96 条 JSON 记录；按 `role=dispatcher`、`status=archived`、`risk=high` 过滤，唯一命中 `bot_id=RB-739201-57`，其 memo 中含 flag。

## 触发条件

- 拿到 APK 与加密归档；能反编译/静态分析 assets 与 res/raw。
- 归档密钥由低密度子集和解（或类似可约减的格问题）派生，且算法/参数在 APK 中可见。
- 有明文校验值（plaintext_sha256）用于验证解密链路。
- 记录集可用业务字段过滤出唯一目标。

## 利用步骤

1. 解包 APK，枚举 `assets/` 与 `res/raw/` 中的配置、归档、模板文件；识别魔数 `RBV2`、`NTC2`。
2. 反编译相关类，确认归档格式、KDF 前缀、bit 打包顺序、ChaCha20 参数（counter/nonce）与明文校验。
3. 从 `region_rules.json` 读取 64 个权重，从 `notice_template.bin` 解析 21 字节大端目标值。
4. 构造 CJLOSS 格并 LLL 约减，扫描短向量还原 64 位选择向量；用多组格参数/重新计算子集和校验。
5. 按 MSB0 打包 8 字节，拼 `BOTPACK-V2\0` 做 SHA-256 得 ChaCha20 密钥；用 counter/nonce 解密 `robot_cache.dat` 第 5 字节起的密文。
6. 校验明文 SHA-256，解析 JSON，按 role/status/risk 过滤出唯一记录并提交 flag。

## PoC

```python
def solve_subset_sum(weights, target, Nbits=200):
    n = len(weights); N = 1 << Nbits; dim = n + 1
    M = IntegerMatrix(dim, dim)
    for i in range(n):
        M[i, i] = 2
        M[i, n] = N * weights[i]
    for j in range(n):
        M[n, j] = 1
    M[n, n] = N * target
    LLL.reduction(M)
    for r in range(dim):
        row = [M[r, j] for j in range(dim)]
        if row[n] != 0 or not all(v in (1, -1) for v in row[:n]):
            continue
        bits = [1 if row[j] == 1 else 0 for j in range(n)]
        for cand in (bits, [1 - b for b in bits]):
            if sum(weights[i] for i in range(n) if cand[i]) == target:
                return cand
    return None

bits = solve_subset_sum(weights, target)
packed = pack_msb0(bits)                      # 8 字节
key = hashlib.sha256(b"BOTPACK-V2\x00" + packed).digest()
plain = chacha20_ietf_decrypt(ciphertext, key, nonce, counter=1)
assert hashlib.sha256(plain).hexdigest() == plaintext_sha256
records = json.loads(plain)
```

```python
# notice_template.bin 解析
data = open("assets/notice_template.bin", "rb").read()
assert data[:4] == b"NTC2"
ln = int.from_bytes(data[4:6], "big")          # 0x0015 = 21
target = int.from_bytes(data[6:6+ln], "big")
```

## 变体与关联

- 变体：高密度子集和需要其他格/中间相遇；权重/目标可隐藏在图片、音频、资源文件；KDF 前缀/打包顺序/端序可用明文哈希反推。
- 变体：ChaCha20 参数可从 native 库、字符串、常量池提取；若 APK 有加固，需先脱壳再静态分析。
- 关联：[[crypto-rsa-multiprime-partial-key-coppersmith]]（格攻击的另一类）、[[crypto-implementation-dirichlet-convolution-parameter-inversion]]（可逆参数隐藏）。
- 边界：密度接近/超过阈值时 LLL 可能失败；需要 Sage/LLL 实现；APK 加固会使静态材料不可见；明文哈希校验保证链路正确。

## 检测与防御

- 检测：APK 中同时出现背包权重、目标值模板、归档魔数与 KDF 参数；assets/res 中存在高熵归档；应用对本地归档做弱密钥派生。
- 修复：不要用低密度子集和等可约减问题派生密钥；使用设备密钥库/Keystore 与标准 KDF；对归档做认证加密；不要把目标值/权重/校验值分散但明文存放在同一 APK。
- 加固：代码混淆/加固、密钥白盒、服务端下发密钥；对本地数据加密并绑定设备；定期轮换密钥。
