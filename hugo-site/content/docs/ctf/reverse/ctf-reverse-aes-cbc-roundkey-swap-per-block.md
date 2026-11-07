---
id: ctf-reverse-aes-cbc-roundkey-swap-per-block
title: AES-CBC 轮密钥逐块交换魔改：按 j%11 交换第 0 轮与第 n 轮后解密
type: scenario
domain: ctf
path: ctf/reverse
technique: aes-cbc-roundkey-swap-per-block
tags:
- ctf
- reverse
- aes
- cbc
- key-schedule
- round-key
- file-encryption
- malware
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:28:26+08:00'
  notes: 已对照原文代码及图52-56核对：主密钥cgDSb6VOegeF7EuW（hex 636744536236564f6567654637457557）、IV 672394ef4cd52f76ffde7bb06a86625c、n=块序号%11、CBC末块不足16字节原样写出、还原PNG且MD5后六位FF74E8均一致；无CVE、frontmatter无sources/source_url；未复跑样本解密。
url: /docs/ctf/reverse/ctf-reverse-aes-cbc-roundkey-swap-per-block/
draft: false
kb_aliases:
- 轮密钥交换魔改
- round key swap
- AES 每块轮密钥轮换
- AES 密钥扩展魔改
- 第 0 轮与第 n 轮交换
---

## 一句话结论

当样本的 AES-128-CBC 密钥扩展在标准 11 组轮密钥生成后，又对每个 16 字节块按 `n = 块序号 % 11` 交换 `round_keys[0]` 与 `round_keys[n]` 时，标准 AES 库会从第 0 轮起就用错密钥，解出乱码；复现同样的“先扩展、再交换”轮密钥生成，并按块传入对应的 n，即可正常 CBC 解密。

## 原理

- AES-128 标准密钥扩展把 16 字节主密钥扩展为 11 组 16 字节轮密钥 `RK0..RK10`（Nk=4、Nr=10、44 个 32-bit 字）。加密第 0 轮用 `RK0`，第 1..9 轮用 `RK1..RK9`，第 10 轮用 `RK10`；解密时逆序使用。
- 样本的 `key_expansion(key16, n)` 在生成完整 `RK[0..10]` 后执行 `tmp = RK[n]; RK[n] = RK[0]; RK[0] = tmp`。于是第 0 轮改用原 `RKn`，第 n 轮改用原 `RK0`，其余轮密钥不变。n 不是主密钥的一部分，而是由当前块序号决定（案例 `n = j % 11`，j 从 0 开始，每 16 字节一块）。
- 为什么标准库解不出：AddRoundKey 是异或，交换轮密钥改变了第 0 轮和第 n 轮的异或值。只要解密轮函数使用同一份“交换后的轮密钥表”，逆运算仍然成立；但标准 AES 实现对每个块只用固定的 `RK0..RK10`，无法表达“逐块变化”的轮密钥，因此第一块起就会出错。
- 识别信号：反编译的密钥扩展多出一个参数并出现轮密钥交换；解密函数按块调用密钥扩展，而不是只扩展一次；S-box、轮常量、MixColumns 都标准；用标准 AES-CBC 解密结果从第一块起就是乱码。
- 案例参数：主密钥 ASCII `cgDSb6VOegeF7EuW`（hex `636744536236564f6567654637457557`），IV `672394ef4cd52f76ffde7bb06a86625c`；解密后文件是 PNG，说明交换规则与块序号对齐（j 从 0 开始）。

## 触发条件

- 目标使用 AES-128-CBC，S-box/ShiftRows/MixColumns 与标准一致，但密钥扩展后对轮密钥做交换或轮换。
- 能从二进制 `.rdata`、配置或动态调试中得到 16 字节密钥与 16 字节 IV。
- 待解文件按 16 字节分块，末块可能不足 16 字节（案例直接原样写出）。
- 能确定交换参数 n 的来源（块序号、固定常量或另一字段派生）。

## 利用步骤

1. 在 IDA 中定位密钥扩展：确认生成 11 组轮密钥、使用标准 Rcon/S-box；查找扩展后的 `swap(RK[0], RK[x])`。
2. 追踪 x 的来源：案例是解密循环中的块计数器 j 对 11 取模，随块递增；确认 j 的初值与自增位置（每解完一块 +1）。
3. 提取密钥与 IV；确认 CBC 模式（首块异或 IV）和末块处理方式。
4. 用标准 AES-128 轮函数实现 `expand(key)`；每块解密前复制轮密钥表并交换 `RK[0]` 与 `RK[n]`，或直接实现带 n 参数的 `key_expansion(key, n)`。
5. 逐块 `P_i = AES_dec_swapped(C_i) XOR prev`（prev 首块为 IV，之后为上一块密文），拼接明文；末块不足 16 字节按样本逻辑处理。
6. 用文件头（PNG `89 50 4E 47` 等）验证；若第一块正确、后续错，检查 j 是否每块递增以及 n 是否在交换前取模。

## PoC

```python
# 仅展示“扩展后交换”的核心；aes128_expand / aes128_dec_block 用标准 FIPS-197 实现
def round_keys_for_block(key, block_index):
    rk = aes128_expand(key)              # 11 x 16 bytes，标准扩展
    n = block_index % 11
    rk[0], rk[n] = rk[n], rk[0]          # 与样本一致的交换
    return rk

def cbc_decrypt_swapped(key, iv, ct):
    out, prev, j = bytearray(), iv, 0
    for i in range(0, len(ct), 16):
        blk = ct[i:i+16]
        if len(blk) < 16:                # 案例：末块不足 16 字节原样写出
            out += blk
            break
        rk = round_keys_for_block(key, j)
        dec = aes128_dec_block(blk, rk)  # 标准逆轮，使用 rk[10]..rk[0]
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
        j += 1
    return bytes(out)

KEY = b"cgDSb6VOegeF7EuW"
IV  = bytes.fromhex("672394ef4cd52f76ffde7bb06a86625c")
# data = open("6c051a72b91a1.1", "rb").read()
# open("6c051a72b91a1.png", "wb").write(cbc_decrypt_swapped(KEY, IV, data))
```

案例用该规则把加密文件还原为 PNG（MD5 后六位 `FF74E8`）。本卡不执行样本。

## 变体与关联

- 交换对象可以是任意两轮（不只第 0 轮与第 n 轮），也可以是全部 11 组轮密钥按块轮转；关键是加解密双方使用同一份逐块轮密钥。
- n 的来源可能是块序号、文件偏移、前一块密文或固定常量；若 n 固定，标准库仍无法直接用，需要手动替换轮密钥。
- 可与“自定义 Rcon”“自定义 S-box/ShiftRows”“末轮省略 MixColumns”等魔改叠加；识别时逐项与标准 AES 对比。
- 关联：[[ctf-reverse-aes256-custom-rcon-key-schedule-decrypt]]（Rcon 魔改）、[[ctf-reverse-aes128-aux-table-roundkey-recovery]]（轮密钥泄露恢复）、[[defense-forensics-fake-v2ray-embedded-rc4-dll-extract]]（同一案例的 RC4 载荷提取与文件加密链）。
- 边界：若交换表在运行时由主密钥或随机数派生且无法 dump，仅靠密文无法恢复；若只有密文没有 key/IV，同样无法解密。

## 检测与防御

- 分析侧：先确认 S-box/轮函数标准，再检查密钥扩展后的额外变换；用已知明文块验证第 0 轮与第 n 轮是否被交换。
- 防御侧：不要用魔改算法代替密钥管理；文件加密密钥不应硬编码在客户端；使用标准密码库与 KMS。
- 检测：PE 中出现“密钥扩展 + 轮密钥交换 + 文件遍历加密”的组合；`RK[0]` 与 `RK[n]` 的交换指令；固定 16 字节 key/IV 常量。
- 加固：加密软件应有签名与完整性校验；终端监控异常批量文件改写与扩展名变更。
