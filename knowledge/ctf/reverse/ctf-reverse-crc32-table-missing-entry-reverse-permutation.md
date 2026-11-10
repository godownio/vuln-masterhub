---
id: ctf-reverse-crc32-table-missing-entry-reverse-permutation
title: CRC32 校验表缺失项恢复：reverse 求 4 字节原像 + 未知位置排列爆破，恢复 AES key
type: scenario
domain: ctf
path: ctf/reverse
technique: crc32-table-missing-entry-reverse-permutation-recovery
aliases:
- CRC32 表恢复
- CRC32 reverse
- crc32.py reverse
- CRC32 校验反推
- CRC32 表 0xff 占位
- CRC32 排列爆破
tags:
- ctf
- reverse
- crc32
- table
- reverse-engineering
- brute-force
- permutation
- aes-key
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:19:37+08:00'
  notes: 已对照原文与图片核对：16 字节表 5 个 0xff 占位（下标 2/5/9/10/14）、check 函数 0xffffffff 初始值且无最终异或、目标 0x80A18648、crc32.py reverse 0x27949C6C 得 {0xbf,0x8d,0x30,0xc2}、排列替换后作为 AES key，均与原文一致。我独立复跑卡片 PoC：唯一命中 1bb1edfd19ce898c09f7fcd74ab389eb，check16=0x80a18648，zlib.crc32=0x7f5e79b7，与卡片说明完全一致。未验证点：还原明文未核对原题；affected_versions 已 --clear。
---

## 一句话结论

逆向题把 16 字节校验表/密钥中的若干字节置成 `0xff` 占位、只用一段 CRC32 校验验证整表时，CRC32 不是密码学哈希，可以先用 `crc32.py reverse <目标校验值>` 求出 4 字节原像，再对少量未知位置的候选值做排列爆破，直到重组后的 16 字节 CRC32 等于目标值；恢复出的整表就是下一步 AES 解密的 key。

## 原理

- **CRC32 可逆且线性**：CRC32 是对消息做 GF(2) 上的线性变换（初始值、查表、移位异或），给定校验值和消息结构，可以反推短消息的字节。`crc32.py` 的 `reverse` 模式对 4 字节目标枚举原像，输出满足 `crc32(bytes) == 目标值` 的 4 字节数据，并自校验结果。
- **题目结构**：目标二进制的校验函数用标准 CRC32 表 `box` 对 16 字节数据做 4 组查表，初始值 `0xffffffff`，返回时不做最终异或（因此与 zlib 的 `crc32` 相差一次 `^0xffffffff`）。16 字节密钥中有 5 个位置被写成 `0xff` 占位（下标 2、5、9、10、14），程序只检查最终 CRC32 是否等于 `0x80A18648`。
- **为什么能爆破**：未知字节的候选集合很小（由题目的数据行给出），5 个位置的排列数是 `5! = 120`；对每个排列计算一次 CRC32 即可筛选。CRC32 的 32 位校验空间远大于 120，命中即唯一（或极少）候选。
- **与“哈希碰撞”无关**：这里不是找碰撞，而是利用 CRC32 的线性/可逆性做约束求解；即使校验值随机，也能从候选集合中恢复出满足约束的那组字节。
- **恢复后的用途**：补齐的 16 字节表被直接当作 AES key（ECB/NoPadding）解密密文，得到最终答案；CRC32 在这里只承担完整性/校验作用，不能提供任何抗篡改能力。

## 触发条件

- 逆向题用 CRC32（或类似线性校验）验证一段短数据/表，且校验值已知。
- 数据中未知字节数量少、候选值集合小，或未知位置可枚举。
- 能确定 CRC32 的参数约定：多项式、初始值、是否反射、最终异或、字节序；不一致会导致重算结果对不上。
- 恢复出的数据在后续流程中作为密钥/表使用（本例为 AES key）。

## 利用步骤

1. 逆向定位校验函数，确认 CRC32 表、初始值、循环结构、目标值（本例 `0x80A18648`）以及最终异或约定。
2. 找出被 `0xff` 占位的未知位置（本例 2、5、9、10、14）和候选值集合。
3. 对可独立求解的部分使用 `crc32.py reverse <目标>` 求 4 字节原像（本例用于 rand1，得到 `{0xbf, 0x8d, 0x30, 0xc2}`，工具自校验通过）。
4. 对 5 个未知位置的候选值做全排列（120 种），填入 16 字节模板后用与二进制一致的 CRC32 函数计算，命中目标值即恢复整表。
5. 用恢复出的 16 字节作为 AES key 解密密文，按题目格式取答案。

## PoC

```python
import itertools

# 标准 CRC32 表 + 与题目一致的无最终异或版本
poly = 0xEDB88320
box = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ poly if c & 1 else c >> 1
    box.append(c)

def check16(data):
    v = 0xffffffff
    for b in data:
        v = box[(v ^ b) & 0xff] ^ (v >> 8)
    return v  # 题目函数不做最终 ^0xffffffff

template = [0x1B, 0xB1, 0xFF, 0xFD, 0x19, 0xFF, 0x89, 0x8C,
            0x09, 0xFF, 0xFF, 0xD7, 0x4A, 0xB3, 0xFF, 0xEB]
pos = [2, 5, 9, 10, 14]
cands = [237, 206, 247, 252, 137]
target = 0x80A18648

for perm in itertools.permutations(cands):
    key = template[:]
    for p, v in zip(pos, perm):
        key[p] = v
    if check16(key) == target:
        print("recovered key:", bytes(key).hex())
        break
# recovered key: 1bb1edfd19ce898c09f7fcd74ab389eb
# 验证：check16(bytes.fromhex(...)) == 0x80a18648
```

说明：恢复结果已按题目校验函数复算，`check16` 返回 `0x80a18648`；与 zlib.crc32 相差一次最终异或（`zlib.crc32(key) == 0x7f5e79b7`）。`crc32.py reverse` 的用法为 `python crc32.py reverse 0x27949C6C`，输出 4 字节原像并自校验。

## 变体与关联

- **已知部分明文的 CRC 反推**：若未知的是消息中的 4 字节，可直接 reverse；若未知分散在多处，先 reverse 再排列/线性方程求解。
- **CRC16/CRC64/自定义多项式**：方法相同，但必须确认多项式、初始值、反射与最终异或；线性方程组可处理更多未知位。
- **弱校验替代思路**：当未知字节较多时，用 GF(2) 线性代数把 CRC 约束写成方程组，比纯排列爆破更高效。
- **边界**：校验使用密码学哈希（SHA/MD5）或带密钥的 MAC 时，本方法不成立；未知空间过大且无可利用结构时也无法爆破。

## 检测与防御

- **CTF/出题**：不要把 CRC32 当作密钥完整性保护；如果密钥必须校验，使用带密钥的 MAC（HMAC）或签名。
- **逆向分析**：遇到“表不完整 + 末尾校验”的题目，优先确认校验算法与参数，再决定 reverse/排列/线性代数路线。
- **工程侧**：CRC 只用于误码检测，不用于安全认证；密钥/固件完整性应使用 SHA-256 + 签名，并避免在二进制中留下可反推的短校验约束。
