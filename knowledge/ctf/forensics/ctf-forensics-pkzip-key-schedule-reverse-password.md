---
id: ctf-forensics-pkzip-key-schedule-reverse-password
title: PKZIP 传统加密密钥调度逆向：由 Key0/Key1/Key2 反推密码（bkcrack -r）
type: scenario
domain: ctf
path: ctf/forensics
technique: pkzip-key-schedule-reverse-password
aliases:
- bkcrack -r
- bkcrack ?b
- PKZIP 密码恢复
- ZipCrypto 密钥反推
- inverse_crc32
- 三段密钥逆推密码
- 已知内部密钥恢复密码
tags:
- ctf
- forensics
- zip
- zipcrypto
- pkzip
- bkcrack
- key-recovery
- password-recovery
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:02:32+08:00'
  notes: 已对照 90749 原文核对：Key0/Key1/Key2 初值、CRC32/0x08088405/加法更新式、三段逆向与 bkcrack -r 3 ?b 参数语义均与原文/算法一致；原文注释把 -r 的 3 误说成逆向迭代次数，卡片按真实语义写为密码长度。未复跑 bkcrack。
---

## 一句话结论

PKZIP 传统加密（ZipCrypto）的三段 32 位内部 key 更新过程是逐字节可逆的：CRC32 单字节更新可逆、乘 `0x08088405` 在模 2^32 下可逆、加法可逆；因此只要通过已知明文攻击（或其它方式）拿到某一时刻的 Key0/Key1/Key2，就能逐字节枚举并反推出原始密码。bkcrack 的 `-k <key0> <key1> <key2> -r <长度> <字符集>` 把这一逆推自动化，例如 `-r 3 ?b` 用于恢复 3 字节、全字节字符集的密码。

## 原理

- **正向密钥调度**：ZipCrypto 初始 `Key0=0x12345678`、`Key1=0x23456789`、`Key2=0x34567890`。每处理一个密码字节 `p`：
  ```text
  Key0 = CRC32(Key0, p)
  Key1 = (Key1 + (Key0 & 0xff)) * 0x08088405 + 1   (mod 2^32)
  Key2 = CRC32(Key2, Key1 >> 24)
  ```
  加密数据时每处理一个明文字节 `P`，也执行同样的三步更新；因此密钥状态与“已处理的密码字节 + 明文字节”一一对应。
- **逆向的可行性**：三个更新步骤都是双射（在已知输入/输出之一时）：
  1. `Key2 = CRC32(Key2_prev, MSB(Key1_prev))`：CRC32 的单字节更新可按位反向，给定 `Key2` 和候选字节 `b` 可求 `Key2_prev`；候选 `b = Key1_prev >> 24` 只有 256 种。
  2. `Key1 = (Key1_prev + LSB(Key0_prev)) * 0x08088405 + 1`：先减 1，再乘 `0x08088405` 在模 2^32 下的乘法逆元，得到 `Key1_prev + LSB(Key0_prev)`；`LSB(Key0_prev)` 只有 256 种，枚举即可分离出 `Key1_prev`。
  3. `Key0 = CRC32(Key0_prev, p)`：对候选密码字节 `p`（0x00–0xFF）反向 CRC32，得到 `Key0_prev`。
  三组候选必须同时满足 `Key1_prev` 的最高字节等于步骤 1 的候选、`Key0_prev` 的低字节等于步骤 2 的候选，才能确定该字节；确定后把三个 key 回退一位，继续处理前一个字节。
- **为什么能恢复整个密码**：密码调度是串行的，最后一个密码字节处理完后的 key 状态包含此前所有字节的信息；从该状态逐字节回退即可唯一（或少数候选）恢复密码。若 key 是在加密若干数据字节之后取得的，需要先按已知明文回退数据字节，再回退密码字节；bkcrack 的已知明文攻击会处理这部分。
- **bkcrack 参数**：`-k` 指定已知的三段内部 key；`-r` 进入密码恢复模式，后跟密码长度与字符集。`?b` 表示按全部 256 个字节值枚举（适合二进制密码）；若已知密码只含小写字母/数字，可用 `?l`/`?d` 等缩小空间。具体参数语义以所用 bkcrack 版本的 `-h` 为准。
- **边界**：只适用于传统 ZipCrypto；WinZip AES（method 99）不适用。密码长度/字符集未知时需要扩大枚举范围；key 状态若包含数据字节，必须先按明文回退。

## 触发条件

- 目标 ZIP 使用传统 ZipCrypto 加密（general purpose bit flag bit0=1，compression method 8/0，且没有 AES extra `0x9901`）。
- 已通过 bkcrack 已知明文攻击、zip2john+爆破、内存/流量泄露等方式获得某一时刻的 Key0/Key1/Key2。
- 需要恢复原始密码（例如同一密码还用于其它归档、题目要求密码的 MD5、或需要验证密钥来源）。
- 知道或能限定密码长度与字符集；二进制密码用 `?b`，可打印密码用 `?a`/`?l`/`?d` 等加速。
- 若 key 是在数据加密过程中取得的，已知明文足够回退到密码结束时刻。

## 利用步骤

1. 先用已知明文攻击恢复内部 key（若尚未获得）：
   ```bash
   bkcrack -C purezip.zip -c "secret key.zip" -p key
   ```
   输出形如 `Keys: e63af7cc 55ef839d dc10b922`。
2. 用 `-k` 验证 key 能解密目标条目：
   ```bash
   bkcrack -C purezip.zip -c "secret key.zip" -k e63af7cc 55ef839d dc10b922 -d 1.zip
   ```
3. 若需要原始密码，运行密码恢复：
   ```bash
   bkcrack -k e48d3828 5b7223cc 71851fb0 -r 3 ?b
   ```
   工具会反推密钥调度并输出密码字节（例如 `as bytes: ffffff8b ffffffe7 ffffffdc`，实际取低字节 `8b e7 dc`）。
4. 用恢复出的密码重新生成 key 或直接解压验证；若题目提示“密码是明文的密钥的 MD5，长度为 3 字节”，对 3 字节明文做 MD5，尝试 32 字符 hex 与 16 字节 raw 两种形式作为最终 ZIP 密码。
5. 若密码长度未知，先用小范围长度/字符集试跑，再逐步扩大；bkcrack 会输出尝试的长度区间与找到的密码。
6. 对 2 字节密码也可直接用 Python `zipfile` 枚举 65536 种组合（见 PoC），比通用恢复更快。

## PoC

```bash
# 1) 已知明文攻击恢复内部 key
bkcrack -C purezip.zip -c "secret key.zip" -p key

# 2) 用 key 解密条目（输出的是条目原始数据，若为 deflate 还需 raw inflate）
bkcrack -C purezip.zip -c "secret key.zip" -k e63af7cc 55ef839d dc10b922 -d 1.zip

# 3) 由内部 key 反推密码：3 字节、全字节字符集
bkcrack -k e48d3828 5b7223cc 71851fb0 -r 3 ?b
```

2 字节密码的 Python 枚举（原文思路）：

```python
import zipfile

with zipfile.ZipFile("download.zip", "r") as fz:
    for i in range(256):
        for j in range(256):
            pwd = bytes([i, j])
            try:
                fz.extractall(pwd=pwd)
                print("password:", pwd)
                raise SystemExit
            except Exception:
                continue
```

恢复出 3 字节密码后，按题目提示计算 MD5：

```python
import hashlib
pwd3 = bytes.fromhex("8be7dc")
print(hashlib.md5(pwd3).hexdigest())   # 若题目要 32 字符 hex
print(hashlib.md5(pwd3).digest())      # 若题目要 16 字节 raw
```

## 变体与关联

- **已知明文攻击 → key → 密码**：先用归档内已知文件（≥12 字节）恢复 key，再逆推密码；见 [[ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip]]。
- **zip2john + 已知密码**：若密码已知，可直接按 `$pkzip$` 哈希解密，不必逆推密钥调度；见 [[ctf-forensics-zip2john-pkzip-hash-zipcrypto-stream-decrypt]]。
- **2 字节/短密码**：直接穷举比 bkcrack 反推更简单；长密码/受限字符集则用 `-r <len> <charset>`。
- **嵌套 ZIP**：解密后的条目可能是 deflate 流，需要 raw inflate 才能得到内层 ZIP；见 [[ctf-forensics-bkcrack-d-raw-inflate-nested-zip]]。
- **边界**：AES ZIP 不适用；密码含 `?b` 之外的字符集时需扩展 charset；key 状态含数据字节时先按明文回退。

## 检测与防御

- **安全认知**：ZipCrypto 是弱流密码，已知明文即可恢复内部 key，进而解密所有条目并可能逆推密码；不要用 ZipCrypto 保护敏感数据，改用 AES-256 + 强随机密码。
- **避免已知明文**：归档中不要放入可公开获取/可猜测的文件（模板、图标、已知文档），否则会成为明文攻击的锚点。
- **检测**：识别 ZIP 的加密算法（method 8 + 加密标志 vs method 99 + AES extra）；对包含大量已知文件的归档提高警惕；CTF 中看到 `bkcrack`/`$pkzip$`/三段 key 提示时按本卡流程处理。
