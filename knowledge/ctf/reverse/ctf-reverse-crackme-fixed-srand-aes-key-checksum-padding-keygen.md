---
id: ctf-reverse-crackme-fixed-srand-aes-key-checksum-padding-keygen
title: Crackme 注册机：固定种子 srand 派生可预测 AES 密钥 + 对密文的校验和用填充字段暴破满足
type: scenario
domain: ctf
path: ctf/reverse
technique: fixed-seed-aes-key-checksum-padding-keygen
aliases:
- 固定种子 AES 密钥
- srand(0x12345678) 可预测
- 校验和 padding 暴破
- crackme keygen
- AES-128 ECB 序列号
tags:
- ctf
- reverse
- crackme
- keygen
- aes
- srand
- fixed-seed
- checksum
- brute-force
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:12:04+08:00'
  notes: 已对照原文与 6 图核对：图 01 主流程 fgets/FUN_00401280 正则/FUN_00401312 取字段/CheckNameKey；图 02 sscanf %02x 循环 16 次转 sn_key；图 03 前 12 字节(3 个 DWORD 高低字节)求和与 sn_key[3](高/低字节)比较；图 04 srand(0x12345678)+rand 取低字节 16 次；图 05 FUN_00408d24 密钥扩展 + FUN_0040a1b6 解密；图 06 DAT_004153f4&0xffff0000==0x19790000 与用户名 hash 比较。keygen 已实测输出合法 key。与 keygenme4/keygenme-xtea 等卡均 related 但约束与解法不同，不合并。
---

## 一句话结论

某 Windows crackme 用 `srand(0x12345678)` 固定种子生成 16 字节「随机数」当作 AES-128 密钥，使密钥可预测；校验要求输入 key 的字节满足「前 12 字节之和的低/高 8 位分别等于 key[15]/key[14]」，且解密后的明文含固定魔术字节 0x1979。于是 keygen 只需构造明文（用户名 hash + 特性位 + 0x1979 + 序列号 + 填充）、用该固定密钥 AES 加密，并暴力递增填充字段直到密文满足校验和，即可为任意用户名生成合法序列号。

## 原理

- 固定种子 ⇒ 密钥公开：`srand(0x12345678)` 后连续 `rand()` 取低字节生成 16 字节，序列恒定（本例为 16 个固定字节）。PRNG 不是真随机、种子硬编码，攻击者可在自己环境重放得到同一 AES 密钥，「密钥」退化为公开常量。这是整条链能离线构造的前提。
- 校验和是对**密文**的线性约束：程序把 key 字符串按 `%02x` 转成 16 字节 `sn`，先算前 12 字节之和 `S`，要求 `(S & 0xff) == sn[15]` 且 `((S >> 8) & 0xff) == sn[14]`。它检查的是加密输出，而不是有意义的明文字段。
- 算法识别：`FUN_00408d24` 是 AES 密钥扩展、`FUN_0040a1b6` 是 AES 解密，密文就是输入的 key；大段常数表/S 盒、密钥扩展结构是 AES 指纹（PEiD Krypto 插件、常数检索、找 T 表）。把它当自写算法硬啃会浪费大量时间——先识别标准算法是关键一步。
- 解密后明文结构（16 字节，AES-128-ECB 恰好一段）：4 字节 username hash（由 `FUN_00401000` 计算）+ 2 字节 feature 位（每 bit 一个开关）+ 2 字节 magic 固定 0x1979 + 4 字节 serial（程序不校验、只展示，可自定）+ 4 字节填充（不校验）。
- 为什么 padding 暴破有效：校验和只依赖 16 字节密文，而密文 = AES(key, 明文)。填充字段是明文里唯一自由且不影响其它语义的 4 字节；递增它 → 密文整体改变 → 校验和随之变化。AES 是置换，改明文必然改密文，所以枚举填充等价于枚举校验和输出，不需要破 AES；约束是 2 个字节（约 2^16 量级），平均很快命中目标对 `(S&0xff, S>>8&0xff)`。
- 为什么是完整链：得到固定密钥 + 知道明文布局 + 可枚举填充满足校验和，三者合起来能为任意用户名产出通过程序校验的 key，实测 keygen 输出合法 N/K 对。

## 触发条件

- 程序用固定种子 PRNG 或硬编码常量派生对称密钥；
- 校验约束作用在攻击者可控的加密输出上（而非服务端/不可控数据）；
- 明文中留有不影响语义、可自由枚举的字段（填充/序列号），且分组长度与结构对齐（AES 16 字节一段）；
- 用户名 hash 算法可得（能重写或二进制复用）；
- 对称算法与模式已识别（此处 AES-128-ECB）。

## 利用步骤

1. 逆向定位校验函数，确认 key 的字节转换（`%02x`）与校验和公式（前 12 字节和 → key[14]/key[15]）。
2. 找密钥生成处，识别固定种子/硬编码常量，复现 16 字节密钥。
3. 用常数表/密钥扩展结构识别标准算法，确定模式与分组长度。
4. 逆出解密后明文的字段布局与固定魔术字节（0x1979）。
5. 构造明文，AES 加密成 key，循环递增 padding 直到通过校验和，输出 key。

## PoC

```python
from Crypto.Cipher import AES
import struct

KEY = bytes([0xE9,0x3F,0x0D,0xA1,0x96,0x95,0x31,0x04,
             0x49,0x2D,0x9E,0x61,0x83,0xCF,0x09,0x6F])  # srand(0x12345678) 固定序列

def check(sn):
    s = sum(sn[:12])
    return (s & 0xff) == sn[15] and ((s >> 8) & 0xff) == sn[14]

def keygen(name_hash, features=0x1979FFFF, serial=0xbeefbeef):
    cipher = AES.new(KEY, AES.MODE_ECB)
    patch = 0
    while True:
        data = struct.pack('<IIII', name_hash, features, serial, patch)
        sn = cipher.encrypt(data)
        if check(sn):
            return sn.hex()
        patch += 1
```
（name_hash 由目标函数计算，可重写或用「二进制机器码编译成 .so」的方式复用，见同篇另一卡。）

## 变体与关联

- 变体：约束换成 CRC/某几字节哈希、约束落在明文而非密文（则直接构造无需暴破）、CBC/多分组、种子来自时间戳但可爆破、magic 与 feature 位位置变化。
- 关联：固定种子 PRNG 可预测性、标准算法常数识别、二进制代码复用（把 namehash 机器码编译成 .so 调用）。

## 检测与防御（软件保护视角）

- 不要用固定种子/硬编码常量派生密钥；密钥与校验逻辑分离，序列号校验放服务端在线完成。
- 校验应作用于有意义的明文，避免「对密文做线性校验和」这种可被枚举绕过的结构；不要自创弱校验叠加在标准算法外。
- 关键序列号做在线激活与绑定，避免纯本地离线可算。
- 分析侧提示：遇到大段常数表先做算法识别（Krypto 插件、常量检索、密钥扩展结构），别把 AES 当自写算法；确认是否有固定种子 PRNG，可极大缩短 keygen 路径。
