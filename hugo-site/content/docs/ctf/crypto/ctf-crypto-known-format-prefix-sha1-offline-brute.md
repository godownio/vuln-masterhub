---
id: ctf-crypto-known-format-prefix-sha1-offline-brute
title: 已知格式前缀的 SHA1 哈希离线爆破：40 位 SHA1 + 11 位手机号前 3 位，枚举后 8 位数字命中即得完整号码
type: scenario
domain: ctf
path: ctf/crypto
technique: known-format-prefix-sha1-offline-bruteforce
tags:
- ctf
- crypto
- hash
- sha1
- bruteforce
- known-plaintext
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:17:26+08:00'
  notes: 已对照 16579 原文与 img/15-16 核对：目标 ca12fd8250972ec363a16593356abb1f3cf3a16d、188 前缀 + 后 8 位补零枚举、命中 flag{18876011645} 均一致；未验证点：未实际跑 10^8 枚举复核哈希
url: /docs/ctf/crypto/ctf-crypto-known-format-prefix-sha1-offline-brute/
draft: false
kb_aliases:
- 通往哈希的旅程
- 188 开头手机号 SHA1
- 已知前缀哈希爆破
- 40 位 SHA1 判型
- 后 8 位数字枚举
---

## 一句话结论

题目给出一个 40 位十六进制串和一个“188 开头的 11 位纯数字手机号”的提示：40 位长度即 SHA1 摘要，前 3 位已知，只有后 8 位未知（`10^8` 空间），直接 `for suffix in range(10**8)` 计算 `sha1(f"188{suffix:08d}")` 与目标比对，命中即得完整号码并提交 `flag{11位号码}`。

## 原理

- **哈希长度判型**：十六进制摘要长度对应算法——32 位 MD5、40 位 SHA1、64 位 SHA256、96 位 SHA384、128 位 SHA512。本题 40 位即 SHA1；这一步避免了对不可逆摘要做无意义的“解密”尝试。
- **已知格式把空间压到可枚举**：明文是 11 位纯数字手机号（前 3 位固定为 `188`），未知只有后 8 位，空间 `10^8 = 1 亿`；单机 Python 用 `hashlib.sha1` 每秒约 1e5~1e6 次，几十秒到十几分钟可穷尽；用 hashcat `-m 100`（SHA1）+ mask `188?d?d?d?d?d?d?d?d` 更快。
- **为什么不需要盐/彩虹表**：题目用的就是裸 `sha1(明文)`，没有盐与迭代；彩虹表只覆盖常见口令，不覆盖“手机号”这种结构化长数字，所以定向枚举比查表更有效。
- **格式化补零**：`f"188{suffix:08d}"` 保证 8 位不足时补前导零（如 `00001234`），否则会漏掉号码中含前导零的候选；这一点是脚本正确性的关键。
- **验证与提交**：命中后得到完整 11 位号码；题面要求提交 `flag{11位号码}`，说明该值本身就是答案，不需要再解密别的密文。

## 触发条件

- 给出固定长度的十六进制摘要，且能据长度判断算法（40=SHA1）。
- 明文格式已知或部分已知（如手机号前缀、日期、编号规则），使未知空间可枚举。
- 哈希为无盐、单次计算（否则需要按目标算法的迭代/加盐参数复现）。
- 允许离线计算（不依赖在线接口/不会被限速）。

## 利用步骤

1. 数摘要长度（40 位）→ 判定 SHA1；确认明文格式（188 开头、11 位纯数字）。
2. 计算未知位数：11-3=8，空间 `10^8`；估算耗时（Python 约 1e5/s，必要时用 hashcat 或 PyPy）。
3. 写脚本枚举 `range(10**8)`，`f"188{suffix:08d}"` 计算 SHA1 与目标比对，命中立即返回并 break。
4. 用命中号码按题面格式提交（`flag{号码}`）；可再用一次 `hashlib.sha1(号码.encode()).hexdigest()` 复核结果。

## PoC

```python
import hashlib

def sha1_crack(target_hash: str, prefix: str = "188") -> str | None:
    for suffix in range(10 ** 8):                 # 00000000 .. 99999999
        number = f"{prefix}{suffix:08d}"          # 11 位，不足补零
        if hashlib.sha1(number.encode()).hexdigest() == target_hash:
            return number
    return None

if __name__ == "__main__":
    target = "ca12fd8250972ec363a16593356abb1f3cf3a16d"
    r = sha1_crack(target)
    print(f"flag{{{r}}}" if r else "not found")
```

等价的 hashcat 写法（更快）：

```bash
hashcat -m 100 -a 3 target.txt 188?d?d?d?d?d?d?d?d --quiet
```

## 变体与关联

- 变体：明文是日期（`YYYYMMDD`）、身份证（前 6 位地区码已知）、工号/学号规则，同样把空间压到可枚举；位数越多越要用 mask/GPU。
- 变体：摘要长度不是标准值（如 40 位但带前缀 `sha1:`），先剥前缀；若是 HMAC-SHA1 则需要密钥，不能用本方法。
- 变体：若目标哈希对应多个候选（碰撞或格式歧义），用题面其它约束（号段、校验位）二次筛选。
- 关联：[[ctf-misc-firmware-eeprom-byte-transform-bruteforce-flag]]（同为小空间枚举还原明文）、[[ctf-reverse-java-string-hash-8digit-bruteforce]]（固定位数枚举匹配哈希）、[[crypto-hash-sha256-length-extension-append-field]]（哈希类攻击的另一方向）、[[web-generic-auth-sms-code-md5-hash-response-offline-bruteforce]]（有限空间哈希枚举的 Web 侧应用）。
- 边界：本方法只适用于“无盐 + 明文空间可枚举”；真实口令哈希应使用 bcrypt/argon2 等慢哈希并加盐，1 亿空间的暴力将不可行。

## 检测与防御

- 检测（出题/业务侧）：不要把“结构化、可枚举”的值（手机号、编号、日期）直接用裸 SHA1/MD5 当保密标识；这类摘要等价于明文可枚举。
- 修复（真实系统）：口令与标识一律用带盐慢哈希（bcrypt/scrypt/argon2id），并对可枚举输入加速率限制与服务端 pepper。
- 加固：对返回给客户端的哈希类字段做脱敏；对“按编号/手机号查哈希”的接口增加鉴权与频率控制。
