---
id: crypto-hash-md5-digest-strcmp-nullbyte-truncation
title: MD5 二进制摘要用 strcmp 比较：空字节截断只需碰撞 3 字节前缀
type: scenario
domain: crypto
path: crypto/hash
technique: md5-digest-strcmp-nullbyte-truncation
aliases:
- MD5 摘要比较
- strcmp 截断
- 哈希前缀碰撞
- 二进制摘要比较
tags:
- crypto
- hash
- md5
- strcmp
- null-byte
- auth-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:41:58+08:00'
  notes: 已对照原文与图02（GDB strcmp@plt：s2=0x7c994fe632004064）核对：期望摘要16字节为64 40 00 32 e6 4f 99 7c ac 1e ca 67 59 44 30 a4，strcmp遇第3字节0x00截断，只需MD5前3字节=64 40 00；OnkI的MD5=6440001ddb3fb9ab106b55f74f7dbd01与原文一致。原文为CTF题解，PoC未复跑；无组件影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

程序把 16 字节 MD5 原始摘要直接当 C 字符串用 `strcmp` 与常量比较时，比较会在摘要中第一个 `0x00` 字节处停止；若期望摘要的第三字节就是 `0x00`，攻击者只需找到一个 MD5 前 3 字节为 `64 40 00` 的用户名即可通过认证，而无需碰撞完整 128 位摘要。

## 原理

- `MD5()` 输出 16 字节二进制摘要，通常包含不可打印字节甚至 `0x00`。正确比较应使用 `memcmp(digest, expected, 16)` 或先转成 hex 字符串再比较。
- 若代码写成 `strcmp(md5_digest, expected_digest)`，`strcmp` 把两块内存都当作以 `\0` 结尾的 C 字符串：遇到第一个 `0x00` 就认为字符串结束，后续字节完全不参与比较。
- 示例中期望摘要常量按小端内存布局为 `64 40 00 32 E6 4F 99 7C AC 1E CA 67 59 44 30 A4`；`strcmp` 只比较到第三字节的 `0x00`，实际要求退化为“MD5 的前 3 字节等于 `64 40 00`”。
- 3 字节前缀空间只有 2^24，用字母数字短字符串暴力搜索通常很快就能找到；文章找到的用户名是 `OnkI`，其 MD5 为 `6440001ddb3fb9ab106b55f74f7dbd01`。
- 该用户名随后被拼进 `rtsp://<username>/...` 的 URL，通过用户名校验后即可进入后端功能（堆操作等），把认证绕过转化为后续漏洞利用入口。

## 触发条件

- 代码用 `strcmp`/`strncmp`（长度不足）比较 MD5/SHA 等二进制摘要，而不是 `memcmp` 或 hex 字符串。
- 期望摘要常量在较早位置包含 `0x00`（本例为第 3 字节），使有效比较前缀很短。
- 攻击者能控制被哈希的输入（用户名、口令、路径等），并能多次尝试。
- 目标没有对输入做严格格式限制，或允许字母数字组合。
- 摘要常量可从二进制/流量中提取，或已知目标值。

## 利用步骤

1. 逆向认证逻辑，确认 `MD5(input)` 的输出直接传入 `strcmp`/`strncmp`，并定位期望摘要常量。
2. 按小端序把常量还原为字节串，找到第一个 `0x00` 的位置，确定实际需要碰撞的前缀长度（示例 3 字节）。
3. 用短字母数字串枚举，计算 MD5 并比较前缀；命中后记录该输入（示例 `OnkI`）。
4. 将该输入作为用户名/参数发送，通过摘要比较；随后继续走正常业务逻辑（如 RTSP URL 的 `rtsp://<username>/...`）。
5. 若认证后还有后续校验，按业务协议继续构造请求。

## PoC

```python
import hashlib, itertools, string

target = b"\x64\x40\x00"          # 期望摘要的前 3 字节（到第一个 0x00）
alphabet = string.ascii_letters + string.digits

for n in range(1, 6):
    for x in itertools.product(alphabet, repeat=n):
        s = ''.join(x).encode()
        if hashlib.md5(s).digest()[:3] == target:
            print("found:", s, hashlib.md5(s).hexdigest())
            raise SystemExit
# found: b'OnkI' 6440001ddb3fb9ab106b55f74f7dbd01
```

## 变体与关联

- 变体：期望摘要第一个字节就是 `0x00` 时，`strcmp` 直接判定相等（空串比较），任何输入都能通过；可用小端常量布局判断。
- 变体：`strncmp(digest, expected, n)` 长度小于摘要长度时，只比较前 n 字节，同样可暴力/碰撞。
- 变体：SHA1/SHA256 等二进制摘要被 `strcmp` 比较时同理，只是前缀长度不同；hex 字符串比较没有该问题。
- 关联：[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（另一类“常量校验被离线复现”的问题）、[[binary-pwn-stack-strcmp-nullbyte-local-ptr-backfill-ret2text]]（C 字符串 `\0` 截断在栈溢出登录绕过中的同类利用）。

## 检测与防御

- 检测：代码审计搜索 `strcmp`/`strncmp` 的实参是否为哈希函数输出；静态扫描二进制摘要常量与字符串比较的组合。
- 修复：二进制摘要一律用 `memcmp(digest, expected, digest_len)` 或常量时间比较函数；需要字符串比较时先转 hex 并固定长度。
- 加固：不要硬编码摘要作为唯一认证因子；使用 HMAC/口令哈希（bcrypt/Argon2）并配合随机盐；对认证失败限速与告警。
