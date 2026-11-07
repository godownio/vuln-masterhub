---
id: ctf-reverse-per-char-salted-md5-bruteforce-decoy-path
title: 逐字符加盐 MD5 爆破：识别 decoy 路径并按位置枚举字符
type: scenario
domain: ctf
path: ctf/reverse
technique: per-char-salted-md5-bruteforce-decoy-path
aliases:
- 逐字符 MD5 爆破
- 加盐 MD5 按位爆破
- decoy flag 路径
- E4sy_P3asy
- 每字符独立哈希
tags:
- ctf
- reverse
- md5
- salt
- bruteforce
- decoy
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T10:01:18+08:00'
  notes: 已对照原文与图 02/04/06 核对：真分支 salt=KnightCTF_2026_s@lt、%s%zu%c 逐字符 MD5、23 个 hash（v16==23）、KCTF{ 前缀；假分支 GoogleCTF{/G00gleCTF_s@lt_2026/13 个 hash 均一致。卡片 PoC 只列 1 个 hash 作示例，需从 .rodata 完整提取；未复跑。
---

## 一句话结论

程序把 flag 的每个字符单独计算 `MD5(salt + str(i) + c)` 并与一张 32 字节 hex 哈希表逐项比较时，每个位置可以独立枚举可打印字符爆破；同时要区分“只打印 decoy flag”的假分支和真正走 `Success! Real flag accepted.` 的真分支，使用正确的 salt/前缀/哈希表。

## 原理

- **逐字符独立哈希**：第 `i` 个字符的校验只依赖 `salt`、`i` 和 `c`，不依赖其他位置，因此不需要笛卡尔积；对每个 `i` 枚举字符集（`string.ascii_letters + digits + punctuation + " _"`），计算 `MD5(f"{salt}{i}{c}")`，命中即恢复该字符。
- **decoy 分支**：程序可能先检查另一个前缀（如 `GoogleCTF{`）和另一套 salt/hash 表，命中后只输出一句“decoy flag”或假 flag，并不进入真正的成功路径；必须用交叉引用/输出字符串定位真正的 `Success! Real flag accepted.` 分支。
- **本题**：假分支使用 `salt="G00gleCTF_s@lt_2026"`、13 个字符、前缀 `GoogleCTF{`，解出 `n0T_tH3_r1GhT_0N3`；真分支使用 `salt="KnightCTF_2026_s@lt"`、23 个哈希、前缀 `KCTF{`，解出 `_L0TS_oF_bRuTE_foRCE_:P`。
- **为什么可行**：MD5 是确定性函数，salt 和 index 已知，字符集只有约 100 个候选；每个位置最多 100 次 MD5，23 个位置几毫秒完成。
- **边界**：若哈希还包含位置之外的滚动状态、或 salt 不是明文常量，按字符独立爆破会失败；需要先恢复 salt/状态或改用动态调试。

## 触发条件

- 反编译中出现 `MD5(input)` 后 `strcmp` 到 hex 字符串表，输入拼接方式为 `salt + index + char` 或类似。
- 哈希表项数等于 flag 中间长度，且每项独立比较。
- 程序存在多个校验分支，其中一个只打印 decoy/假 flag；真正成功字符串是 `Success! Real flag accepted.` 之类。
- salt/前缀/哈希表可从 `.rodata` 直接读取。

## 利用步骤

1. 定位所有校验分支，按成功输出字符串区分真/假；记录每个分支的前缀、salt、长度、哈希表地址。
2. 对真分支，确认哈希拼接格式（`salt + str(i) + c`）和字符集。
3. 逐位置枚举字符，计算 MD5 并与 `hashes[i]` 比较；命中后拼接。
4. 用 `KCTF{...}` 格式和长度校验结果；若某位置找不到，扩大字符集（空格、`!`、`~`、UTF-8 多字节）。
5. 对假分支同样爆破，确认它是 decoy（输出假 flag），不要误交。
6. 必要时用 GDB/IDA 动态断在 `strcmp` 处，直接读期望哈希/输入。

## PoC

```python
import hashlib, string

salt = "KnightCTF_2026_s@lt"
hashes = [
    "781011edfb2127ee5ff82b06bb1d2959",
    # ... 共 23 项，按 .rodata 顺序
]
charset = string.ascii_letters + string.digits + string.punctuation + " _"

out = []
for i, h in enumerate(hashes):
    for c in charset:
        if hashlib.md5(f"{salt}{i}{c}".encode()).hexdigest() == h:
            out.append(c)
            break
    else:
        raise RuntimeError(f"not found at {i}")
print("KCTF{" + "".join(out) + "}")
```

说明：PoC 按原文的 `salt + i + c` 逐字符 MD5 逻辑重写；哈希表需从二进制完整提取。未在本机对附件复跑。

## 变体与关联

- **哈希算法**：SHA-1/SHA-256/CRC32 也可按字符独立爆破；注意输出是 hex 还是 raw。
- **拼接格式**：`salt+i+c`、`salt+c+i`、`c+salt+i`、带分隔符；按反编译字符串格式调整。
- **多字节字符**：UTF-8 中文/emoji 需要按字节或码点枚举，字符集会变大。
- **decoy 识别**：参见 [[ctf-reverse-fnv1a-jumptable-base131-hash]]（跳表分发 + 假 flag 分支）、[[ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse]]（诱饵串识别）。
- **关联**：[[ctf-reverse-right-shift-constraint-md5-bruteforce]]（MD5 约束爆破的另一形式）。

## 检测与防御

- 识别：`.rodata` 中连续 32 字节 hex 字符串表、MD5 常量/调用、按 index 拼接的 `snprintf`。
- CTF 防守方：逐字符独立哈希等价于把 flag 拆成 23 个可独立爆破的字符，安全性很低；应使用整体哈希/HMAC 或 native 校验。
- 真实系统：不要用无迭代的 MD5 存储口令；使用 Argon2/bcrypt/PBKDF2 并加随机 salt。
