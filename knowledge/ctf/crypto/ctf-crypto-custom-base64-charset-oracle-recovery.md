---
id: ctf-crypto-custom-base64-charset-oracle-recovery
title: 自定义 Base64 字符集还原：AA+X 探测第 4 字符反推 64 字符索引表
type: scenario
domain: ctf
path: ctf/crypto
technique: custom-base64-charset-oracle-recovery
aliases:
- 自定义 base64 字符集爆破
- base64 换表还原
- AA+X 探测
- Base64 编码 oracle 字符集恢复
- byte3 % 64 索引
tags:
- ctf
- crypto
- base64
- chosen-input
- oracle
- charset
- encoding
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:13:20+08:00'
  notes: 已对照原文与图核对：AA+X 探测、第 4 字符索引=X&0x3f、33-96 共 64 次、提交字符表一致；未复跑服务。
---

## 一句话结论

当服务用自定义 64 字符表做 Base64 编码并提供编码 oracle 时，发送 `AA` + 一个可打印字符 X（共 3 字节），输出第 4 个字符的索引恰好等于第 3 字节的低 6 位（`X & 0x3f`）；用 64 个连续 ASCII 字符探测一遍，就能建立“索引 → 密文字符”的完整映射，还原字符集并提交。

## 原理

- **Base64 分组**：3 个输入字节共 24 位，按 6 位切成 4 组，分别作为 4 个字符在字符表中的索引。
- **第 4 组的来源**：第 1、2 字节共 16 位，只影响前 3 组；第 4 组完全由第 3 字节的低 6 位构成。因此固定前两字节为 `AA`，改变第 3 字节 X，第 4 个输出字符的索引就是 `X % 64`（等价于 `X & 0x3f`）。
- **为什么用 64 个连续值**：`X % 64` 的取值覆盖 0–63；取 64 个连续可打印 ASCII（如 33–96）即可让每个索引恰好出现一次，且不会引入 `=` 填充（3 字节输入编码后必为 4 个字符）。
- **反推字符表**：对每个 X，记录输出第 4 个字符 `c`，令 `charset[X % 64] = c`；遍历完 64 个 X 后得到完整字符表。若某个索引重复/缺失，说明输入被过滤、编码器有特殊处理或输出长度异常，需要跳过并补测。
- **提交与利用**：题目通常分两步——先交互式探测字符表，再提交完整字符表换取 flag；也可以在本地用还原出的表解码给定的密文。
- **数学本质**：Base64 是 6 位分组映射，`64 = 2^6`，所以 `% 64` 与取低 6 位等价；这也是为什么只改第 3 字节就能独立控制第 4 个字符。

## 触发条件

- 服务使用非标准 Base64 字符表（自定义 alphabet/换表），且允许攻击者提交任意短输入并返回编码结果。
- 编码器对 3 字节输入不添加 `=` 填充（或输入长度是 3 的倍数）。
- 攻击者能进行至少 64 次探测（通常有交互式菜单/无限次输入）。
- 目标字符表由 64 个互不相同的可打印字符组成，未做额外混淆（如位置相关换表）。

## 利用步骤

1. 确认是“编码 oracle”：发送 `AAA`，观察返回 4 个字符；发送 `AAB`，观察第 4 个字符变化。
2. 依次发送 `AA` + `chr(i)`（i 从 33 到 96），读取返回的第 4 个字符；记录 `charset[i & 0x3f] = c`。
3. 校验：64 个索引是否全部覆盖、字符是否互不重复；若有缺失，扩大/调整探测范围补测。
4. 拼接 `charset[0..63]` 得到完整字符表。
5. 按题目要求提交字符表（或用它解码目标密文）获取 flag。
6. 若服务把探测输入做了 URL/JSON 转义，注意选择不会被过滤的可打印字符区间。

## PoC

```python
from pwn import remote

HOST, PORT = "target", 1337
p = remote(HOST, PORT)

p.recvuntil(b"Choose an option (1/2): ")
p.sendline(b"1")
p.recvuntil(b"> ")

charset = {}
for i in range(33, 97):          # 64 个连续可打印字符
    p.sendline(("AA" + chr(i)).encode())
    p.recvuntil(b"Result: ")
    out = p.recvline().strip().decode()
    if len(out) < 4 or out[3] == "=":
        continue
    charset[i & 0x3f] = out[3]

final = "".join(charset[k] for k in range(64))
assert len(set(final)) == 64
print(final)

p.sendline(b"!q")
p.recvuntil(b"Choose an option (1/2): ")
p.sendline(b"2")
p.recvuntil(b"Your charset guess: ")
p.sendline(final.encode())
print(p.recvall(timeout=2).decode(errors="replace"))
```

说明：PoC 为原文脚本的最小化复现，未在本机执行；原文用 `AA+X` 探测 64 次还原字符表并提交拿到 flag。

## 变体与关联

- 变体（探测位置）：固定前两字节改第 3 字节看第 4 字符；固定后两字节改第 1 字节看第 1 字符；利用不同分组位置恢复更多映射。
- 变体（编码）：换表 Base64、Base32/Base58 自定义 alphabet、ROT 后的字符表、按位置轮换的字符表（需分别探测）。
- 变体（利用）：还原字符表后解码密文；结合已知明文/选择明文恢复密钥；用于绕过只允许特定字符集的过滤器。
- 关联：[[crypto/classical]]（古典替换密码）；[[ctf-crypto-blackbox-chosen-input-mapping]]（黑盒选择输入映射）；[[ctf-crypto-repeating-xor-key-known-plaintext-oracle]]（选择明文 oracle）；[[web-python-base64-padding-parser-differential-command-injection]]（Base64 实现差异）。
- 边界：字符表很短/有重复、编码器对输入做位置相关变换、探测次数受限、或输出不返回第 4 字符时，需要改用其他 oracle 或更多假设。

## 检测与防御

- 检测：短时间内大量 `AAx` 形式的短输入、每次只变一个字符；返回的第 4 字符呈系统性映射；交互式菜单被脚本高频调用。
- 防御：不要把自定义字符表当作秘密；使用标准算法与固定字符表；对编码 oracle 做速率限制/鉴权；避免向不可信输入暴露可用于逐位探测的编码接口。
