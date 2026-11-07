---
id: binary-pwn-sandbox-escape-pickle-byte-flip-long4-short-binunicode-leak
title: Pickle 单字节翻转 LONG4→SHORT_BINUNICODE：把后续字符串字节并入整数回显泄露
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: pickle-opcode-byte-flip-short-binunicode-leak
tags:
- python
- pickle
- ctf
- sandbox-escape
- opcode
- byte-flip
- leak
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:02:23+08:00'
  notes: 已对照原文lost in transit核对：user_data=2^2064+0x014e8b、LONG4(0x8b)→SHORT_BINUNICODE(0x8c)单字节+1、大整数回显含flag，与exp/输出一致；未验证点：未连接远程复跑。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-pickle-byte-flip-long4-short-binunicode-leak/
draft: false
kb_aliases:
- lost in transit
- pickle 字节翻转
- LONG4 SHORT_BINUNICODE
- pickle 反序列化偏移
- radiation alert
---

## 一句话结论

当服务把“用户可控的整数 + 秘密字符串”一起 `pickle.dumps`，又允许攻击者对序列化结果修改任意一个字节后再反序列化时，即使 `find_class` 拒绝所有全局对象、完全没有 RCE，也可以把某个 `LONG4` 操作码递增成 `SHORT_BINUNICODE`，改变后续长度字段的解析方式，让紧随其后的整数载荷把秘密字符串的序列化字节一起吞进一个大整数并回显；把该整数转回字节即可读出秘密。

## 原理

- pickle 协议是“操作码 + 长度 + 数据”的自描述流。`LONG4`（`0x8b`）格式为：1 字节操作码、4 字节小端长度 N、N 字节小端补码整数；`SHORT_BINUNICODE`（`0x8c`）格式为：1 字节操作码、1 字节长度 L、L 字节 UTF-8 字符串。两者操作码只差 1。
- 服务端逻辑是 `pickle.dumps((user_int, flag))`，随后对序列化字节做 `dumped[attacker_index] += 1` 再 `load()`。攻击者知道 flag 长度（题中 `assert len(flag) == 79`），也可以精确构造 `user_int` 的低位字节。
- 构造 `user_int` 使其序列化后的 `LONG4` 操作码后面紧跟可控的长度字节与载荷字节；把 `0x8b` 递增为 `0x8c` 后，反序列化器把原来的 `LONG4` 当作 `SHORT_BINUNICODE` 读取，消耗掉少量字节；随后遇到的第一个载荷字节被重新解释为新的 `LONG4` 操作码，其 4 字节长度被构造成足以覆盖“剩余整数载荷 + 后面 flag 的 `SHORT_BINUNICODE` 头和内容”。
- 于是这个大整数对象的 little-endian 字节表示里就包含了 `\x8c <len> flag{...}` 的原始序列化片段。服务把元组的第一个元素（该整数）以十进制打印出来，攻击者再把十进制转回 little-endian 字节，即可在字节流中看到 flag 明文。
- 关键点：绕过并不依赖执行任何代码，而是利用“解析器把攻击者数据与秘密数据放进同一个长度域”这一点，把秘密变成攻击者可观测的数据值。`find_class` 返回 `'no'` 也阻止不了信息泄露。

## 触发条件

- 服务端把秘密与攻击者可控数据放进同一个 pickle 流（通常是元组/列表的相邻元素）。
- 攻击者可选择要递增的字节下标，且只能加 1（或改动幅度受限）。
- 反序列化结果至少有一部分会回显（本例为元组第一个元素 `info` 的十进制打印）。
- 秘密的长度已知或可枚举，且其序列化位置相对可控整数可预测。

## 利用步骤

1. 分析服务端 pickle 结构，确认秘密字符串在流中的位置（`SHORT_BINUNICODE` 头 + 长度 + 内容）以及可控整数使用的整数操作码。
2. 构造一个足够大的正整数，使其序列化采用 `LONG4`，并把低位字节布置成后续能被重新解释为长度域的值。题中构造为：
   ```python
   user_data = (1 << (0x0102) * 8) + pickle.LONG4[0] + (0x014e << 8)
   ```
   即 `2^2064 + 0x014e8b`，其 `LONG4` 载荷低字节为 `8b 4e 01 00 ...`。
3. 本地生成同样的 `pickle.dumps((user_data, flag_placeholder))`，找到第一个 `0x8b` 的下标（即 `LONG4` 操作码位置），作为 radiation 下标提交。
4. 服务把该字节加 1 变成 `0x8c`，反序列化后返回一个大整数；把十进制整数转成 little-endian 字节。
5. 在字节中定位 `jail{...}` 或目标 flag 格式；若整数长度不对，微调 `user_data` 的高位/长度字段，使第二个 `LONG4` 恰好吞掉 flag 内容。

## PoC

```python
import pickle

# 题中服务端：flag 长度 79；user_data 由用户输入
user_data = (1 << (0x0102) * 8)
user_data += pickle.LONG4[0]
user_data += (0x014e) << 8

flag = 'A' * 79  # 本地占位；远程由服务端真实 flag 填充
dumped = list(pickle.dumps((user_data, flag)))
idx = dumped.index(0x8b)
print('user_data =', user_data)
print('radiation index =', idx)
```

```text
# 远程交互：
# favorite number > <user_data 十进制>
# radiation alert! > <idx>
# here is your info: <巨大的十进制整数>, {}
#
# 本地还原：
# python -c "from Crypto.Util.number import long_to_bytes; \
#   print(bytes(reversed(long_to_bytes(<打印出的十进制整数>))))"
# 输出字节的尾部包含 b'\x01\x8c\x4f' + b'jail{...}'
```

## 变体与关联

- 其他操作码对：`BININT`/`BININT1`、`LONG1`/`LONG4`、`BINUNICODE`/`SHORT_BINUNICODE` 之间只差少量数值，单字节递增/递减都可能改变长度域解释；关键是找到“可控长度字段 + 相邻秘密”的布局。
- 若只能改一个 bit 而不是加 1，可寻找仅差 1 bit 的操作码对，或利用长度字段的低位翻转使解析器多吞/少吞字节。
- 关联：[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（受限 unpickler 的代码执行绕过）、[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]（pickle 黑名单的另一类绕过）。
- 边界：若秘密不以明文出现在序列化流中（例如先加密/压缩），或服务端不回显任何反序列化结果，本手法只能造成解析异常，无法泄露。

## 检测与防御

- 检测：禁止把秘密与不可信数据放在同一序列化对象中；对“允许外部指定字节偏移并修改序列化数据”的接口直接视为高危；监控 pickle 流中出现 `0x8b`/`0x8c` 等长度域密集的操作码组合及异常 `UnpicklingError`。
- 修复：不要对攻击者可控的序列化字节做部分修改后再反序列化；秘密单独存放、单独鉴权读取；对 pickle 使用 HMAC/签名并在反序列化前校验完整性。
- 加固：反序列化在无秘密的子进程中执行；返回错误时只给通用提示，不打印元组内容或大整数；限制单次请求的序列化长度与可修改范围。
