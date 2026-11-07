---
id: ctf-crypto-blackbox-chosen-input-mapping
title: 黑盒加密选择明文建表：构造非线性输入让密文保持一一映射，再查表解 flag
type: scenario
domain: ctf
path: ctf/crypto
technique: blackbox-chosen-plaintext-mapping-table
aliases:
- 小蓝鲨的密码箱
- 黑盒加密
- 选择明文建表
- 密文到明文字符映射
- 非线性输入
- 密码表
tags:
- ctf
- crypto
- blackbox
- chosen-plaintext
- substitution
- mapping
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:28:21+08:00'
  notes: 已对照原文小蓝鲨的密码箱核对：93 字符表、cipher_hex/flag_hex 全量数据、密文值→明文字符映射与 flag 一致；已补全原文截断的密文数据并修正 90→93 字符；算法黑盒、映射来自原文，未复跑
---

## 一句话结论

当加密逻辑是黑盒、但可对任意输入查询且算法确定时，可用已知字符表逐字符查询，建立“密文值 → 明文字符”的一一映射；若输入高度共线会导致多个明文字符对应同一密文，则改用高度非线性的输入让密文保持可区分，最后用映射表逐值翻译 flag 密文。

## 原理

- **确定性黑盒 = 可建表**：若加密函数对相同输入总是产生相同输出，攻击者可以把它当作一个未知的替换表；对受控明文查表，记录输出即可反查。
- **共线性问题**：题目参数 a、b、c 在某些取值下高度共线（例如线性相关/比值固定），不同明文字符可能产生相同或相近的密文，导致“一个密文字节对应多个明文字符”，映射不唯一。
- **非线性输入**：选择使 a、b、c 高度非线性的输入（例如让参数之间无简单比例关系、跨越不同数量级），可以让密文分布分散、每个字符的密文值唯一，从而恢复一一映射。
- **建表与翻译**：把明文空间（示例大小写字母+数字+符号共 93 个字符）逐个加密，得到 `cipher_value -> plain_char` 的字典；对 flag 密文的每个值查表，缺失值标记为 `?` 并单独分析。
- **为什么可行**：黑盒只隐藏算法，不隐藏“输入-输出”可查询性；在密钥固定、无随机化的情况下，替换表就是完整的解密能力。

## 触发条件

- 存在加密 oracle（接口/程序/函数），可提交任意明文并得到对应密文。
- 加密是确定性的（同一输入同一输出），且密钥/参数在会话内固定。
- 明文空间较小且已知（字母、数字、符号、flag 字符集），flag 使用同一字符集。
- 可以通过调整输入参数（示例 a、b、c）避免共线碰撞，保持密文可区分。
- 有足够的查询次数建表。

## 利用步骤

1. 确认 oracle 的输入格式与输出编码（示例输出为 16 进制整数列表）。
2. 先用一组高度共线的输入测试，观察是否出现同一密文对应多个明文字符的碰撞。
3. 调整输入参数为高度非线性，重复测试直到密文值在已知字符表上基本唯一。
4. 对字符表中的每个字符查询一次，记录 `cipher_value -> char`，检查映射冲突。
5. 对 flag 密文逐值查表；对未出现的值，单独查询/插值或分析其生成规律。
6. 拼接得到 flag；若仍有少量缺失，可扩大字符表或结合频率/格式约束补全。

## PoC

```python
from collections import OrderedDict

plain = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
         "{}!@#$%^&*()_+-=`,./<>?;':\"[]\\|")

cipher_hex = "96 123 ea ba c0 c3 cf 03 99 de 45 24 ae 132 102 48 e4 4b 108 00 c6 0f 18 b4 d8 117 a2 2d 12f 9f 4e 6c 13e 63 21 138 3f 87 5d 1b 81 12 30 120 90 51 11d 3c 1e 135 ed f6 54 a5 ab 15 93 12c 69 114 11a 06 b1 e7 e1 72 7b f0 fc 8a ff 129 d5 9c 60 0c 84 75 42 57 09 f3 cc 13b 27 78 105 2a 126 10e d2 c9 a8"
flag_hex   = "99 108 ea 00 c3 b1 54 a2 12f 06 15 2d ab 69 84 ab 12c 93 a5 84 15 a5 4e 69 84 11a 93 9f 9f 84 54 9f ab 2d 54 114 a2 54 2d 93 6c 06 e7"

def hex_str_to_ints(s):
    return [int(h, 16) for h in s.split()]

def build_mapping(plain_chars, cipher_ints):
    mapping = OrderedDict()
    for ch, val in zip(plain_chars, cipher_ints):
        if val in mapping and mapping[val] != ch:
            raise ValueError(f"密文值 0x{val:03x} 映射冲突")
        mapping[val] = ch
    return mapping

mapping = build_mapping(plain, hex_str_to_ints(cipher_hex))
flag = "".join(mapping.get(v, f"?{v:03x}") for v in hex_str_to_ints(flag_hex))
print(flag)
```

输出：

```text
ISCTF{1ac04b37-3652-42e7-95dd-1d3b18a1b5f0}
```

## 变体与关联

- 选择密文变体：若能提交密文并观察解密/错误，可做选择密文攻击或填充预言机。
- 统计分析变体：若不能任意查询，可用频率分析、已知明文/格式约束恢复替换表。
- 碰撞处理变体：若无法消除共线碰撞，可对同一字符用多组不同参数查询，取交集/多数投票确定映射。
- 关联：[[ctf-crypto-semi-adfgx-5x6-polybius-hillclimb-substitution]]（替换表恢复）、[[ctf-crypto-single-byte-seed-recurrence-stream-cipher-bruteforce]]（密钥空间枚举）。
- 边界：加密带随机化/nonce、每次查询参数变化、或明文空间过大时，建表不可行。

## 检测与防御

- 检测：CTF 中提供加密接口且算法未公开；输出随输入确定变化；字符集为常见 flag 字符。
- 防御：不要向不可信方暴露固定密钥的加密 oracle；使用随机化加密（OAEP、AEAD、随机 IV）使相同明文产生不同密文。
- 加固：限制查询频率与参数控制；对 oracle 输入做范围校验；密钥定期轮换。
