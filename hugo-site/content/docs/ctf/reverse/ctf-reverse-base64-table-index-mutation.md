---
id: ctf-reverse-base64-table-index-mutation
title: Base64 换表 + 索引魔改还原：先映射回标准表再按 key 逆运算
type: scenario
domain: ctf
path: ctf/reverse
technique: base64-variant-table-index-mutation
tags:
- ctf
- reverse
- base64
- base58
- custom-encoding
- table-permutation
- index-mutation
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:54:46+08:00'
  notes: 已对照原文 base64换表/base58换表/base64魔改三节与图 01-02、19 核对：标准表与变表 ZYX...、索引 ^0x15、密文与 SDPCSEC{th1s_7s_A_g1ft_f0r_new_Reverser}、变表交换生成 CDAB...、key=[1,2,3,4] 的加法变体及 (idx-key)&0x3f 注意事项均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-base64-table-index-mutation/
draft: false
kb_aliases:
- Base64 换表
- Base64 变表
- 索引异或 0x15
- 索引加 key mod 64
- 魔改 Base64
- base58 换表
---

## 一句话结论

魔改 Base64 通常只改两层：64 字符表（换表）和 6 位索引变换（异或/加 key）。解密时先在题目表中定位密文字符得到变表索引，按加密的逆运算还原成标准 Base64 索引，再交给标准库解码；用“重新编码回密文”做闭环即可确认方向没写反。

## 原理

- **Base64 把每 3 字节拆成 4 个 6 位索引**，再用 64 字符表把索引映射成字符；`=` 只做尾部填充，不在表中。
- **换表**：题目把标准表替换成另一张 64 字符排列，例如 `ZYXABC...`；解密时用 `变表.index(ch)` 得到索引，再映射到标准表。
- **索引魔改**：在查表前/后对索引做变换。示例一是 `table[standard_index ^ 0x15]`，解密时 `变表索引 ^ 0x15` 即还原（异或是自逆）；示例二是 `table[(standard_index + key[i%4]) & 0x3f]`，解密时 `(变表索引 - key[i%4]) & 0x3f`，必须用按位与/取模处理负数，不能只在小于 0 时加一次 64。
- **顺序很重要**：先做索引逆变换，再按标准 Base64 解码；如果先解码再变换会得到错误结果。
- **验证**：把还原出的明文用题目同样的表与索引变换重新编码，结果必须等于原密文；这能区分“换表 + 异或”和“换表 + 加法”等变体。

## 触发条件

- 逆向程序中出现长度 64 的字符表、`table[index]` 取表、每 3 字节分组/每组 4 个 6 位索引的结构。
- 索引在查表前有异或、加常数、加循环 key、取模等操作。
- 密文尾部可能有 `=` 填充；`=` 不参与查表。
- 已知或可推导变表与索引变换常量。

## 利用步骤

1. 从 `.rodata`/局部数组提取 64 字符变表，确认 64 个字符互不重复。
2. 反编译取索引变换：记录异或常量、加法 key 数组、循环周期、取模方式、发生在查表前还是查表后。
3. 去掉密文尾部 `=` 并记录数量；对每个字符查变表得到索引。
4. 按逆运算还原标准索引：异或用 `^`；加法用 `(idx - key[i%n]) & 0x3f`。
5. 按标准 Base64 表把索引转回字符，补回 `=`，用 `base64.b64decode` 解码。
6. 重新编码回密文比对；不一致说明表/常量/顺序有误。

## PoC

```python
import base64

s1 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
s2 = 'ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/'
mask = 0x15
en_text = 'YeBCCdVNCf4eMTNjXjFjXeNHJjNwFNlwWPxHLwZfXdxtFwZkGgZkHC=='

def decode_variant(ciphertext):
    padding = len(ciphertext) - len(ciphertext.rstrip('='))
    body = ciphertext.rstrip('=')
    if len(set(s2)) != 64:
        raise ValueError('变表必须是 64 个不重复字符')
    standard = ''.join(s1[s2.index(ch) ^ mask] for ch in body) + '=' * padding
    return standard, base64.b64decode(standard, validate=True)

std, plain = decode_variant(en_text)
print(std)          # U0RQQ1NFQ3t0aDFzXzdzX0FfZzFmdF9mMHJfbmV3X1JldmVyc2VyfQ==
print(plain.decode())
```

```python
# 加法变体：table[(index + key[i%4]) & 0x3f]
table = "CDABGHEFKLIJOPMNSTQRWXUVabYZefcdijghmnklqropuvstyzwx23016745+/89"
key = [1, 2, 3, 4]
idx = [(table.index(ch) - key[i % 4]) & 0x3f for i, ch in enumerate(cipher.rstrip('='))]
```

原文实测：异或变体还原出 `SDPCSEC{th1s_7s_A_g1ft_f0r_new_Reverser}`；回加密与比较串一致。

## 变体与关联

- **换表变体**：标准表任意置换、大小写/数字段重排、base58 表换表（无 `=` 填充，用 `str.maketrans` 映射回标准表后 `b58decode`）。
- **索引变体**：`^ const`、`+ key[i%n] & 0x3f`、`- const & 0x3f`、按位置/轮次变化的 key。
- **实现变体**：先加 key 再查表、先查表再加 key、变表本身由程序运行时生成（需复现生成逻辑）。
- **关联卡片**：[[ctf-reverse-modified-rc4-rounds-sbox]]（同类魔改算法还原）、[[ctf-reverse-z3-constraint-equation-solve]]（逆向约束求解）。
- **边界**：若索引变换不是双射（如丢失高位、非可逆位运算），不能逐字符还原；若变表/常量未知，需先逆向生成逻辑。

## 检测与防御

- **CTF 验证**：还原后必须回编码比对；`=` 不参与查表；加法变体用 `& 0x3f` 而非一次性 `+64`。
- **防御视角**：自定义 Base64 只是混淆，不是加密；不要把密钥/敏感数据只靠换表保护。
- **检测信号**：二进制中出现 64 字符表、`index ^ const`、`% 64` 取表；编码结果尾部有 `=`。
- **复盘**：先分清“表”和“索引”两层，再分别求逆；不要直接把变表当标准表解码。
