---
id: crypto-classical-keyword-cipher-first-letter-brute-frequency
title: 关键字替换密码（keyword cipher）密钥未知：按首字母枚举候选密钥 + 词频/可读性打分自动定位
type: scenario
domain: crypto
path: crypto/classical
technique: keyword-substitution-cipher-key-brute-frequency-score
aliases:
- 关键字密码
- keyword cipher 爆破
- 密钥短语换表
- 首字母枚举定密钥
- 词频筛选密钥
tags:
- crypto
- classical
- substitution
- keyword-cipher
- frequency-analysis
- brute-force
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:35:21+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文第 6 题为关键字密码、密钥在 key 文档中、从 b 开始逐个试到 bingo，卡内『首字母枚举+词频打分』与该过程一致；PoC 中 bingo 相关候选为按原文情境构造，统计截图与换表内容未读图验证
---

## 一句话结论

密文保持词形、空格与标点不变但字母全被替换，且题面暗示"密钥/关键在一个 key 里"时，通常是关键字替换密码：换表由一个密钥短语（去重后接剩余字母表）生成。密钥未知时不必穷举整个短语——**按密钥首字母枚举长度较小的候选短语，用英文词频与可打印率给每个候选的明文打分**，分数陡然升高的那一个就是密钥（本例枚举到 `b` 开头时命中 `bingo`）。

## 原理

- 关键字替换密码（keyword cipher）构造换表：取密钥短语 → 去掉重复字母 → 后接字母表中未出现的字母 → 得到 26 字母密文字母表；加密即把明文按该表逐字母替换。密钥是一句话/一个词，因此**密钥空间远小于 26!**，属于"可枚举的置换"。
- 与纯单表替换的区别：它的换表有强结构（密钥字母按原序出现在表头、剩余字母按 a–z 顺序补齐）。这既是特征的来源，也意味着只要猜中密钥就能精确复现整张表。
- 当密钥本身是无意义短词（`bingo`），词频工具（quipqiup 类）往往直接给出明文，反而"顺手"暴露密钥；先试工具、工具不给唯一解时再退回枚举，是效率最高的顺序。
- 枚举策略：**固定首字母 + 短语长度 3~6**，或直接用一个常见单词表（rockyou 的前若干万条、人名词表）作为候选密钥。评分函数用英文四元组/单词命中率（如 `the`、`and`、`ing` 出现次数）+ 明文可打印率，排序取最高；通常第一名的分数会明显高于第二名。
- 本题的可利用提示：文档里"降序和升序"两处文字都出现了 `bingo`，说明出题人把密钥埋在文本细节里；真实题面里凡是**在无关位置重复出现的同一个短词**，都应优先当候选密钥试。

## 触发条件

- 密文为纯字母替换，保留空格/标点、单词长度不变（可据此确认是单表替换类，而非换位）。
- 题面或附件暗示"key/关键字/密钥在某个文档里"，或提供了候选词来源（提示文本、文件名、图片）。
- 明文为英文自然语言（词频与词典匹配才有意义）；若是中文拼音或随机串则失效。
- 有词频统计工具或能写十几行评分脚本。

## 利用步骤

1. 先做基础判定：统计密文字母频率并画图，与英文频率（e/t/a/o/i/n 高、q/z/x 低）比对，确认是单表替换。
2. 先试自动化工具（quipqiup 类）：若直接给出可读明文，则从明文反推换表、再反查密钥短语（换表开头连续的、未按字母序排列的字母即密钥去重后的结果）。
3. 工具不给唯一解时改为枚举：对候选密钥（首字母 a–z 各枚举 3~6 位短语，或直接用词表）生成换表、解出明文、打分。
4. 打分：统计 `the/and/ing/ion/ent` 等高频片段命中数 + 明文可打印率 + 单词是否在词典中；取分数最高的候选。
5. 用命中的密钥复现完整换表，逐字解密全文（含 `flag{}` 内的数字/符号，注意非字母字符通常原样保留）。
6. 回填验证：解密结果里的 `flag{...}` 前缀应与题面格式一致，可据此反向确认换表正确。

## PoC

```python
import string, collections

ALPHA = string.ascii_lowercase

def build_table(key: str) -> dict:
    """密钥去重后接剩余字母 -> 明文->密文映射（解密时取反映射）"""
    seen, head = set(), ""
    for c in key.lower():
        if c in ALPHA and c not in seen:
            seen.add(c); head += c
    tail = "".join(c for c in ALPHA if c not in seen)
    cipher_alpha = head + tail
    return str.maketrans(ALPHA, cipher_alpha)

def decrypt(ct: str, key: str) -> str:
    enc = build_table(key)                 # 明文->密文
    dec = {v: k for k, v in enc.items()}
    return "".join(dec.get(c.lower(), c) if c.isalpha() else c for c in ct)

FREQ = ("the", "and", "ing", "ion", "ent", "her", "for", "tha", "nth", "int")

def score(pt: str) -> float:
    low = pt.lower()
    words = sum(low.count(w) for w in FREQ)
    printable = sum(c.isprintable() for c in pt) / max(len(pt), 1)
    return words * 3 + printable

# 1) 先用工具/词表给候选；2) 无候选时按首字母枚举
best = None
for first in ALPHA:
    for word in [first + x for x in ("ingo", "ingo!", "ingo1")]:  # 本例命中的构造
        pt = decrypt(CT, word)
        s = score(pt)
        if best is None or s > best[0]:
            best = (s, word, pt)
print(best[1], best[2][:80])
```

```python
# 更通用的做法：用词表当候选密钥，取评分最高者
cands = [w.strip() for w in open("words.txt", encoding="utf-8", errors="ignore") if 3 <= len(w.strip()) <= 8]
ranked = sorted(((score(p := decrypt(CT, w)), w, p) for w in cands), reverse=True)
for s, w, p in ranked[:5]:
    print(round(s, 2), w, p[:60])
```

## 变体与关联

- 变体（密钥是长句）：换表头部很长且顺序明显不是字母序，此时"读出表头即得密钥"，不需要枚举。
- 变体（换表后还叠加移位）：关键字换表 + 凯撒移位，先按频率定移位量、再解关键字表。
- 变体（换位而非替换）：若字母频率与英文吻合但词不成词，说明是换位类（栅栏/列置换），走另一条路。
- 关联：[[crypto-classical-monoalphabetic-substitution-frequency-tool]]（同类问题的"先上词频工具"路线）、[[crypto-classical-lookup-table-multibyte-substitution-reverse]]（表结构与换表映射）、[[crypto-classical-column-transpose-vertical-read-caesar-shift]]（换位类的对照）。
- 边界：明文不是英文时评分函数失效；密钥含数字/符号时换表构造需按样本的实际实现（有的实现只对字母去重，数字原样保留）。

## 检测与防御

- 说明：本条是古典密码的分析与还原方法，不是对在用系统的攻击手段。
- 防御侧价值：任何"用短语派生换表"的古典方案都不构成现代密码学安全边界；需要保密时应使用 AEAD 类现代加密，而不是字符替换。
- 若作为题目/教学材料：提醒出题人避免在正文里重复出现密钥词（本例的 `bingo` 就出现在无关句子里，直接缩小了搜索空间）。
