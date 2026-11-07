---
id: ctf-crypto-semi-adfgx-5x6-polybius-hillclimb-substitution
title: Semi-ADFGX 5×6 Polybius 方阵 + 爬山/模拟退火替换还原英文贺词
type: scenario
domain: ctf
path: ctf/crypto
technique: semi-adfgx-5x6-polybius-hillclimb-substitution
tags:
- ctf
- crypto
- adfgx
- polybius
- substitution
- hill-climb
- simulated-annealing
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:53:41+08:00'
  notes: 已对照原文核对：5×6 Polybius（第一位 5 符号/第二位 6 符号）、86 万+ 截获密文、频率初始化+爬山/退火、解出新年贺词均一致；PoC 为原文流程重写，未复跑。
url: /docs/ctf/crypto/ctf-crypto-semi-adfgx-5x6-polybius-hillclimb-substitution/
draft: false
kb_aliases:
- Semi_ADFGX
- 5×6 Polybius
- ADFGX 变体
- 爬山替换
- 模拟退火破译
---

## 一句话结论

密文只由大写字母组成、按两个字符一组且第一位来自 5 个符号、第二位来自 6 个符号时，可判定为 5×6 Polybius 方阵（Semi-ADFGX 变体）；在不知道表内容的情况下，用大量截获密文统计二元组频率、以英文 n-gram 打分，爬山/模拟退火优化 27 个字符的替换映射，即可解出目标短密文的新年贺词。

## 原理

- **Polybius 坐标**：每个明文字符被编码成 `(行,列)` 二元组；本题第一位来自 `{C,F,G,R,T}`（5 种）、第二位来自 `{A,E,N,P,W,Y}`（6 种），所以是 5×6=30 个符号的方阵。
- **单表替换**：在不知道方阵内容时，可把每个二元组视为一个未知符号；密文就是“未知符号序列”。只要符号集大小有限（本题约 27 个，对应 `a-z` + `_`），就可用单表替换的频率分析/爬山求解。
- **训练数据**：题目给出 86 万+ 字符的截获密文（同一套表加密），以及一段短目标密文；截获密文足够统计每个二元组的频率。
- **评分函数**：用英文 n-gram/常见片段（`_the_`、`_and_`、`_new_`、`_year_`、`happy`、`merry`、`christmas` 等）给解码文本打分；频繁二元组初始映射为 `_`、`e`、`t`、`a`、`o` 等。
- **优化**：随机交换两个符号的映射，若分数提高则接受；否则以 `exp(delta/T)` 概率接受（模拟退火），`T` 逐步下降；保留历史最优映射，最后解目标密文。
- **为什么可行**：替换密码保留字符频率/ngram 统计；数据量越大，爬山越容易收敛。5×6 只是把 26 个字母 + 下划线映射到 30 个坐标，未知表等价于 27 个符号的置换。
- **本题**：解出 `happy_new_year_and_merry_christmas_to_all_participants_of_the_new_year_ctf_from_our_team_we_would_be_delighted_to_see_you_at_our_grand_finale_in_february`，按 `grodno{...}` 提交。

## 触发条件

- 密文仅含有限大写字母集，且按 2 字符分组；第一/第二位字符集大小分别为 5/6（或 ADFGX 的 5/5、ADFGVX 的 6/6）。
- 有大量同表加密的截获文本（用于频率/ngram 训练）和一段目标短密文。
- 明文是自然语言（英文/拼音/带下划线空格），可用 ngram 打分。
- 没有转置层，或转置层已知/可先还原（标准 ADFGX 还有列转置）。

## 利用步骤

1. 统计密文字符集与分组：按 2 字符切分，确认第一位/第二位各自的字符集大小，判定 5×6 Polybius。
2. 收集所有出现过的二元组（本题约 27 个），把文本转成符号索引序列。
3. 按频率初始化映射：最常见二元组→`_`，其余按 `e,t,a,o,i,n,s,h,r,d,l,u,c,m,f,w,y,g,p,b,v,k,x,q,j,z` 顺序分配。
4. 定义英文打分函数：统计常见 ngram/单词出现次数（`_the_`、`_and_`、`_new_`、`_year_`、`happy`、`merry`、`christmas` 等），可加可打印/字母比例。
5. 在训练样本上做爬山/模拟退火：随机交换两个映射，按分数接受/概率接受，温度逐步下降；保留最优映射。
6. 用最优映射解目标密文；对明显错字做人工/词典修正（如 `berry`→`merry`、`qhristbas`→`christmas`）。
7. 按题目格式提交 flag；若标准 ADFGX 有转置层，先还原列顺序再做替换。

## PoC

```python
from collections import Counter
import math, random

def digrams(s):
    return [s[i:i+2] for i in range(0, len(s), 2)]

inter = open("Intercepted_Codes.txt").read().strip()
cipher = open("Cipher.txt").read().strip()
inter_d, cip_d = digrams(inter), digrams(cipher)
tokens = sorted(set(inter_d)); idx = {t:i for i,t in enumerate(tokens)}
sample = [idx[t] for t in inter_d[:20000]]
target = [idx[t] for t in cip_d]

freq = Counter(inter_d)
init = list("_etaoinshrdlucmfwygpbvkxqjz")
mapping = [None]*len(tokens)
for i, (t, _) in enumerate(freq.most_common()):
    mapping[idx[t]] = init[i]
for i in range(len(mapping)):
    if mapping[i] is None:
        mapping[i] = init[i]

def score(text):
    grams = ["_the_", "_and_", "_to_", "_of_", "_in_", "_for_", "_new_", "_year_",
             "happy", "merry", "christmas", "participants", "from_", "our_",
             "team", "delighted", "grand", "finale", "february"]
    return sum(text.count(g)*100 for g in grams)

def decode(seq, m):
    return "".join(m[i] for i in seq)

random.seed(2026)
cur = mapping[:]
cur_score = score(decode(sample, cur))
best, best_score = cur[:], cur_score
T = 6.0
for _ in range(25000):
    i, j = random.sample(range(len(cur)), 2)
    new = cur[:]; new[i], new[j] = new[j], new[i]
    s = score(decode(sample, new))
    if s > cur_score or random.random() < math.exp((s-cur_score)/max(T,1e-9)):
        cur, cur_score = new, s
        if s > best_score:
            best, best_score = new, s
    T *= 0.9997

plain = decode(target, best)
print("grodno{" + plain + "}")
```

说明：PoC 按原文的频率初始化 + 爬山/退火流程重写；实际需按训练数据规模调整迭代/温度。未在本机对附件复跑。

## 变体与关联

- **标准 ADFGX**：5×5 方阵 + 列转置；需要同时恢复转置与替换。
- **ADFGVX**：6×6 方阵（字母+数字）+ 转置；先确定列数/列序。
- **其他 Polybius**：5×5/6×6/自定义符号集；按字符集大小识别。
- **优化算法**：爬山、模拟退火、遗传算法、模拟退火 + 词典；数据量越大越稳。
- **关联**：[[ctf-reverse-adfgvx-click-matrix-md5-constraint-brute-force]]（ADFGVX 坐标矩阵 + 约束爆破）、[[crypto-classical-pigpen-variant-fence-column-decode]]（古典替换/栅栏）。

## 检测与防御

- 识别：密文字符集有限、按二元组重复、两组字符集大小 5/6；标准 ADFGX 还会有转置痕迹。
- CTF：这类古典密码强度低，数据量足够时统计破译可行；真实系统不要使用。
- 防御：使用现代 AEAD/分组密码；若必须用古典密码，至少加长密钥/转置并避免大量同表密文泄露。
