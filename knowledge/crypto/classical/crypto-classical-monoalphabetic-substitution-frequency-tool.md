---
id: crypto-classical-monoalphabetic-substitution-frequency-tool
title: 简单替换密码（单表替换）：用词频/字典搜索工具秒解，再用已知前缀反推整张映射表提 flag
type: scenario
domain: crypto
path: crypto/classical
technique: classical-monoalphabetic-substitution-frequency-tool
aliases:
- 单表替换密码
- 简单替换
- 词频分析
- quipqiup
- substitution cipher
tags:
- crypto
- classical
- substitution
- frequency-analysis
- monoalphabetic
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:28:49+08:00'
  notes: 已对照原文核对：Analyze 题面明说每个字母换成另一个字母（All a become b, b become c）、密文含 nrfl{...} 前缀，原文用 quipqiup 词频工具得明文并以 ictf{chatGPT_is_my_best_friend} 收尾，卡片步骤（工具求解 + 已知前缀反推映射表）与原文一致；已将失效关联 [[crypto-classical-table-map-chinese-substitution-double-layer]] 改为实际存在的 crypto-classical-lookup-table-multibyte-substitution-reverse；未设 affected_versions；未复跑
---

## 一句话结论

一段保留空格与标点、且同一字母始终被换成同一个字母的文本（题面明说“把 a 全换成 b、b 全换成 c 这类一致替换”）属于单表替换密码；把整段密文（含花括号前缀）丢进词频/词典搜索工具（quipqiup 之类）自动求解，得到可读英文后，用“解出的前缀 ⇔ 已知前缀”反推整张字母映射表，再全文替换一遍即得 flag。

## 原理

- **密钥就是一个置换**：单表替换（monoalphabetic substitution）把 26 个字母一一映射到 26 个字母，同一明文字母永远映射到同一密文字母；因此密文的**字母频率分布与明文同构**，只是标签换了。
- **为什么可破**：英语里 e/t/a/o/i/n 高频、q/z/x 极稀有，`the/and/ing` 等高频词与双/三字母组合提供强约束；把频率排序 + 词典匹配作为目标函数，爬山/贪心搜索能在秒级收敛到唯一候选。
- **与凯撒的区别**：凯撒只是置换的特例（循环移位，26 种），可直接暴力；单表替换密钥空间是 26!，暴力不可行，必须靠统计搜索。
- **工具省掉手工**：quipqiup 一类服务把“词频 + 英文词典 + 词间关系”做成搜索；题目文本是多句自然语言，约束足够强，通常首个候选就是明文。
- **为什么要“反推整表再全文替换”**：工具给的候选可能只覆盖部分字符（尤其花括号内混有大小写/数字），只有把解出的前缀与题面已知前缀（如 `ictf{`）对齐，才能确定完整映射并逐字还原花括号内容。
- **边界**：文本太短（少于约 30 个字母）、或明文不是英文（中文/拼音/随机串）时频率分析失效，需已知明文攻击或人工猜词；密文中未被替换的数字/符号会保留原位，可当锚点。

## 触发条件

- 密文由字母（含空格与标点）组成，长度足够长（几十词以上）。
- 题面/提示暗示“每个字母换成另一个字母”“同一字母替换后仍相同”这类一致替换。
- 明文是自然语言英文；存在已知格式前缀（`ictf{`、`flag{` 等）可用于反推映射与校验。

## 利用步骤

1. 判类型：字母分布像英文、单词长度模式（1 字母词必是 `a`/`I`）成立，且词边界完整 → 单表替换（而非换位）。
2. 把整段密文原样（保留空格、标点、`nrfl{...}` 之类前缀）粘贴到词频/词典求解工具（quipqiup、dCode substitution solver，或本地爬山脚本）。
3. 在返回的候选里挑语义连贯、专有名词合理的一条，逐句核对。
4. 对齐前缀：找到解出文本中对应 `nrfl{` 的位置，得到 `n→i, r→c, f→t, l→f` 这几个字母，并据此确认工具用的是哪一套映射。
5. 用完整映射逐字符替换花括号内的密文，得到 flag；再用已知前缀做最终校验。
6. 若工具输出有个别错字（少见字母 z/q/x 或大小写），用题干描述词、常见词典补全残余映射后手工修正。

## PoC

```python
# sub: 由工具候选 + 已知前缀对齐后确定的“密文->明文”映射
sub = {'n': 'i', 'r': 'c', 'f': 't', 'l': 'f', ...}

cipher = "<保留空格与花括号的整段密文>"
plain = ''.join(sub.get(c.lower(), c) if c.isalpha() else c for c in cipher)
print(plain)          # 可读英文，末尾即 ictf{...}
```

## 变体与关联

- 变体：替换表不是纯字母（含中文/多字节符号）时，先按编码单位切分再逆表，见 [[crypto-classical-lookup-table-multibyte-substitution-reverse]]。
- 变体：换位（列换位/栅栏）保持字母频率但破坏词边界，需先还原置换再做替换，见 [[crypto-classical-column-transpose-vertical-read-caesar-shift]]。
- 变体：单表替换叠加移位（凯撒/维吉尼亚）时先解外层移位再解替换，或对组合做联合搜索。
- 关联：[[crypto-classical-pigpen-variant-fence-column-decode]]（符号表 + 换位组合）、[[ctf-crypto-semi-adfgx-5x6-polybius-hillclimb-substitution]]（非字母表替换的爬山求解）。

## 检测与防御

- 教学/CTF 场景：单表替换对现代算力无意义（26! 也能靠统计搜索 + 明文约束破解），真实系统不应使用任何“字符替换表”保护数据。
- 若遗留系统用置换表加密：检测信号是密文字母频率与自然语言同构、无随机化；应替换为 AEAD（AES-GCM/ChaCha20-Poly1305）。
- 提醒：任何“自制字母置换 + 固定分隔符”方案都等价于无加密，叠加在别的替换之上也不改变可解性。
