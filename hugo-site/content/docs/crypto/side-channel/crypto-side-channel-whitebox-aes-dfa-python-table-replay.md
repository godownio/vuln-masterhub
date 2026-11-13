---
id: crypto-side-channel-whitebox-aes-dfa-python-table-replay
title: 白盒 AES 的 Python 表复现 DFA：按 v11/v12/v13 查表重建 AAA，倒数第二轮前改一字节生成故障密文并用 phoenixAES 恢复主密钥
type: scenario
domain: crypto
path: crypto/side-channel
technique: whitebox-aes-dfa-python-table-replay
tags:
- crypto
- aes
- whitebox
- dfa
- fault-injection
- table-lookup
- python
- phoenixaes
- ctf
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V589
  verified_at: '2026-11-12T14:24:15+08:00'
  notes: 已对照原文与7张截图核对：img02 C# AAA 源码(v11/v12/v13 半字节表+table4[9])与卡内表结构/索引描述一致；img04 phoenixAES 实际输出 EA9F6BE2DF5C358495648BEAB9FCFF81（文中代码注释另有 13111D... 旧 trace，卡内已注明以实际跑出为准）；img07 aes_keyschedule 逆扩展 K00=51574232303233486170707947616D65(QWB2023HappyGame)；img05 CyberChef AES-ECB/NoPadding 用该 key 解 6193317bf896e000a527b7374ae303a8 得 WelcomeToQWB2023；img06 RC4 以该口令解出 .NET 序列化 license 数据。故障注入点 i==8 查表前 v16[ss]=1、16 组故障+1 正常密文喂 phoenixAES、R9 模型均与原文一致。修正1处：PoC 骨架注释原写『1 正常 + 16 故障密文』但该循环只产 16 个故障密文，已改为需另跑一次无注入 AAA 获正常密文（知识库与 staging 同步）。dedup：与 crypto-side-channel-whitebox-aes-dfa-round8-fault(动态调试注入)、crypto-side-channel-whitebox-aes-table-fingerprint-frida-dfa(Frida 自动采样)同属白盒 AES DFA 大链，但故障获取路径不同——本卡为源码级查表 Python 复现、无需调试器，且给出 AAA/change_index/v11-v12-v13 具体结构与半字节二级索引变体；按 append_scenario 保留为第三种取故障路径，理由成立；全局 dup-scan 无本卡 pair。原文未标注软件版本，affected_versions 保持空。
url: /docs/crypto/side-channel/crypto-side-channel-whitebox-aes-dfa-python-table-replay/
draft: false
kb_aliases:
- 白盒 AES Python 复现
- AAA 函数复现
- 查表法白盒 DFA
- 半字节查表白盒 AES
- 强网杯 dotdot
---

## 一句话结论

当白盒 AES 以半字节查表形式实现（`v11`/`v12`/`v13` 三级表 + 末轮 `table4`），且程序可运行/有源码可对照时，可以不去调试原二进制，而是按查表逻辑在 Python 中复现加密函数，在倒数第二轮（第 9 轮）查表前把状态的一个字节改成固定值，逐个位置生成 16 组故障密文，连同 1 个正常密文交给 phoenixAES 做 DFA 恢复第 10 轮轮密钥，再用 Stark 的 `aes_keyschedule` 逆扩展得到 K00 主密钥并解密目标密文。

## 原理

- **白盒 AES 仍是 10 轮结构**：查表实现把 SubBytes、AddRoundKey、MixColumns 融合成多级查找表，但轮序不变；末轮没有 MixColumns。DFA 的数学前提（故障经末轮扩散成固定 4 字节模式）因此仍然成立。
- **半字节表结构**：本例 C# 实现中 `v11[i][4*j][byte]` 先做字节级替换，`v12[i][24*j+k][hi_nibble][lo_nibble]` 用 16×16 小表组合半字节并实现列混合，`v13[i][4*j][byte]` 再做一轮字节替换，末轮用 `table4[9][k][byte]` 完成最后的 SubBytes+AddRoundKey；把连续两轮查表合并后，故障在最后一轮前扩散到密文固定 4 字节。
- **为什么可以 Python 复现**：白盒的“密钥”已折进表里，但表的输入输出关系是确定的；直接照 C#/C 源码把同样的查表序列写成 Python，就能在不运行原程序的情况下得到任意输入的中间状态与密文——包括人为注入故障后的密文。前提是能从源码或 dump 中得到 `v11`/`v12`/`v13`/`table4` 这些表。
- **故障位置**：循环 `for i in range(9)` 的第 `i==8` 次迭代对应第 9 轮（最后一个带列混合的轮），在查表前执行 `v16[ss]=1`（`ss` 遍历 0..15）就是把该轮输入状态的一个字节改坏；经最后一轮扩散后，密文出现 4 字节差异，满足 phoenixAES 的 R9 故障模型。
- **密钥恢复**：phoenixAES 从 1 正常 + 16 故障密文解出第 10 轮轮密钥；AES 密钥扩展可逆，`aes_keyschedule <K10> 10` 逆推 K00（主密钥），再 AES-ECB/NoPadding 解密目标密文。

## 触发条件

- 目标是查表法白盒 AES（如 Android/iOS 或 CTF 程序中的 C#/C++ 实现），且能拿到其查表源码或从二进制中 dump 出表。
- 程序或复现代码能确定性运行，允许对中间状态注入单字节故障；需要同一明文的 1 个正常密文与 16 个不同位置的故障密文。
- 白盒实现没有额外的输入/输出非线性编码；若有固定异或掩码，需先剥掉再喂 phoenixAES。
- 有 phoenixAES 与 Stark 的 `aes_keyschedule`（或等价的逆密钥扩展实现）。

## 利用步骤

1. 阅读白盒加密函数（本例为 C# 的 `AAA`）：确认 9 个 `i` 轮循环 + 末轮 `table4[9]`，记录 `v11[i][4*j][byte]`、`v12[i][24*j+k][hi][lo]`、`v13[i][4*j][byte]` 的索引方式与 `change_index()` 的行列置换（`[0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]`）。
2. 从源码/二进制导出 `v11`、`v12`、`v13`、`table4` 四张表，用 Python 逐行复现 `change_index()` 与 `AAA()`，先用任意输入与程序输出比对，确认复现无误。
3. 生成正常密文：取固定明文（如 16 个递增字节），运行复现函数记录输出。
4. 逐个 `ss=0..15` 注入故障：在第 `i==8` 次迭代查表前令 `v16[ss]=1`，运行完整轮序列，记录 16 个故障密文。
5. 按 phoenixAES tracefile 格式写 1 行正常密文 + 16 行故障密文（每行 16 字节 hex），运行 `phoenixAES.crack_file('tracefile')` 得到第 10 轮轮密钥（本例截图输出 `EA9F6BE2DF5C358495648BEAB9FCFF81`；文中另有一组注释值来自不同 trace，需以实际跑出的结果为准）。
6. 运行 `aes_keyschedule <K10> 10`，取 `K00` 作为主密钥（本例 `K00 = 51574232303233486170707947616D65`，即 ASCII `QWB2023HappyGame`）。
7. 用主密钥按 AES-ECB/NoPadding 解密题目密文；若解密结果仍是某种编码/密钥（本例得到 RC4 口令 `WelcomeToQWB2023`），按题目分层继续解密。

## PoC

故障注入骨架（表来自 `datas_table`，`change_index` 见步骤 1）：

```python
for ss in range(16):
    v16 = [i for i in range(97, 97 + 16)]
    AAA()                 # i==8 迭代内执行 v16[ss] = 1，即最后一轮前改一字节
    print(bytes(v16).hex())   # 16 个故障密文；正常密文需另跑一次未注入故障的 AAA()
```

phoenixAES 与逆密钥扩展：

```python
import phoenixAES
phoenixAES.crack_file('tracefile')   # 首行正常密文，其余为故障密文
```

```text
aes_keyschedule EA9F6BE2DF5C358495648BEAB9FCFF81 10
K00: 51574232303233486170707947616D65
```

无独立可执行 PoC：文中 Python 实现依赖从目标导出的 `datas_table` 与 `test2` 表模块，未随文章给出，复跑需自行 dump 表。

## 变体与关联

- **故障获取方式**：本卡是“Python 复现后直接改中间变量”；若无法复现但能调试原程序，可在第 8 轮 MixColumns 后用 gdb/x64dbg 改内存（见 `crypto-side-channel-whitebox-aes-dfa-round8-fault`）；若能 attach 进程，可用 Frida 在轮入口自动注入并批量采样（见 `crypto-side-channel-whitebox-aes-table-fingerprint-frida-dfa`）。
- **表结构变体**：本卡为半字节二级索引（16×16 小表）的白盒；经典的 `10×16×256` Tbox + `9×16×256` TyiBox + `16×16` 异或表是同一结构的另一种组织方式。
- **后处理**：DFA 拿到的是轮密钥而非直接明文；AES 密钥扩展可逆，`aes_keyschedule` 只是逆扩展工具，任何等价实现均可。
- **关联**：`ctf-reverse-aes128-aux-table-roundkey-recovery`（辅助表泄露轮密钥）、`mobile-android-sig3-unidbg-trace-crc32-whitebox-aes-hmac`（移动端白盒 AES DFA 实战）。

## 检测与防御

- 检测：白盒程序中出现多级字节/半字节查表、9 次轮循环 + 末轮表、状态缓冲区可被写；phoenixAES tracefile 形态（1 正常 + 多故障密文）是 DFA 的明显特征。
- 防御：白盒实现加入故障检测（重复计算与比对、冗余校验、随机化轮序不可行时加随机掩码）；对中间状态做完整性保护；不要把白盒 AES 当成抗故障注入方案。
- 分析侧：注入故障时保持其他字节不变、每轮只改一个位置，先验证复现代码与原始输出一致，再批量生成 trace，避免把实现差异误当成故障效应。
