---
id: ctf-crypto-tweakable-aes-round-constant-cancel-key-recovery
title: 可调 AES 后门：构造 tweak 使每轮轮 tweak 抵消轮常数，单次选择明文恢复主密钥
type: scenario
domain: ctf
path: ctf/crypto
technique: tweakable-aes-round-constant-cancellation-key-recovery
aliases:
- Doctored Dobbertin v2
- 可调分组密码后门
- tweak 抵消轮常数
- 轮常数后门
- 单次选择明文恢复密钥
tags:
- ctf
- crypto
- aes
- tweakable
- backdoor
- round-constant
- chosen-plaintext
- key-recovery
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:59:01+08:00'
  notes: 已对照原文核对：10 轮可调 AES、tweak 0x846a51a2787d09d057b2bfa8a3481dae、全 0 明文、列 1=3/2=4、最后一轮密钥一半为 0、8 字节+2 字节枚举均一致；原文未贴求解脚本
---

## 一句话结论

10 轮可调 AES 每轮把轮常数与轮 tweak 分别加到内部状态上；存在一个特殊 tweak 使各轮派生出的轮 tweak 恰好抵消轮常数（本题为 `0x846a51a2787d09d057b2bfa8a3481dae`），此时加密退化为无轮常数的结构；发送全 0 明文后，最后一轮密钥加之前的内部状态满足列 1=列 3、列 2=列 4，而最后一轮轮密钥有一半为 0，攻击者可提取 8 个非 0 密钥字节并枚举剩余 2 字节恢复主密钥。

## 原理

- **可调分组密码**：加密输入除明文、密钥外还有 tweak；轮函数在每轮把 round constant 与由 tweak 派生出的 round tweak 异或/加到状态上。
- **后门思路**：若轮常数与轮 tweak 的派生方式允许选择一个 tweak，使得“轮 tweak = 轮常数”，则两者在每轮相互抵消；等价于把带常数轮函数变成无常数版本，攻击者可对加密做代数/结构分析。
- **tweak 求解**：轮 tweak 通常由 tweak 经线性/简单派生（如每轮循环移位/重复）得到；由于每轮常数已知，可反推需要哪一组轮 tweak，再逆推主 tweak。本题求得 `0x846a51a2787d09d057b2bfa8a3481dae`。
- **选择明文**：发送全 0 明文，经过 9 轮后（最后一轮密钥加前）状态具有“列 1 与列 3 相等、列 2 与列 4 相等”的结构；最后一轮轮密钥中恰有一半字节为 0，因此密文的对应部分直接暴露了内部状态的一半，可反推出 8 个非 0 轮密钥字节。
- **密钥扩展逆推**：AES-128 的轮密钥与主密钥一一对应；拿到 8 个轮密钥字节可确定主密钥 8 个字节，剩余 2 字节只需 2^16 枚举并用已知明密文验证。
- **与原题差异**：hacklu CTF 2023 的 Doctored Dobbertin 改的是 S 盒/常数、需要 7 次选择明文；本题修改了 S 盒、P 盒与常数并把选择明文次数降到 1 次，常规线性/差分所需数据量不够，必须利用轮常数抵消这一结构性弱点。

## 触发条件

- 加密服务允许攻击者提交一次（或少量）自选明文与 tweak，并用同一随机密钥加密。
- 轮常数与 tweak 派生方式已知或可逆，存在可抵消的 tweak。
- 最后一轮轮密钥存在一半为 0 的弱点（题目构造导致）。
- 能对剩余密钥字节做离线枚举与验证。

## 利用步骤

1. 逆/读题目的轮函数实现，提取轮常数、S 盒、P 盒与 tweak 派生规则。
2. 解方程 `round_tweak_i == round_constant_i`（逐轮），逆推主 tweak；本题结果 `0x846a51a2787d09d057b2bfa8a3481dae`。
3. 用该 tweak 提交全 0 明文，获得一次加密结果。
4. 利用最后一轮前的列相等结构与轮密钥一半为 0，从密文反推 8 个非 0 轮密钥字节。
5. 逆密钥扩展得到主密钥 8 字节，枚举剩余 2 字节并用已知明密文验证，恢复完整主密钥。
6. 用主密钥解出服务端挑战密文对应的明文/flag。

## PoC

无完整脚本（原文未贴求解代码）。关键参数：

```text
tweak = 0x846a51a2787d09d057b2bfa8a3481dae
plaintext = 0x00000000000000000000000000000000
# 最后一轮密钥加前：col1 == col3, col2 == col4
# 最后一轮轮密钥一半为 0 → 提取 8 个非 0 字节，枚举剩余 2 字节
```

## 变体与关联

- 变体：若选择明文次数更少（0 次），需要利用挑战密文与 tweak 的结构直接反推。
- 变体：其他可调分组密码（SKINNY、PRESENT tweak 版本）也可能存在轮常数/tweak 抵消后门。
- 关联：魔改 AES 的逆向识别见 [[ctf-reverse-aes-mixcolumns-extra-xor-0x55]]；白盒 AES 的差分故障分析见 [[crypto-side-channel-whitebox-aes-dfa-round8-fault]]。
- 边界：原文只给出 tweak、攻击思路与密钥字节数，未给出完整推导；复现需按题目实现重算轮常数与密钥扩展。

## 检测与防御

- 修复：轮常数与 tweak 派生避免可抵消的线性关系；使用经过审计的可调分组密码实现。
- 加固：限制同一密钥下的选择明文次数与 tweak 自由度；密钥定期轮换。
- 检测：固定/特殊 tweak 的高频加密请求；异常全 0 明文与重复 tweak。
