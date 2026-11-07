---
id: crypto-side-channel-whitebox-aes-dfa-round8-fault
title: 白盒 AES 差分故障分析：第 8 轮列混淆注入 + phoenixAES 恢复轮密钥
type: scenario
domain: crypto
path: crypto/side-channel
technique: whitebox-aes-dfa-round8
aliases:
- 白盒 AES
- DFA
- 差分故障分析
- phoenixAES
- aes_keyschedule
- 第 8 轮列混淆
- 故障注入
tags:
- crypto
- aes
- whitebox
- dfa
- fault-injection
- side-channel
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V218
  verified_at: '2026-11-07T04:49:46+08:00'
  notes: 已对照原文与图12-25核对：第8轮列混淆后单字节故障、条件断点rdi==0x8000、phoenixAES输出4214F7345BB25523851334E94F03DF5F、aes_keyschedule K00 009CF29131C8E4EA81BD5DD248E6F3E0、CyberChef解出flag均一致；未复跑。
---

## 一句话结论

对白盒 AES 实现，如果在第 8 轮 MixColumns 后的状态中注入单字节故障，收集同一明文的 1 个正常密文和 16 个故障密文，就可以用差分故障分析（phoenixAES）恢复最后一轮轮密钥，再用 `aes_keyschedule` 逆扩展得到第 1 轮轮密钥（即 AES 主密钥），最后解密目标密文。

## 原理

- 白盒 AES 把轮密钥与 S 盒/列混淆融合成查表，静态提取密钥困难；但它仍然是 AES 的 10 轮结构，差分故障分析利用“故障在倒数第二轮（第 8/9 轮）注入后，经最后一轮扩散到 4 字节”的可预测模式。
- 在第 8 轮 MixColumns 之后修改 1 个字节（共 16 个位置分别注入），经过第 9 轮、第 10 轮后，故障会扩散成最后一轮密文中的特定 4 字节差异；比较正常密文与故障密文，可以逐字节恢复最后一轮轮密钥的 4 个字节。
- 收集 16 个不同位置的故障密文（每个位置至少 1 个，实际建议每列 2 个）后，phoenixAES 的 `crack_file` 可以自动完成 DFA，输出最后一轮轮密钥（文章为 `4214F7345BB25523851334E94F03DF5F`）。
- AES 密钥扩展是可逆的：拿到任意一轮轮密钥后，用 `aes_keyschedule`（Stark 的 C 工具）逆扩展，可得到第 1 轮轮密钥/主密钥（文章 K00 = `009CF29131C8E4EA81BD5DD248E6F3E0`）。
- 有了主密钥后，按 AES-ECB/NoPadding 解密目标密文即可得到 flag；白盒实现的外部输入/输出编码需要在 DFA 前去掉，或按实现调整。

## 触发条件

- 目标为白盒 AES（查表实现），但保留标准 AES 轮结构；能动态调试并在第 8 轮/列混淆后注入故障。
- 能获得同一明文的正常密文和至少 16 个不同位置的故障密文；故障注入点/时机稳定。
- 白盒实现没有额外的输入/输出线性编码（或已还原），否则 DFA 需要先去除编码。
- 有 phoenixAES 与 `aes_keyschedule`（或等价的逆密钥扩展实现）。

## 利用步骤

1. 在 IDA/x64dbg 中定位白盒 AES 的轮循环（文章条件断点 `rdi == 0x8000` 判断轮数），找到第 8 轮 MixColumns 后的状态缓冲区。
2. 记录同一明文的正常密文；对状态缓冲区的 16 个字节逐一注入单字节故障（修改 1 字节），继续执行到最终赋值处，提取故障密文。
3. 对每个注入位置重复，得到 1 个正常密文 + 16 个故障密文；按 phoenixAES 的 tracefile 格式写入（每行一个 16 字节十六进制密文）。
4. 运行 `phoenixAES.crack_file('tracefile', [], True, False, 3)`，得到最后一轮轮密钥。
5. 用 `aes_keyschedule.exe <last_round_key> 10` 逆扩展，取 K00 作为 AES 主密钥。
6. 用主密钥按 AES-ECB/NoPadding 解密目标密文，得到 flag/明文；必要时去掉白盒的输入/输出编码。

## PoC

phoenixAES tracefile（文章示例，首行正常密文 + 16 行故障密文）：

```python
import phoenixAES

with open('tracefile', 'wb') as t:
    t.write("""
0150A8D131E87AE1332AE72A84C28F96
E450A8D131E87A6B332AA62A84608F96
0150A83E31E893E13313E72A7AC28F96
0150FED131537AE12A2AE72A84C28F0E
016BA8D18EE87AE1332AE76084C2D696
01C0A8D1A4E87AE1332AE74E84C2D296
F150A8D131E87A38332A5A2A84718F96
0150A81031E8B6E1335BE72A4CC28F96
0150C2D131ED7AE16F2AE72A84C28F02
015098D131AE7AE1B62AE72A84C28F2C
0141A8D166E87AE1332AE7D484C29796
6A50A8D131E87AB0332A102A84698F96
0150A86031E887E13369E72A47C28F96
0150A82231E8EAE133EBE72A4AC28F96
015075D131477AE1442AE72A84C28F48
015BA8D17BE87AE1332AE79C84C24D96
1E50A8D131E87AB5332A5C2A84718F96
""".encode('utf8'))

phoenixAES.crack_file('tracefile', [], True, False, 3)
# Round key bytes recovered: 4214F7345BB25523851334E94F03DF5F
```

逆密钥扩展：

```text
aes_keyschedule.exe 4214F7345BB25523851334E94F03DF5F 10
K00: 009CF29131C8E4EA81BD5DD248E6F3E0
...
K10: 4214F7345BB25523851334E94F03DF5F
```

解密：

```text
AES Decrypt, Key=009CF29131C8E4EA81BD5DD248E6F3E0, Mode=ECB/NoPadding
Input: 61E2312BDB5D41BF03F604A7F478680E41AB532035C2B87894E140F40A9F0F0795C6208C653C8C2732B026A83614F04F6D44CB66BB784726881EABC3FDF283CB8
Output: flag{7h3_Pyr4m1d_0f_Py7h0n_4w4175_175_M4573r_R3v3r53r_uJ6gG3qVs}
```

## 变体与关联

- 变体：第 9 轮注入（simple DFA R9）需要 4 列 × 每列至少 2 个故障；第 8 轮单字节故障可当作 R9 处理（文章说明）。
- 变体：白盒实现带输入/输出编码时，先用代数/查表还原去掉编码，再做 DFA。
- 变体：无法动态注入时，用运行时表重建 + meet-in-the-middle 恢复密钥；见 [[ctf-reverse-whitebox-aes-runtime-table-reconstruction-mitm]]。
- 关联：[[crypto-side-channel-aes-cpa-hamming-weight]]（AES CPA 侧信道）。
- 边界：白盒实现不是标准 AES 轮结构、故障注入点不稳定、无法获得足够故障密文、输出编码未去除时，DFA 失败。

## 检测与防御

- 检测：白盒 AES 二进制中出现大查表、轮循环常量 `0x8000`/9 轮判断；动态调试对第 8 轮 MixColumns 后缓冲区写 1 字节；phoenixAES tracefile 形态。
- 防御：白盒实现加入随机化/故障检测（重复计算、校验和、冗余轮）；对关键状态做完整性校验；使用外部编码/掩码提高 DFA 成本。
- 加固：不要把白盒 AES 当作抗故障攻击的方案；结合硬件安全模块/可信执行环境保护密钥。
