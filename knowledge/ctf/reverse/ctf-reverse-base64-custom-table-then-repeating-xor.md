---
id: ctf-reverse-base64-custom-table-then-repeating-xor
title: 换表 Base64 + 轮密钥 XOR 两层编码逆向：先 translate 解码，再按 key[i%5] 异或还原（勿额外加索引）
type: scenario
domain: ctf
path: ctf/reverse
technique: base64-custom-table-then-repeating-xor
aliases:
- 换表 Base64 加 XOR
- 轮密钥 XOR 解密
- Roses 逆向
- Base64 外层 XOR 内层
- 两层编码逆向
- key[i%5] 异或
tags:
- ctf
- reverse
- base64
- custom-table
- repeating-key-xor
- multi-layer-encoding
- python
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V181
  verified_at: '2026-11-06T17:43:21+08:00'
  notes: 已对照原文核对：XOR(key=Roses,周期5)在自定义表 Base64 之前，解密顺序为先 translate 再 b64decode 再 key[i%5] 异或；本地按卡内 PoC 复算得到含 SDPCSEC{M155_1da_thank_y0u_f0r_solv1ng_her_troub7e} 的明文块，PoC 注释仅展示其中的 flag 行；未复跑原二进制。
---

## 一句话结论

程序先对文件字节做周期为 5 的轮密钥 XOR（key=`Roses`），再用一张置换过的 64 字符表做 Base64；逆向时按相反顺序：先把密文从自定义表翻译回标准表、`base64.b64decode`，再对每个字节异或 `key[i%5]`，即可还原 flag。注意 XOR 只与 key 有关，不要再额外加上下标 `i`。

## 原理

- **内层 XOR**：`encrypt_xor(input, output, len)` 对每个字节执行 `output[i] = input[i] ^ KEY[i % KEY_LEN]`，`KEY="Roses"`、`KEY_LEN=5`，即 5 字节循环密钥；这是对称操作，解密用同一公式。
- **外层 Base64 换表**：`encode_base64` 按标准 3→4 分组取 6 位索引，但查表用自定义表 `VxKw7QTsMd5Bri83NZe9Ut6pChXzD4IAYqmLuakbHofRWycvjGPnS2JE/+l01OFg`；`=` 仍只做尾部填充。这里没有对索引再做异或/加法，只是换表。
- **解密顺序必须相反**：先处理外层 Base64（把自定义表字符映射回标准表索引，再标准解码），再处理内层 XOR（按 `key[i%5]` 异或）。先把 XOR 作用在 Base64 文本上会得到错误结果。
- **易错点**：文章第一次尝试写成 `key[i%5] ^ (value + i)`，凭空加了下标 `i`；而源码只有 `input[i] ^ KEY[i%5]`。这一步会导致解出乱码。逆向时应以加密函数为准，并用“重新编码回密文”做闭环验证。
- **花指令干扰**：`encrypt_xor` 与 `encode_base64` 中插入了 `xor eax,eax; jz +2; E8 xx` 垃圾字节，IDA 线性扫描会误识为 `CALL` 导致反编译错位；按 `U`/`C`/`F5` 修复后算法本身是普通的 XOR+Base64（修复细节见关联卡）。
- **成立条件**：密钥与 64 字符表都能从 `.rodata` 或栈上常量提取；密文完整（含 `=` 填充）；XOR 与 Base64 的先后顺序能从 main 的调用链确定。

## 触发条件

- CTF 逆向题：二进制读取文件/输入，先做固定 key 的循环 XOR，再做自定义表 Base64；给出密文。
- 能从二进制中提取 64 字符表与循环密钥（示例 key `Roses`、周期 5）。
- 密文尾部可能有 `=`，翻译表时需保留填充、不计入查表。

## 利用步骤

1. 在 main 中确认调用顺序：`encrypt_xor(file_buffer, xor_buffer, len)` → `encode_base64(xor_buffer, ...)`；记录 key 与表。
2. 提取自定义表，确认是 64 个互不重复字符的排列；提取循环 key（示例 `Roses`，长度 5）。
3. 用 `str.maketrans(custom, standard)` 把密文中的自定义表字符翻译成标准 Base64 字符（`=` 原样保留）。
4. `base64.b64decode` 得到 XOR 后的字节串。
5. 对第 i 个字节异或 `key[i % len(key)]`（不要加 i、不要加其他偏移），输出为字符即 flag。
6. 闭环验证：用同样的 key 和表重新加密明文，结果应等于原密文；若不等，检查表方向、key 周期与是否误加索引。

## PoC

```python
import base64

cipher = ("QY/sxQrVKqD77KCTsVy97GHpwV4PMGjKAaYR7q76X7OxtUQbNudppkxAAk11MYHxxVDOsUaQMZDRrmCb"
          "QPyFznMFKxjpTmCssaO9DLD1i2i+9nVNVKCVsmDeMNoQUtrupt26AaYksZUTdu1ExVDnttrJijMWMKVj5ed"
          "KU7CipqD7BKCs7YWCwZhw7KjSpj7lVwSwxtN4i9VzVV7iTj75xLxCQqqF6wjsxVDbs7aQrxSmMPuJxmoFznS"
          "OTGhAUGrwsSULTPh9wZMq9G7VQLG3VNVprjjsVx4PsGCpUGURMn497GSseSdaCbu=")
standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
custom   = "VxKw7QTsMd5Bri83NZe9Ut6pChXzD4IAYqmLuakbHofRWycvjGPnS2JE/+l01OFg"
key      = b"Roses"

raw  = base64.b64decode(cipher.translate(str.maketrans(custom, standard)))
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
print(flag.decode())
# SDPCSEC{M155_1da_thank_y0u_f0r_solv1ng_her_troub7e}
```

如果解出乱码，优先检查是否多加了 `i`（错误写法 `key[i%5] ^ (value + i)`）或把自定义表/标准表写反；可用 `flag.encode()` 重新走一遍加密验证。

## 变体与关联

- **索引魔改变体**：如果 Base64 在查表前对 6 位索引做异或/加法，而不是对明文做 XOR，应按 [[ctf-reverse-base64-table-index-mutation]] 的方式先还原索引；本卡的内层 XOR 发生在 Base64 编码之前，两者顺序不同。
- **未知 key 变体**：若 key 不可直接从二进制提取，可用已知明文/格式前缀做重复 XOR 密钥恢复，见 [[ctf-crypto-repeating-xor-key-known-plaintext-oracle]]。
- **花指令变体**：本卡的 `xor/jz/E8` 垃圾字节修复见 [[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]。
- 边界：换表 Base64 + 固定 XOR 只是编码混淆，不是密码学保护；密钥和表都在二进制中时可完全还原。

## 检测与防御

- 对参赛/分析者：先定位编码函数与调用顺序，提取表和 key；用 re-encode 闭环验证，避免凭感觉加索引/偏移。
- 对题目设计者：不要把固定 key/表当作安全边界；若需保护 flag，应使用标准密码学与外部密钥，而不是自定义编码。
- 检测思路：二进制中出现 64 字符表、`key[i % N]` 形式的 XOR 循环、Base64 编码函数调用链；密文只含表内字符与 `=`。
