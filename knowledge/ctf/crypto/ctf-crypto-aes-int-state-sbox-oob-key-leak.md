---
id: ctf-crypto-aes-int-state-sbox-oob-key-leak
title: C 自实现 AES-ECB 用 int[16] 存 state：sbox 越界索引读 0，解密逆字节代换泄露 key⊕0x52，爆破前 3 字节恢复完整密钥
type: scenario
domain: ctf
path: ctf/crypto
technique: aes-int-state-sbox-oob-key-recovery
aliases:
- encrypted runner
- AES 自实现类型误用
- int 数组存 state
- sbox 越界
- 汉字 ord 大于 256
- 逆字节代换 0x52
- 轮密钥加泄露密钥
- 3 字节爆破
tags:
- aes
- ecb
- sbox
- out-of-bounds
- type-confusion
- key-recovery
- ctf
- crypto
- reverse
- gdb
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-12
  verified_at: '2026-11-08T07:15:33+08:00'
  notes: 已对照原文核对：sbox[0x52]=0 与 InvSubBytes(0)=0x52 经 gdb dump 与逐字节 ^0x52 验算吻合，原文实测泄出 key[3:]+爆破得到完整 key；PoC 段自注未执行为保守表述，原文已跑通。未验证点为未在本机重跑。
---

## 一句话结论

当自实现 AES-ECB 用 `int input[16]`（4 字节）而非 `unsigned char` 保存 state、且 `SubBytes` 直接用该 4 字节值索引只有 256 项的 sbox 时，输入 ord>255 的字符（如汉字）会让索引越界读到 sbox 之后的全 0 内存，使加密各轮 state 退化为 0；利用加解密过程互相抵消，解密到末轮「逆字节代换前仍为 0」，而 InvSubBox 把 0 映射为固定索引 0x52，最后一次 AddRoundKey 与原始密钥逐字节异或，于是输出泄露 `key ^ 0x52`，再爆破未知的前 3 字节即可还原完整 16 字节密钥。

## 原理

- 标准 AES state 是 16 个 `unsigned char`；本题 `main` 里 `int input[16]`，`scanf("%x", &input[i])` 读入的每个元素占 4 字节，可容纳 >255 的值。Python 侧 `data = [ord(c) for c in data]` 把汉字（ord 远大于 255）原样作为 int 传入。
- `SubBytes` 实现为 `state = (unsigned __int8)sbox[*(unsigned int *)state_ptr]`：索引用的是整个 4 字节 int 而非单字节。sbox 只有 256 项（0x00–0xff），越界后（gdb 可见 sbox 之后 `.data` 是一大段 00）读到 0，故从第一次字节代换起这些位置恒为 0，后续 ShiftRows/MixColumns/AddRoundKey 都以 0 参与。
- 加密与解密是互逆的，除「被破坏的那一段」外整体抵消，因此只需关注：加密首轮 AddRoundKey → 字节代换（越界变 0）… ↔ 解密末轮。解密到最后一轮、逆字节代换之前 state 仍是这些 0。
- 逆字节代换用 rsbox 查「哪个索引的值是 0」：在 sbox 中值 0x00 出现在索引 0x52，故 0 经 InvSubBytes 变成 0x52（13 个位置都是 0x52）。随后最后一次 `AddRoundKey(0xA, ...)`（等价于与初始密钥 W[0,3] 逐字节异或）输出 = `0x52 ^ key[i]`。
- 于是发一个「首 3 字节为合法命令、后 13 字节用汉字」的加密请求，再 `run` 解密，命令执行报错信息里会带出解密后明文的可见/八进制表示；还原成原始字节后对后 13 字节 `^0x52` 即得 key[3:16]。
- 前 3 字节未泄露：用同一密钥加密一段已知明文（题目可正常 `encrypt`）拿到参考密文，本地用标准 AES-ECB 三重循环枚举 256^3 个前 3 字节，比对密文即可补全（本题得完整 key）。

## 触发条件

- 目标使用自实现 AES（非标准库），state 元素为 int/4 字节且 SubBytes 未对索引做 `&0xff`/范围检查。
- sbox 之后的内存可控为 0（或至少稳定已知），使越界读结果确定。
- 存在「加密任意输入」与「解密并回显/执行解密结果」的双向接口（encrypt/run），能把泄露的字节带出来。

## 利用步骤

1. 审计/逆向 AES 实现，确认 `int state[16]`、`sbox[int]` 未截断、sbox 后内存为 0。
2. 构造 `encrypt ls <13 个 ord>255 的字符>`（汉字），使后 13 个 state 越界变 0，得到密文。
3. 用 `run <密文>` 让服务端解密并执行；从报错/回显里提取解密后的原始字节（把 shell 的 `$'\017'` 八进制转义还原为字节）。
4. 对后 13 字节逐字节 `^0x52` 得到 key[3:16]。
5. 正常 `encrypt` 一段已知明文得到参考密文；本地三重循环爆破前 3 字节，比对密文，拼出完整 16 字节 key。

## PoC

```text
# 泄露后 13 字节
encrypt ls 啊啊啊啊啊啊啊啊啊啊啊啊啊        -> Encrypted command: <hex>
run <hex>                                    -> 报错带出解密明文(含 $'\017' 等八进制转义)
out = b'ls <13 原始字节>'                    # 还原 shell 转义，非 $'' 字面
key_tail = bytes(o ^ 0x52 for o in out[3:]) # 得 key[3:16]

# 爆破前 3 字节（伪代码，占位值）
for i in range(256):
  for j in range(256):
    for k in range(256):
      if AES_ECB(bytes([i,j,k])+key_tail).encrypt(known_plaintext).hex() == reference_ciphertext:
        key = bytes([i,j,k])+key_tail
```

（最小化示意，密文/密钥/明文为占位，未执行任何 PoC。）

## 变体与关联

- 变体：越界读到的不是 0 而是其他稳定值时，InvSubBox 的「反查索引」随之改变，公式推广为 `输出 = InvSBox[越界读值] ^ key`。
- 关联：与库内「AES-128 辅助表泄露 RK9/RK10 反推主密钥」「白盒 AES 运行时表重建 / 差分故障分析 DFA 恢复轮密钥」「魔改 AES MixColumns 0x55 写注册机」同属「AES 实现缺陷/密钥恢复」族，但本卡根因是 **int 类型误用导致的 sbox 越界读**，而非辅助表、查表重建或故障注入。
- 关联：拿到 key 后可接「用泄露密钥伪造加密命令绕过白名单实现 shell 命令注入」（本批另有对应卡），构成完整 flag 链。
- 边界：本卡只到「恢复完整密钥」；危害程度取决于该密钥保护的下游数据/命令。

## 检测与防御

- 检测：审计自实现密码算法中 state/索引的类型（应为 `uint8_t`、索引需 `&0xff`）、对 sbox/rsbox 访问加边界断言；动态检测越界读。
- 防御：改用标准库 AES 实现、对输入字节做范围校验、state 用无符号单字节类型、编译期开启 UBSan/ASan 捕获越界；对「加密预言机 + 解密执行」的双向接口做认证（如 HMAC，题目总结亦指出 `hmac would have been better`）。
