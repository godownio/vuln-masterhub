---
id: crypto-aes-cbc-padding-oracle-certificate-service
title: AES-CBC 填充预言机：证书校验服务用两种错误响应逐字节恢复密文
type: scenario
domain: crypto
path: crypto/aes
technique: aes-cbc-padding-oracle-certificate-service
tags:
- crypto
- aes
- cbc
- padding-oracle
- pkcs7
- certificate
- tcp
- byte-recovery
- oracle
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T02:17:09+08:00'
  notes: V118 指出的 PoC/代码错误已修正并重新 verify
url: /docs/crypto/aes/crypto-aes-cbc-padding-oracle-certificate-service/
draft: false
kb_aliases:
- AES-CBC padding oracle
- 填充预言机
- 证书校验填充泄露
- PKCS#7 padding oracle
---

## 一句话结论

当服务端对攻击者提交的密文先解密、再区分“填充错误”和“业务拒绝”两种响应时，AES-CBC 的链式异或结构会把填充校验结果变成逐字节解密的预言机；攻击者不需要密钥，只需约 16×256 次提交即可恢复整块明文，进而伪造管理员凭据。

## 原理

- CBC 解密：`P_i = D(C_i) XOR C_(i-1)`。修改前一块密文 `C_(i-1)` 的第 j 个字节，只会让 `P_i` 的第 j 个字节发生同样的 XOR 变化。
- PKCS#7 填充：最后一块明文必须是 `01`、`02 02`、…、`10×16` 之一。服务端先解密并校验填充，填充合法才进入业务校验。
- 两个可区分响应构成预言机：
  - 填充无效 → `format or padding error`；
  - 填充有效但业务拒绝 → `certificate rejected`。
- 恢复算法：从最后一块开始，已知后缀 `known[j]`，构造 `modified[j] = original[j] XOR known[j] XOR pad`，遍历 0x00–0xFF，命中合法填充后得到 `plain[j] = guess XOR pad XOR original[j]`；pad 从 0x01 递增到 0x10。
- 恢复前一块时，把目标块作为最后一块提交（例如三块 `C0 || modified(C1) || C2`），IV 保持原始值，避免引入额外变量。若服务允许控制 IV，可继续恢复第一块 `P1 = D(C1) XOR IV`。
- 0x01 填充存在假阳性：倒数第二个字节也可能碰巧构成合法填充。稳妥做法是命中 0x01 后再把前一个字节改成 0x02 强制验证 `02 02`，两次都通过才确认。

## 触发条件

- 攻击者能向服务提交任意密文，并获得至少两种可区分的错误响应（填充错误 vs 业务错误），或通过状态码、耗时、连接行为区分。
- 使用 CBC 模式且服务端校验 PKCS#7 填充；块大小通常为 16 字节。
- 目标密文长度是块大小的整数倍；IV 可控或位于密文最前面（如 `IV || C1 || C2...`）。
- 会话状态在恢复过程中保持有效；若服务把证书与当前连接绑定，必须在同一 TCP 连接内完成全部请求。
- 服务没有对填充错误做统一响应、随机延迟、限速或请求次数限制。

## 利用步骤

1. 探测服务形态：提交空串、错误长度、随机 hex，记录错误文案；提交一份格式合法但业务不符的样本，记录另一种响应。两种响应分别对应“填充无效”和“填充有效”。
2. 判定块大小：逐字节修改密文不同位置，观察响应变化的边界；影响范围严格按 16 字节出现即块大小为 16。修改某块只影响其后一块明文而非全部，指向 CBC 而非 ECB。
3. 切分密文：`C0` 作为 IV，`C1..Cn` 为密文块；从最后一块 `Pn` 开始恢复。
4. 对 `Pn` 的每个字节，按 pad 从 0x01 到 0x10，构造 `modified(C_(n-1))` 并提交 `C0 || ... || modified(C_(n-1)) || Cn`；命中 `certificate rejected` 即填充合法，计算明文字节。
5. 恢复 `P_(n-1)` 时提交 `C0 || ... || modified(C_(n-2)) || C_(n-1)`，把 `C_(n-1)` 当作最后一块；重复直到恢复所有块。
6. 拼接明文，按业务格式提取 credential/会话密钥，提交到最终接口验证。

## PoC

```python
# 通用骨架：oracle(ct) 返回 True 表示“填充合法、业务拒绝”
def recover_block(prev: bytearray, target: bytes, oracle, bs=16) -> bytes:
    known = bytearray(bs)
    plain = bytearray(bs)
    for pad in range(1, bs + 1):
        idx = bs - pad
        base = bytearray(prev)
        for j in range(idx + 1, bs):
            base[j] = prev[j] ^ known[j] ^ pad
        for guess in range(256):
            base[idx] = guess
            if oracle(bytes(base) + target):
                plain[idx] = guess ^ pad ^ prev[idx]
                known[idx] = plain[idx]
                break
    return bytes(plain)

# 恢复最后一块：oracle 提交 modified(C_(n-1)) || Cn
# 恢复前一块：把 C_(n-1) 当作 target，修改 C_(n-2)
```

```text
恢复顺序（64 字节证书 = IV + 3 个密文块）：
  P3 = D(C3) XOR C2   -> 提交 C0 || C1 || modified(C2) || C3
  P2 = D(C2) XOR C1   -> 提交 C0 || modified(C1) || C2
  P1 = D(C1) XOR C0   -> 提交 modified(C0) || C1（IV 可控时）
```

无真实目标 PoC：原文为 CTF 服务，PoC 需按实际协议实现 socket 交互；上述骨架可直接替换 `oracle` 函数复用。

## 变体与关联

- **只校验最后一块**：服务只检查最后一块填充时，恢复最后一块后可直接伪造任意前缀块；若服务校验所有块，需要逐块恢复。
- **IV 不可控**：若服务固定 IV 或对 IV 做完整性校验，无法恢复第一块，只能从第二块开始。
- **错误响应差异**：状态码、响应长度、连接是否关闭、耗时均可作为预言机；统一错误文案 + 固定延迟可防御。
- **加密后 MAC**：先加密再 MAC（EtM）或使用 AEAD（GCM/CCM）可从根本上消除填充预言机。
- **关联**：Shiro-721 的 rememberMe Padding Oracle、CBC 翻转攻击、AEAD 误用、密钥硬编码。

## 检测与防御

- **统一错误响应**：填充错误与业务错误返回同一状态码/同一文案/同一长度，避免可区分；不要在错误信息中暴露“padding”字样。
- **恒定时间与限速**：对解密失败路径加入固定延迟或随机抖动；按来源/IP/会话限速，检测大量失败提交。
- **使用 AEAD 或 Encrypt-then-MAC**：AES-GCM/ChaCha20-Poly1305 自带完整性；CBC 场景先计算 HMAC 再解密，MAC 失败直接拒绝，不进入填充校验。
- **会话隔离**：不要把证书/凭据校验与长连接状态强绑定，减少攻击者逐字节试探的便利；对同一连接内的失败次数设上限。
- **日志与检测**：监控同一来源对证书/解密接口的高频提交、响应码分布、密文逐字节变化模式；对 `format or padding error` 类错误集中告警。

## 可信度与边界

- 原文为 CTF 题，完整攻击链与最终 credential 提交均有服务响应验证；恢复算法、块大小与 CBC 模式判定有实测依据。
- 具体服务菜单、证书布局（IV 前置、64 字节）与错误文案为该题实现；真实目标需重新探测块大小、模式和响应差异。
- 未在真实目标复跑 PoC；卡内不包含题目 flag。
