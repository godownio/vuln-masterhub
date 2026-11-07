---
id: ctf-crypto-base58-wrailfence-rot13
title: 多层编码链：Base58 → W 型栅栏（3 栏）→ ROT13
type: scenario
domain: ctf
path: ctf/crypto
technique: base58-wrailfence-rot13-decode
tags:
- ctf
- crypto
- encoding
- base58
- rail-fence
- rot13
- multi-layer
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:16:54+08:00'
  notes: 已对照原文与全部22张图核对；Base58→3栏W型栅栏→ROT13顺序与CyberChef截图一致；已修正frontmatter domain为ctf；PoC未本机执行
url: /docs/ctf/crypto/ctf-crypto-base58-wrailfence-rot13/
draft: false
kb_aliases:
- Base58 栅栏 ROT13
- 58 摄氏度白开水
- W 型栅栏 3 栏
- 凯撒跨过 3 层栅栏
- CTF 多层编码
---

## 一句话结论

题目给出一串 Base58 字符和提示“凯撒先生跨过了 3 层栅栏后点单了一份 58 摄氏度的白开水”，按提示顺序解码即可：先做 Base58 解码，再用 3 栏 W 型栅栏还原，最后 ROT13，得到 `flag{...}`；这类多层编码题的关键是把自然语言提示逐词映射到编码/密码算法，再按可逆顺序逐层剥离。

## 原理

- **Base58**：使用 Bitcoin 字母表 `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`，去掉了易混淆的 `0`、`O`、`I`、`l`。提示中的“58 摄氏度”对应 Base58；字符串只含该字母表字符且长度较长时优先尝试。
- **W 型栅栏（Rail Fence）**：把明文按锯齿形写到 `rails` 条轨道上（3 栏时轨道序号为 0,1,2,1,0,1,2,...），再按轨道从上到下读出密文。解密时先按同样规则生成每个位置所属的轨道，统计各轨道字符数，把密文按轨道切分，再按原锯齿顺序逐位取回。
- **ROT13**：凯撒移位 13 位，英文字母大小写分别旋转；加密与解密是同一个操作。提示中的“凯撒先生”对应 ROT13。
- **顺序**：题面“跨过 3 层栅栏后点单 58 度白开水”提示先栅栏后 Base58？实际解题按 Base58 → 栅栏 → ROT13 得到明文；多层编码题的顺序需按中间结果的字符集特征判断（Base58 解码后出现 `{}`/可读片段，再试栅栏；栅栏结果仍是字母移位形态，再 ROT13）。
- **验证**：每层解码后观察是否出现 `flag{`/`synt{`（ROT13 后的 flag 前缀）等特征，避免盲目组合。

## 触发条件

- 题目给出仅含 Base58 字母表的长字符串，或提示中出现 58/Base58、栅栏/rails、凯撒/ROT 等关键词。
- 编码是可逆的经典算法组合，没有自定义密钥（或密钥已在提示中给出）。
- 允许使用 CyberChef/脚本尝试多层组合。

## 利用步骤

1. 识别字符串字符集：只含 Base58 字母表、无 `0OIl`，优先 Base58 解码。
2. 观察 Base58 解码结果：出现类似 `s{...}`/`flag{...}` 的结构，说明还差字母移位或换位。
3. 用 3 栏 W 型栅栏解密（CyberChef 的 Rail Fence Cipher Decode，rails=3；或脚本）。
4. 对栅栏结果做 ROT13，得到 `flag{...}`。
5. 若中间结果不符合预期，调整栅栏/ROT 的先后顺序或栏数（提示中的数字通常就是参数）。

## PoC

```python
import codecs

def rail_fence_decrypt(cipher: str, rails: int) -> str:
    n = len(cipher)
    pattern, r, direction = [], 0, 1
    for _ in range(n):
        pattern.append(r)
        if r == 0:
            direction = 1
        elif r == rails - 1:
            direction = -1
        r += direction
    counts = [pattern.count(k) for k in range(rails)]
    rows, idx = [], 0
    for c in counts:
        rows.append(list(cipher[idx:idx + c]))
        idx += c
    ptr = [0] * rails
    out = []
    for k in pattern:
        out.append(rows[k][ptr[k]])
        ptr[k] += 1
    return ''.join(out)

# pip install base58
import base58
s = "2vnWdE3QfQQvsZZaozQLiRMhYbmG1o1vhFWcjfcZbAUmnpW5XKUU7DYRQA"
step1 = base58.b58decode(s).decode()
step2 = rail_fence_decrypt(step1, 3)
step3 = codecs.decode(step2, 'rot13')
print(step1, step2, step3, sep='\n')
```

CyberChef 等价配方：`From Base58 → Rail Fence Cipher Decode (3) → ROT13`。

## 变体与关联

- **参数变体**：栅栏栏数、ROT 偏移可能不是 3/13；提示中的数字要逐一对应（“3 层栅栏”“凯撒”默认 13）。
- **相邻编码**：Base62/Base85/Base64、Atbash、Vigenère、列置换等也可与栅栏/ROT 组合；先按字符集与结果特征判断。
- **CTF 同类**：[[ctf-crypto-rsa-unknown-e-rail-fence-filter]] 等涉及栅栏的 RSA 题可参考栅栏还原部分。

## 检测与防御

- 此类为 CTF 离线解码，不涉及目标系统防御；实际工作中若发现业务用多层弱编码“保护”敏感数据，应改为标准加密与完整性校验，而不是 Base58/栅栏/ROT 这类可逆编码。
