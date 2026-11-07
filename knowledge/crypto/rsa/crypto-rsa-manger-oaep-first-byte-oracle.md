---
id: crypto-rsa-manger-oaep-first-byte-oracle
title: Manger RSA-OAEP 首字节零预言机：三步区间压缩恢复明文
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-manger-oaep-oracle
aliases:
- Manger 攻击
- RSA-OAEP 预言机
- 首字节零预言机
- OAEP padding oracle
- Manger's attack
tags:
- rsa
- oaep
- padding-oracle
- manger
- chosen-ciphertext
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:38+08:00'
  notes: 已对照原文核对：B=2^{8(k-1)}、2B<n、Step1 f1 翻倍、Step2 f2 初始化与递增、Step3 f/i/f3 公式均与原文一致；原文 _step_1 写作 while padding_oracle(...)，与其 oracle 定义极性相反，卡片已改为 while not 并在说明中标注。未验证点：PoC 未端到端复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

RSA-OAEP 解密时会检查恢复出的整数 `m` 是否小于 `B = 2^{8(k-1)}`（首字节为 `0x00`）。如果服务端把这个检查结果以可区分的方式返回，攻击者提交 `c·f^e mod n` 并观察 `f·m mod n < B` 是否成立，用三步区间压缩即可在约 `log2(n)` 次查询内恢复完整明文。

## 原理

- OAEP 解码前，RSA 解密得到整数 `m`；合法 OAEP 块要求 `m < B`，其中 `k` 是模数字节长度，`B = 2^{8(k-1)}`。服务端若对“首字节是否为 0”给出不同响应，就构成一个比特预言机。
- 提交 `c' = c·f^e mod n`，解密得到 `m' = f·m mod n`；oracle 返回的是布尔值 `[f·m mod n < B]`。
- **Step 1**：从 `f1=2` 开始不断翻倍，直到首次出现 `f1·m mod n < B`。这给出一个缩放因子，使 `m` 落入 `[0, B/f1)` 附近的区间。
- **Step 2**：令 `f2 = floor((n+B)/B)·f1/2`，若 oracle 为假则每次加 `f1/2`，直到 oracle 为真。此时区间收缩为 `[ceil(n/f2), floor((n+B)/f2)]`，宽度约 `B/f2`，且包含 `m`。
- **Step 3**：在区间 `[mmin, mmax]` 上做二分：取 `f = floor(2B/(mmax-mmin))`、`i = floor(f·mmin/n)`、`f3 = ceil(i·n/mmin)`；查询 `f3`，根据 oracle 结果把 `mmax` 或 `mmin` 更新为 `(i·n+B)/f3` 或 `ceil((i·n+B)/f3)`。区间不断缩小，最终 `mmin` 即明文。
- 攻击成立的关键是 `2B < n`，且 oracle 只泄露“是否小于 B”这一比特；它不需要私钥，也不需要知道 OAEP 的随机种子。

## 触发条件

- 服务端使用 RSA-OAEP 解密，并把“首字节是否为 0x00 / OAEP 解码是否通过”以可区分方式返回（错误信息、状态码、连接行为、耗时）。
- 攻击者已知 `n`、`e`、目标密文 `c`，能反复提交任意密文。
- `2B < n`（标准 RSA 模数满足）。
- 无速率限制或查询预算足够（约 `n.bit_length()` 次）。

## 利用步骤

1. 从公钥提取 `n`、`e`，确认服务端使用 OAEP 且错误可区分。
2. 实现 `padding_oracle(trial_c)`：发送密文，按响应判断解密结果首字节是否为 `0x00`；注意 True 必须对应“小于 B”。
3. Step 1：`f1=2`，当 oracle 为假时 `f1*=2`，直到首次为真。
4. Step 2：按公式初始化 `f2`，当 oracle 为假时 `f2 += f1//2`，直到为真。
5. Step 3：按区间二分公式迭代，直到 `mmin == mmax`。
6. 返回 `mmin`，转字节；去掉 OAEP 填充后得到消息。

## PoC

```python
from pwn import *
from sage.all import ZZ
import logging

logging.basicConfig(level=logging.INFO)

HOST = 'target.example.com'
PORT = 1337
N = ZZ(0x...)
E = ZZ(65537)
C = ZZ(0x...)

def padding_oracle(trial_c):
    try:
        io = remote(HOST, PORT, level='error')
        io.sendline(hex(trial_c).encode())
        response = io.recvall()
        io.close()
        # True 表示解密结果首字节为 0x00（m < B）
        return b"Success" in response or b"Decrypted" in response
    except Exception as e:
        logging.error(f"Oracle connection error: {e}")
        return False

def _step_1(oracle, n, e, c):
    f1 = 2
    while not oracle((pow(f1, e, n) * c) % n):
        f1 *= 2
    return f1

def _step_2(oracle, n, e, c, B, f1):
    f2 = ((n + B) // B) * f1 // 2
    while not oracle((pow(f2, e, n) * c) % n):
        f2 += f1 // 2
    return f2

def _step_3(oracle, n, e, c, B, f2):
    mmin = (n + f2 - 1) // f2          # ceil(n / f2)
    mmax = (n + B) // f2               # floor((n + B) / f2)
    while mmin < mmax:
        f = (2 * B) // (mmax - mmin)
        i = (f * mmin) // n
        f3 = (i * n + mmin - 1) // mmin  # ceil(i*n / mmin)
        if oracle((pow(f3, e, n) * c) % n):
            mmax = (i * n + B) // f3
        else:
            mmin = (i * n + B + f3 - 1) // f3
    return mmin

def manger_attack(oracle, n, e, c):
    k = (n.bit_length() + 7) // 8
    B = 2 ** (8 * (k - 1))
    assert 2 * B < n, "Manger 条件不满足: 2B 必须小于 N"
    f1 = _step_1(oracle, n, e, c)
    f2 = _step_2(oracle, n, e, c, B, f1)
    return _step_3(oracle, n, e, c, B, f2)

m = manger_attack(padding_oracle, N, E, C)
print(m)
print(hex(int(m)))
```

> 说明：原文脚本的 `_step_1` 写作 `while padding_oracle(...)`；若 oracle 的 True 表示“首字节为 0”，正确极性应为 `while not oracle(...)`。实际题目必须按返回值调整。

## 变体与关联

- 变体：oracle 返回的是“OAEP 解码是否成功”而非严格的“首字节为 0”，只要失败条件与 `m < B` 等价即可。
- 变体：若服务端只泄露“m 的最高位”而不是 `< B`，可先做区间归一化，再套类似的二分。
- 变体：PKCS#1 v1.5 的填充合法性对应 Bleichenbacher 攻击，查询量与区间结构不同。
- 关联：[[crypto-rsa-bleichenbacher-pkcs1v15-padding-oracle]]、[[crypto-rsa-lsb-parity-oracle]]、[[crypto-rsa-rabin-random-square-root-oracle]]。

## 检测与防御

- 防御：OAEP 解码失败必须返回统一错误、统一状态码、恒定时间，不能泄露“首字节是否为 0”。
- 防御：对解密接口做认证、速率限制和查询审计；新协议优先使用 ECDHE 等不依赖 RSA 解密的密钥交换。
- 检测：同一来源高频提交不同密文、每次密文呈 `c·f^e` 结构、响应耗时/长度分布异常。
- 响应：确认预言机存在后下线或改为恒定时间实现，轮换密钥并审计历史解密请求。
