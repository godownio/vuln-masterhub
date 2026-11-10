---
id: ctf-crypto-dsa-linear-related-nonce-lattice-k0-forgery
title: DSA 多次签名 nonce 线性相关：构造 q-对角格 + A_i/B_i 关系，LLL 恢复 k0 后伪造 admin 签名
type: scenario
domain: ctf
path: ctf/crypto
technique: dsa-linear-related-nonce-lattice-k0-forgery
aliases:
- DSA 格攻击
- Signature 题
- k_i = A_i k0 + B_i
- LLL 恢复 k0
- DSA 伪造签名
- 春秋杯 Signature
- DSA nonce 线性关系
tags:
- ctf
- crypto
- dsa
- lattice
- lll
- nonce
- signature-forgery
- sage
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V312
  verified_at: '2026-11-08T12:50:51+08:00'
  notes: 已对照原文 content.md 逐项核对：DSA 签名方程、消去 x 得 r0*s_i*k_i-r_i*s0*k0≡r0*h_i-r_i*h0、A_i/B_i 定义与原文公式一致（原文 r_1*s_0 按 i=1 记号笔误处理）；exp 中 inverse((r0*S[i]),q)*(R[i]*s0) 与 B 公式、q-对角+末两行 A/B+K=2^128 的格、abs(line[-1])==K 取 k0、再对 admin 签名均与卡片一致。卡片明确指出 exp 的 halib.sha256 笔误、p 被 socket 覆盖、仅判 line[-1]==K 等问题，并注明 option 2 读到的 x 语义原文未解释。dedup 除自身外 related 为 ECDSA nonce 复用/部分 nonce/HNP 等，均为已知 nonce 信息的格攻击，本卡是 DSA nonce 线性关系+消元，非同一链；dup-scan 无涉及本卡 pair。原子性：单一 DSA 格攻击场景，不拆分。未验证点：原文未展示拿到 flag/通过校验的截图，exp 按原样不可直接运行（卡片已披露），confidence 为 medium 合理；无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

同一 DSA 私钥对多条已知消息签名时，任意两条签名消去私钥后可得到 `k_i ≡ A_i·k_0 + B_i (mod q)` 的线性关系；把 `A_i、B_i` 写进以 q 为对角的格并做 LLL，找出最后一位等于权重 K 的短向量即可读出 `k_0`，再用恢复出的 `k_0` 为 `admin` 计算 `r = g^k0 mod p mod q`、`s = k0⁻¹(h + x·r) mod q` 并通过服务端校验。

## 原理

- **DSA 签名方程**：`s = k⁻¹(h + x·r) mod q`，等价于 `k = s⁻¹·h + s⁻¹·r·x mod q`，其中 h 是消息哈希、x 是长期私钥、k 是每次签名的新鲜 nonce。
- **两条签名消去 x**：对第 0 条和第 i 条签名分别有 `k_0 = s_0⁻¹(h_0 + x r_0)`、`k_i = s_i⁻¹(h_i + x r_i)`，消去 x 得
  `r_0·s_i·k_i − r_i·s_0·k_0 ≡ r_0·h_i − r_i·h_0 (mod q)`。
  两边乘 `(r_0 s_i)⁻¹` 后令
  `A_i = (r_0 s_i)⁻¹·(r_i s_0) mod q`，`B_i = (r_0 s_i)⁻¹·(r_0 h_i − r_i h_0) mod q`，
  即 `k_i ≡ A_i·k_0 + B_i (mod q)`。原文公式把其中一项写成 `r_1 s_0`，与推导中的 `r_i s_0` 对应（i=1 时一致），属于记号笔误。
- **为什么要用格**：每个 k_i 都通过 A_i、B_i 绑定到同一个 k_0，未知量从 n 个 nonce 降为 k_0 一个，但模 q 的同余仍需在整数格中找“短”的解。构造 `(n+2)×(n+2)` 矩阵：前 n 行前 n 列为 q（用于吸收模 q 的整数倍），倒数第二行前 n 列为 A_i、该行对角线为 1，最后一行前 n 列为 B_i、最后一列为权重 K（原文取 `K = 2^128`）。用系数向量 `(k_1,…,k_n, k_0, 1)` 左乘该矩阵，得到的目标向量前 n 个坐标对应各 k_i、倒数第二个坐标为 k_0、最后一位固定为 K。LLL 约减后，若某一行最后一位的绝对值等于 K，则该行倒数第二位就是恢复出的 k_0。
- **为什么能恢复**：当 nonce 的尺度明显小于 q 时，目标向量在格中相对“短”，LLL 会把它约减出来；权重 K 的作用是把最后一位与非零解绑定，便于在约减结果中识别正确行（原文通过 `abs(line[-1]) == K` 筛选）。
- **伪造**：拿到 k_0 后，对 `admin` 的消息哈希 `hh` 计算 `r = (g^k0 mod p) mod q`、`s = k_0⁻¹(hh + x·r) mod q`，把 `(r,s)` 发给服务端；只要 x 是服务端校验所用的长期私钥，签名即通过。原文 exp 在发送前从服务端读取了一个值 x（option 2），该值在题目中的具体语义（私钥/共享密钥）原文没有解释，复现时需按题目协议确认。

## 触发条件

- 服务端使用 DSA（或同构的 ElGamal 签名）且多条签名的 nonce 之间存在可利用的线性关系；本题把每个用户名对应的 nonce 设计成可由前一条推导。
- 能获得至少两条同一私钥、已知消息哈希的签名 `(r,s)`；原文取了 8 条（用户名 `a`、`aa`…，哈希用 SHA-256）。
- 有 SageMath 的 `Matrix(ZZ, ...).LLL()`；q 为大素数。
- 需要向服务端提交 `admin` 的签名，或题目提供可读取签名私钥/共享值的接口。

## 利用步骤

1. 先完成题目的 PoW/交互，拿到 `(p, q, g)` 和服务端公钥。
2. 对 8 个已知用户名各请求一次签名，记录 `(r_i, s_i)`，并计算 `h_i = int(sha256(name), 16)`。
3. 任选第 0 条为基准，按公式计算 `A_i = inverse(r0*s_i, q) * (r_i*s0) % q`、`B_i = inverse(r0*s_i, q) * (h_i*r0 - h0*r_i) % q`（i=0 时 A=1、B=0，可跳过或保留）。
4. 构造 `(n+2)×(n+2)` 格：前 n 行对角为 q；`Ge[-2, i] = A[i]`、`Ge[-2, -2] = 1`；`Ge[-1, i] = B[i]`、`Ge[-1, -1] = K`（K=2^128）。
5. `LLL()` 后遍历每一行，找 `abs(line[-1]) == K` 的行，取 `k0 = line[-2]`；若符号不对可试 `-k0`。
6. 用 k0 对 `admin` 计算 `(r, s)` 并提交；若服务端要求 r 与服务端保存的值一致，需用同一 k0 重新计算。
7. 失败排查：确认 h 的字节序/哈希算法、r 是否取 `mod q`、A/B 的索引是否与题目一致、K 的取值是否足够大于 nonce 上界。

## PoC

核心格构造与 k0 提取（SageMath；按原文整理）：

```python
def get_k(R, S, H, q):
    n = len(R)
    r0, s0, h0 = R[0], S[0], H[0]
    A, B = [], []
    for i in range(n):
        inv = inverse(r0 * S[i], q)
        A.append(inv * (R[i] * s0) % q)
        B.append(inv * (h0 * R[i] - H[i] * r0) % q)   # 与原文等价，符号取反后同样可解

    Ge = Matrix(ZZ, n + 2, n + 2)
    for i in range(n):
        Ge[i, i] = q
        Ge[-2, i] = A[i]
        Ge[-1, i] = B[i]
    K = 2 ** 128
    Ge[-2, -2] = 1
    Ge[-1, -1] = K

    for line in Ge.LLL():
        if abs(line[-1]) == K:
            return line[-2]
```

最终用 k0 签名（原文片段）：

```python
k0 = get_k(R, S, H, q)
r = pow(g, k0, p) % q
hh = int(hashlib.sha256(b"admin").hexdigest(), 16)
s = pow(k0, -1, q) * (hh + x * r) % q
send_sig(r, s)
```

原文 exp 的已知问题（复现时需修）：PoW 用 `itertools.product` 暴力枚举 19 位大小写（2^19 次 SHA-256），开销较大；代码中 `halib.sha256` 是 `hashlib` 笔误；pwntools 的 `p` 变量与素数 p 同名，拿到 `(p,q,g)` 后原始 socket 对象被覆盖；`get_k` 只按 `line[-1] == K` 判断，实际可能需同时检查 `-K`。这些不影响格构造本身，但说明该 exp 未按原样复跑。

## 变体与关联

- **nonce 复用**：所有 k 相同（A=1、B=0）时退化为一对签名直接求私钥，见 [[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]（ECDSA 版本，DSA 同理）。
- **部分 nonce 泄露**：若只知道 k 的高位而非线性关系，用 HNP/CVP 格，见 [[crypto-ecc-ecdsa-partial-nonce-leak-lattice]]。
- **DSA 弱 nonce 的其它形态**：k 由小范围随机数生成可直接枚举；k 与消息/时间线性相关可整理成同样形式的格。
- **ECDSA 对应**：把曲线运算换成椭圆曲线群即可；格的构造和消元公式一致。
- **边界**：K 的取值要大于 nonce 上界且小于 q 量级；若 nonce 与 q 同尺度，短向量假设不成立，需要改用更多同余关系或已知位信息。

## 检测与防御

- **实现侧**：DSA/ECDSA 的 nonce 必须是每次独立的 CSPRNG 输出，禁止用时间戳、计数器、用户输入或可预测种子；RFC 6979 的确定性 nonce 是更稳妥的做法。
- **不要复用 k**：同一私钥下 k 复用或线性相关会直接泄私钥/nonce，进而可伪造任意消息签名。
- **参数与哈希**：使用标准 q 长度（DSA 2048/256），校验 r、s 范围，避免小 q 或哈希截断带来的额外弱点。
- **检测**：监控同一签名密钥下大量签名请求、r 重复或近似关系；对签名服务做速率限制与审计，但这只能降低采样量，不能替代正确实现。
- **合规**：仅在 CTF/授权环境复现，勿对生产签名服务尝试伪造。
