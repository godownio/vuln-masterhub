---
id: ctf-crypto-wagner-generalized-birthday-sha3-mod-collision
title: Wagner 广义生日求 SHA3-512 模素数 k-sum：8 路合并构造哈希碰撞过服务端校验
type: scenario
domain: ctf
path: ctf/crypto
technique: wagner-generalized-birthday-sha3-mod-k-sum
tags:
- ctf
- crypto
- wagner
- generalized-birthday
- k-sum
- hash-collision
- sha3
- modular-arithmetic
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:26+08:00'
  notes: 已对照原文与脚本核对：SHA3-512(r||suffix) mod N、tree_height=3、8 个 r、N=4722366482869645213711；实测 N 为73位素数，已把卡片中误写的约40位/72位修正为73位。未验证点：未连接远程靶场运行 wagner.solve。frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-wagner-generalized-birthday-sha3-mod-collision/
draft: false
kb_aliases:
- Wagner 算法
- 广义生日攻击
- k-sum 哈希碰撞
- SHA3-512 模素数碰撞
- HashBaseWorld
- conduition/wagner
---

## 一句话结论

当服务端把 `SHA3-512(r || suffix) mod N` 当作哈希并要求提交一组 `r` 使这些哈希满足碰撞/求和条件时，可以把问题化成模 `N` 的 k-sum：用 Wagner 广义生日算法按 `tree_height` 分层合并候选，每层只保留低若干位相同的组合，最终在 `2^tree_height` 个叶子中找到一组哈希值之和 ≡ 0（或目标值）的 `r`；原文用 `tree_height=3`（8 个 r）在 73 位模数上快速命中。

## 原理

- **问题形式**：哈希函数 `H(r) = int(SHA3-512(r_bytes || suffix)) mod N`，`r_bytes` 长度按 `N.bit_length()` 向上取整。服务端给出固定的 `suffix`，要求攻击者提交若干 `r`，使 `Σ H(r_i) ≡ 0 (mod N)`（或满足其碰撞条件）。
- **广义生日（Wagner）**：朴素生日攻击找两两碰撞需要 `2^(n/2)`；Wagner 把 k-sum 组织成深度为 `tree_height` 的二叉树：叶子是随机候选 `(H(r), r)`，每层把两组列表按“哈希和在模 `2^b` 下相等”合并，逐步消去低位，最后剩下满足完整模 `N` 条件的组合。`tree_height=3` 表示 8 个叶子（2³），每一层降低一部分模数位数，总候选量远小于暴力枚举。
- **为什么适用于本题**：`N` 为 73 位素数（原文 `4722366482869645213711`），直接把 8 个随机哈希求和命中 0 的概率是 `1/N`，不可行；分层只匹配低位后，每层组合数可控，最终 8 路合并把搜索复杂度降到可接受范围。
- **Lineage 结构**：`wagner.Lineage(hash_value, r)` 保存当前节点的哈希值与原始 `r`（以及合并历史）；`wagner.solve(N, tree_height, generator)` 返回一组 `r` 值，调用方再把每个 `r` 与 `suffix` 拼成消息提交。
- **成立前提**：哈希对 `r` 没有额外结构限制（随机预言机假设），且服务端确实按模 `N` 求和/比较；`tree_height` 与所需消息条数要和协议匹配（原文为 8 条）。

## 触发条件

- 服务端提供一个固定后缀 `suffix`，对攻击者提交的 `r` 计算 `SHA3-512(r || suffix) mod N` 并要求一组值满足求和/碰撞条件。
- `N` 的位数使朴素生日攻击不可行，但足以让 Wagner 分层合并跑完。
- 能使用 `conduition/wagner` 等实现（或自行实现 Wagner 合并）；能按协议连续提交多条消息。
- 原文靶场为动态 flag，脚本需在线连接。

## 利用步骤

1. 连接服务端，先按协议发送初始 `x/y/z`（原文用带双空格的字符串影响后缀生成），读取服务端返回的 `suffix` 十六进制。
2. 定义生成器：随机取 `r`，按 `N.bit_length()` 计算字节长度，计算 `SHA3-512(r_bytes || suffix) mod N`，返回 `wagner.Lineage(hash, r)`。
3. 调用 `wagner.solve(N, tree_height=3, generator=generator)`，得到 8 个 `r`。
4. 把每个 `r` 转为固定长度十六进制，与 `suffix` 拼接，按协议逐条发送。
5. 读取服务端响应；若校验通过则返回 flag（原文为动态 flag，给出了复现实例）。

## PoC

```python
import hashlib, random
import wagner  # https://github.com/conduition/wagner

MODULUS = 4722366482869645213711
SUFFIX = bytes.fromhex("<服务端返回的 suffix>")

def make_generator(n, suffix):
    rlen = (n.bit_length() + 7) // 8
    def gen(modulus, index):
        r = random.randrange(0, modulus)
        h = int.from_bytes(
            hashlib.sha3_512(r.to_bytes(rlen, "big") + suffix).digest(), "big"
        ) % modulus
        return wagner.Lineage(h, r)
    return gen

r_values = wagner.solve(MODULUS, tree_height=3, generator=make_generator(MODULUS, SUFFIX))
for r in r_values:
    rlen = (MODULUS.bit_length() + 7) // 8
    print(r.to_bytes(rlen, "big").hex() + SUFFIX.hex())
```

## 变体与关联

- **哈希/模数变体**：SHA-256/SHA3/BLAKE 等只要输出可映射到模 `N` 的整数即可；`N` 越大需要越高的 `tree_height` 或更多候选。
- **条件变体**：目标不是 0 而是固定 `target`，在合并时把目标减去即可；也可以要求两条消息同哈希（经典碰撞）。
- **实现变体**：`conduition/wagner`、`k-sum` 库或自行写分层合并；注意每层保留的位数与内存/时间权衡。
- **关联**：[[ctf-crypto-linear-hash-collision-lll]]（线性模哈希用 LLL 求短向量，不是广义生日）、[[crypto-hash-md5-three-way-collision-nested-fastcoll]]（MD5 多碰撞构造）。

## 检测与防御

- **CTF 性质**：这是对“模素数哈希 + 求和校验”设计的攻击，不是通用漏洞。
- **设计防御**：不要用 `H(r) mod N` 的求和作为唯一校验；使用带密钥的 MAC/签名、域分离与抗碰撞哈希，并限制提交条数与请求频率。
- **检测**：服务端若看到同一 `suffix` 下大量短时间提交的 `r` 且哈希和恰好为 0，应视为异常；对挑战协议加入服务端随机性与不可预测的绑定值。
