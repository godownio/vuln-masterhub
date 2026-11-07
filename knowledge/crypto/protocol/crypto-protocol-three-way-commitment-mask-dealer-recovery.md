---
id: crypto-protocol-three-way-commitment-mask-dealer-recovery
title: 猜拳承诺可预测：3 值 dealer + 可验证掩码导致每轮必胜
type: scenario
domain: crypto
path: crypto/protocol
technique: three-way-commitment-dealer-recovery
aliases:
- 承诺方案可预测
- 猜拳 commitment 攻击
- dealer 恢复
- mask 可验证
- H(dealer,r) xor mask
- true_ezgame
tags:
- crypto
- protocol
- commitment
- rsa
- small-message-space
- game
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:27+08:00'
  notes: 已对照原文 §true_ezgame 核对：commitment=(mask^e mod n, H(dealer,r) xor mask)、H=sha512(bytes([i])+r)、dealer∈{0,1,2}、pow(mask,e,n)==token、player=(dealer-1)%3、40 轮、flag 均一致；未本机复跑。
---

## 一句话结论

服务端用 `commitment = (mask^e mod n, H(dealer, r) XOR mask)` 承诺出拳，并在玩家输入前公开 `r` 与 commitment；由于 dealer 只有 3 种取值，攻击者对每个候选值计算 `mask = masked XOR H(dealer, r)`，再用 `pow(mask, e, n) == token` 验证，即可唯一确定真实出拳并选择必胜手势。

## 原理

- 承诺方案的正确性依赖“隐藏性”：在揭示前不应泄露被承诺值。但这里的 `mask` 是一个随机数，`masked = H(dealer,r) XOR mask`，而 `token = mask^e mod n`。
- 服务端公开 `r` 和 `(token, masked)` 后，攻击者对 `dealer ∈ {0,1,2}` 逐一计算 `mask_candidate = masked XOR H(dealer, r)`，并检验 `mask_candidate^e mod n == token`。
- 只有真实的 `dealer` 对应的 `mask` 会满足 RSA 关系；其他候选值几乎不可能碰撞。因此 3 次哈希 + 3 次模幂即可恢复出拳。
- 游戏判定为 `beats(player, dealer) := dealer == (player + 1) % 3`，所以选 `player = (dealer - 1) % 3` 即可保证 `dealer == (player+1)%3`，每轮必胜。
- 根因是承诺的消息空间太小（3 个值），且验证等式可离线检查；承诺没有使用盐/随机化隐藏，也没有在玩家出拳后才公开 `r`。

## 触发条件

- 服务端使用“哈希 + RSA 掩码”的承诺，提前公开随机数 `r` 与承诺值。
- 被承诺的消息空间很小（如 3 种手势），可暴力枚举。
- 验证等式 `pow(mask, e, n) == token` 可在客户端计算，且 `H` 的输入格式已知。
- 攻击者能与服务端完成多轮交互（案例 40 轮）。

## 利用步骤

1. 连接服务端，完成 PoW（若有），读取 `n`、`e`。
2. 每轮读取 `r`、`token`、`masked`。
3. 对 `dealer = 0,1,2` 计算 `mask = masked XOR H(dealer, r)`，检查 `pow(mask, e, n) == token`。
4. 找到唯一匹配的 dealer 后，选择 `player = (dealer - 1) % 3` 发送。
5. 重复 40 轮，读取最终 flag。
6. 若多轮中某轮匹配失败，检查 `H` 的字节序（案例 `sha512(bytes([i]) + r)`）、`masked` 的 XOR 字节序、`r` 的十六进制解析。

## PoC

```python
import hashlib

def H(move_id: int, r: bytes) -> int:
    return int.from_bytes(hashlib.sha512(bytes([move_id]) + r).digest(), "big")

def choose_move(n, e, r, token, masked):
    for dealer in range(3):
        mask = masked ^ H(dealer, r)
        if pow(mask, e, n) == token:
            return (dealer - 1) % 3   # beats() 要求 dealer == (player+1)%3
    raise ValueError("dealer not recovered")

# 每轮：r = bytes.fromhex(hex_r); token, masked 从 commitment 解析
# player = choose_move(n, e, r, token, masked)
# MOVES = ("rock", "scissors", "paper"); send MOVES[player]
```

案例输出：40 轮全胜，得到 `NepCTF{6f859e1b-fe35-87d2-08f7-b55697a2d08b}`。

## 变体与关联

- 变体：消息空间稍大但仍可枚举（如 6、10、100 种）时，同样可暴力验证；消息空间很大时才需要其他缺陷。
- 变体：承诺使用 `H(value || r)` 而不是 XOR 时，若 `r` 提前公开且 value 空间小，也可直接枚举哈希。
- 变体：若服务端不公开 `r`，可尝试长度扩展、弱哈希或复用 mask/nonce；若 `mask` 复用，RSA 关系可能被消去。
- 关联：[[crypto-protocol-commitment-reveal-order-bias]]（承诺揭示顺序）、[[crypto-prng-time-seeded-rand-rc4-auth-forge]]（可预测随机数）、[[crypto-rsa-williams-p-plus-1-smooth-factor]]（同题 RSA 背景）。

## 检测与防御

- 防御：承诺必须在玩家出拳后才公开 `r`；使用标准 commitment（如 `H(value || salt)` 并隐藏 salt），不要提前泄露任何可验证关系。
- 防御：扩大消息空间或使用 Pedersen commitment 等具有隐藏性的方案；对承诺值做域分离与随机盐。
- 检测：客户端在单轮内对同一 commitment 做多次哈希/模幂验证；服务端日志中出现大量相同 `r` 或异常短的决策时间。
- 响应：发现承诺可预测后停止该游戏/协议，轮换随机数与密钥，审计是否有其他依赖小消息空间承诺的流程。
