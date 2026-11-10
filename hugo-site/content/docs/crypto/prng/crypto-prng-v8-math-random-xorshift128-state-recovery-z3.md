---
id: crypto-prng-v8-math-random-xorshift128-state-recovery-z3
title: V8 Math.random xorshift128+ 状态恢复：用 5 个连续浮点输出经 Z3 求解 128 位状态并预测后续随机数
type: scenario
domain: crypto
path: crypto/prng
technique: v8-math-random-xorshift128-state-recovery-z3
tags:
- crypto
- prng
- v8
- javascript
- xorshift128
- z3
- state-recovery
- prediction
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V384
  verified_at: '2026-11-09T08:48:23+08:00'
  notes: 已对照原文与图片01-13核对：xorshift128+源码、Z3建模、5个输出序列(0.6199...)、预测0.7449866957281785与截图一致；本机复跑文章脚本输出0.7449866957281785（sat）；另用当前Node V8现场生成5个连续输出并预测第6个，完全命中，证明state0>>12约束模型在现版本V8仍有效；ToDouble源码截图确为(state0+state1)&mask写法，卡中版本差异提示成立。未对安全业务场景做端到端利用。
url: /docs/crypto/prng/crypto-prng-v8-math-random-xorshift128-state-recovery-z3/
draft: false
kb_aliases:
- Math.random 预测
- V8 xorshift128+
- Z3 求解 PRNG
- XorShift128 状态恢复
- 伪随机数破解
- v8-randomness-predictor
---

## 一句话结论

V8 的 `Math.random()` 使用 xorshift128+（128 位内部状态，周期 2^128-1），不是密码学随机数；在 Chrome 控制台取 5 个连续输出（`Array.from(Array(5), Math.random)`），按 xorshift128+ 的状态更新式在 Z3 中建模，把每个 double 的尾数与状态位建立等式约束，求解出 `state0`/`state1` 后按同一规则计算下一个 double，即可与浏览器随后一次 `Math.random()` 的输出完全一致（文章实测预测 `0.7449866957281785` 命中）。

## 原理

- **伪随机的可预测性**：PRNG 由种子和一个确定性的状态转移函数决定；只要恢复内部状态，之后的所有输出都可预测。V8 用 xorshift128+，状态只有两个 64 位字，输出是状态的线性/移位混合，适合用 SMT 求解。
- **V8 的状态更新**（文章源码节选）：
  ```c
  static inline void XorShift128(uint64_t* state0, uint64_t* state1) {
      uint64_t s1 = *state0;
      uint64_t s0 = *state1;
      *state0 = s0;
      s1 ^= s1 << 23;
      s1 ^= s1 >> 17;
      s1 ^= s0;
      s1 ^= s0 >> 26;
      *state1 = s1;
  }
  ```
- **double 的构造**：`Math.random()` 返回 `[0,1)` 的 double，V8 以状态位构造 `[1,2)` 区间的尾数（指数位固定 `0x3FF0000000000000`，尾数掩码 `0xFFFFFFFFFFFFF`）再减 1。文章的 Z3 脚本把观测值 `x` 转成 `x+1` 的 IEEE754 uint64，取低 52 位尾数，与 `state0 >> 12`（52 位）建立等式：
  ```python
  float_64 = struct.pack("d", sequence[i] + 1)
  u_long_long_64 = struct.unpack("<Q", float_64)[0]
  mantissa = u_long_long_64 & ((1 << 52) - 1)
  solver.add(int(mantissa) == z3.LShR(se_state0, 12))
  ```
  每次循环先按 xorshift128+ 推进状态、再对“本次输出”加约束；5 个输出给出 5×52 位约束，足以唯一确定 128 位状态。
- **求解与预测**：`z3.BitVecs("se_state0 se_state1", 64)` 声明符号状态；逻辑右移必须用 `z3.LShR`（算术右移会引入符号位错误）；`solver.check()==sat` 后取模型中的 `se_state0`，按 `(state0 >> 12) | 0x3FF0000000000000` 还原 double 再减 1。
- **版本差异注意**：不同 V8 版本/构建的 `ToDouble` 细节可能不同（源码中可见 `(state0 + state1) & kMantissaMask` 的写法），文章脚本的 `state0 >> 12` 模型在其测试的 Chrome 上实测命中；换目标版本时应先确认该版本 `Math.random`/`ToDouble` 实现，必要时把约束改为对应的加法/移位组合。Node.js、Electron、Chrome 等使用 V8 的运行时同理。
- **危害**：若业务用 `Math.random()` 生成会话密钥、验证码、重置 token、nonce、抽奖结果等安全敏感值，攻击者拿到足够连续输出即可预测后续值，绕过验证或接管会话。

## 触发条件

- 目标运行时使用 V8 的 xorshift128+ `Math.random()`（Chrome/Node/Electron 等）。
- 攻击者能获得至少 5 个**连续、未加工**的 `Math.random()` 原始输出（同页面 console/JS 注入、泄露的随机值、或被映射前的原始值）。
- 观测值与应用使用值来自同一 PRNG 流且顺序连续；若应用做了 `Math.floor(v*16)` 等映射，需要先还原原始 double（可用 hook 记录原值）。
- 目标 V8 版本的输出构造与 Z3 模型一致（否则按版本调整约束）。

## 利用步骤

1. 在目标上下文取连续输出：Chrome DevTools Console 执行 `Array.from(Array(5), Math.random)`，记录 5 个 double。
2. 将序列反转（脚本从后向前建约束），用 Z3 声明两个 64 位 BitVec 作为初始状态。
3. 循环中按 V8 xorshift128+ 更新状态（注意 `LShR` 逻辑右移），并把本次观测的 52 位尾数与 `state0 >> 12` 加为约束。
4. `solver.check()` 为 sat 后取 `se_state0`，按同一 double 构造规则算出下一个值。
5. 在浏览器再执行一次 `Math.random()`（或触发业务下一次随机调用），与预测值比对验证。
6. 若命中，继续迭代预测后续值；结合业务逻辑（token/验证码/密钥）评估影响，验证后停止。

## PoC

```python
#!/usr/bin/python3
import z3, struct

sequence = [0.6199046082820001, 0.6623637813965961, 0.7190181683749095, 0.06169296721449724, 0.915799780594273]
sequence = sequence[::-1]
solver = z3.Solver()
se_state0, se_state1 = z3.BitVecs("se_state0 se_state1", 64)

for i in range(len(sequence)):
    se_s1 = se_state0
    se_s0 = se_state1
    se_state0 = se_s0
    se_s1 ^= se_s1 << 23
    se_s1 ^= z3.LShR(se_s1, 17)      # 逻辑右移，不能用算术右移
    se_s1 ^= se_s0
    se_s1 ^= z3.LShR(se_s0, 26)
    se_state1 = se_s1

    float_64 = struct.pack("d", sequence[i] + 1)
    u_long_long_64 = struct.unpack("<Q", float_64)[0]
    mantissa = u_long_long_64 & ((1 << 52) - 1)
    solver.add(int(mantissa) == z3.LShR(se_state0, 12))

if solver.check() == z3.sat:
    model = solver.model()
    states = {d.__str__(): model[d] for d in model.decls()}
    state0 = states["se_state0"].as_long()
    u_long_long_64 = (state0 >> 12) | 0x3FF0000000000000
    float_64 = struct.pack("<Q", u_long_long_64)
    next_sequence = struct.unpack("d", float_64)[0]
    print(next_sequence - 1)
```

输出 `0.7449866957281785`，与随后浏览器 `Math.random()` 的实际返回值一致（文章截图验证）。

## 变体与关联

- 变体（无原始输出、只能 hook）：直接包装 `Math.random` 记录返回值，按业务映射（如 `floor(v*16)`）还原密钥/字符（见关联卡）；本卡是不依赖 hook、仅凭连续输出恢复内部状态的路径。
- 变体（其他运行时）：Node/Electron 同用 V8；Firefox SpiderMonkey、Safari JSC 的 PRNG 算法不同，需替换状态转移函数；MT19937/glibc rand/LCG 有各自的恢复方法。
- 变体（输出被加工）：若只拿到 `floor(v*100)` 或十六进制字符，可把映射写进 Z3 约束做带噪声求解，或结合多次采样/其他泄露恢复状态。
- 关联：[[crypto-prng-math-random-sharekey-recovery]]（hook Math.random 还原小程序 shareKey）、[[crypto-prng-mt19937-untemper-state-recovery-predict]]（MT19937 状态恢复）、[[crypto-prng-filtered-lfsr-wg-anf-z3-state-recovery]]（Z3 建模 PRNG 的同类手法）。

## 检测与防御

- 防御：任何安全敏感随机值（密钥、token、验证码、nonce、抽奖）必须使用 CSPRNG（浏览器 `crypto.getRandomValues`/WebCrypto，Node `crypto.randomBytes`），不要在客户端或服务端用 `Math.random()` 派生安全值。
- 防御：服务端生成并校验随机值，不要信任客户端提交的随机结果；对验证码/重置 token 加有效期、一次性使用与速率限制。
- 检测：代码审计搜索 `Math.random()` 参与密钥/验证码/nonce/签名的模式；同一会话随机值出现可预测的分布或与时间序列相关；客户端随机值与服务端预期不一致/可重放。
- 边界：若目标使用 CSPRNG、客户端无法观测连续原始输出，或 V8 版本实现与模型不一致且未调整约束，则无法预测。
