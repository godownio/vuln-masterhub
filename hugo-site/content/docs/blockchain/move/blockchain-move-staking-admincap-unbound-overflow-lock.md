---
id: blockchain-move-staking-admincap-unbound-overflow-lock
title: Move 质押池 AdminCap 未绑定 + public create：任意用户篡改 APR 触发 u64 溢出，永久锁死质押与取回
type: scenario
domain: blockchain
path: blockchain/move
technique: move-staking-admincap-unbound-parameter-overflow
tags:
- blockchain
- move
- sui
- staking
- defi
- capability
- access-control
- integer-overflow
- object-binding
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T07:04:01+08:00'
  notes: 已对照原文deadlock_finance全文核对：staking::create为public且update_apr/update_duration参数为_不校验pool_id；check_apr上限1000%、apr=10^18/decimals=18时百分比100%可通过；calculate_rewards的amount*apr在amount=min_stake=200、apr=10^18时=2e20>u64上限1.844e19触发溢出；exp与原文逐行一致，且卡内注明不能在solve里调is_solved；效果为锁死而非盗取，severity/confidence合理
url: /docs/blockchain/move/blockchain-move-staking-admincap-unbound-overflow-lock/
draft: false
kb_aliases:
- Sui 质押池锁死
- AdminCap 跨池使用
- update_apr 未校验 pool_id
- 奖励计算 u64 溢出
- deadlock_finance
- public create 提权
---

## 一句话结论

Sui Move 质押合约把 `staking::create` 设为 public，任何人都能自建池并拿到一个 AdminCap；而 `update_apr`/`update_duration` 只要求传入 `&AdminCap`，不校验 `admin_cap.pool_id == object::id(pool)`，攻击者用自己的 AdminCap 即可把任意池的 APR 改成 `10^18`/18 位精度，随后 `calculate_rewards` 里 `amount * apr` 在 u64 上溢出并使质押/取回路径永久回滚，池内资金被锁死。

## 原理

- **能力对象只校验类型、不校验归属**：`AdminCap` 结构里有 `pool_id` 字段，但 `update_apr<T>(pool: &mut Pool<T>, _: &AdminCap, ...)` 和 `update_duration` 把 cap 参数命名为 `_`，完全不读取、也不比较 `pool_id`。Move 的类型系统只保证“这是一个 AdminCap”，不保证“它是这个 Pool 的 AdminCap”。
- **public 工厂让攻击者自铸能力**：`public fun create<T>(...): (Pool<T>, AdminCap)` 可被任何人调用；攻击者只需提供满足 `rewards.value() > 0` 的 Coin，就能创建一个废池并获得合法类型的 AdminCap，其 `pool_id` 指向废池，但目标函数不检查。
- **APR 校验只看百分比**：`check_apr` 计算 `apr_percentage = apr * 100 / 10^decimals`，要求落在 `[MIN_APR_PERCENTAGE, MAX_APR_PERCENTAGE=1000]`。取 `apr = 10^18`、`decimals = 18` 时百分比恰为 100%，完全通过校验，但内部精度极高。
- **u64 乘法溢出**：`calculate_rewards(amount, apr, apr_base, duration)` 先算 `(amount * apr) / apr_base`，全部是 u64。`amount` 取 `min_stake=200`、`apr=10^18` 时乘积为 `2×10^20`，超过 u64 上限 `1.844×10^19`，Move 运行时直接 abort。`is_solved` 里调用 `pool.stake(min_stake)` 以及任何依赖 `calculate_rewards` 的质押/取回路径都会回滚，合约被永久卡死。
- **完整链**：领取挑战币 → `staking::create` 自建池并获得 AdminCap → 用该 cap 调 `challenge.pool.update_apr(cap, 10^18, 18)` → 目标池 APR 被污染 → 后续 stake/取回在奖励计算处溢出回滚 → 资金无法取出。
- **根因**：能力对象未绑定目标对象 + 公共构造函数 + u64 中间计算未用 u128 拓宽。

## 触发条件

- Sui Move 合约的 `create` 为 `public`（或可被任意用户调用），能凭空铸造 `AdminCap`/`PoolAdminCap` 等能力对象。
- 管理函数接收能力对象但不校验其 `pool_id`/对象归属，或只用类型系统做权限。
- 奖励计算使用 `u64` 乘法且乘数可由管理函数修改（APR、精度、期限）；精度上限足够大（如 18 位小数）。
- 攻击者能获得满足 `create` 前置条件（如 `rewards.value() > 0`）的 Coin；CTF 中由 `claim_coin` 提供。

## 利用步骤

1. 从挑战合约领取可用 Coin（如 `challenge.claim_coin(ctx)`）。
2. 调用 `staking::create<COIN>(...)` 自建一个参数合法的废池，拿到 `(pool2, admin_cap)`；`admin_cap.pool_id` 指向废池。
3. 对目标池调用 `pool.update_apr(&admin_cap, 10^18, 18)`；`check_apr` 只校验 100% 百分比，通过。
4. 目标池的 `apr=10^18`、`apr_base=10^18`；此后任意 `amount >= 19` 的 `amount * apr` 都会超过 u64 上限。
5. 目标池的 `stake`/取回/结算路径在 `calculate_rewards` 处 abort，质押与资金取回被永久阻断。
6. 可把废池与 AdminCap 转走或丢弃，攻击者无需保留任何对象。

## PoC

原文 exp（Move）：

```move
module the_solution::solution;

use challenge::challenge::Challenge;
use challenge::staking;
use challenge::coin::COIN;

const NEW_APR_DECIMALS: u8 = 18;

#[allow(lint(self_transfer))]
public fun solve(challenge: &mut Challenge<COIN>, ctx: &mut TxContext) {
    let coins = challenge.claim_coin(ctx);
    let pool = challenge.get_pool();
    let (pool2, admin_cap) = staking::create<COIN>(
        1000, 3, 90 * 24 * 60 * 60, 24 * 60 * 60, 200, 1_000_000, coins, ctx,
    );
    pool.update_apr(&admin_cap, (10u128.pow(18)) as u64, NEW_APR_DECIMALS);
    transfer::public_transfer(admin_cap, ctx.sender());
    transfer::public_transfer(pool2, ctx.sender());
}
```

关键点：不要在 solve 里再调用 `is_solved`，否则会在 `assert!(rewards <= available_rewards)` 或溢出处 abort，导致取 flag 的交易失败。

## 变体与关联

- 能力对象变体：`AdminCap`、`PoolAdminCap`、`OracleCap`、`FeeCap`；凡是“结构体里存了目标 id 但敏感函数不校验”的都适用。
- 参数变体：改 APR/精度、改 duration（`rewards * duration` 同样可溢出）、改 min/max stake 使 `assert` 恒失败。
- 溢出点变体：`amount * apr`、`rewards * duration`、`old_amount * apr`；把中间值 cast 到 u128 可消除。
- 关联卡片：[[blockchain-move-lending-position-cross-instance-collateral]]（public create + 对象未绑定跨实例）、[[blockchain-move-voting-vote-request-ballot-binding-missing]]（请求/能力未绑定对象）、[[blockchain-move-flashloan-receipt-type-confusion]]。
- 边界：本案最终效果是资金锁死/合约不可用，不是直接盗取；但攻击者可篡改任意池参数，是后续资产类利用的放大器。

## 检测与防御

- 能力对象必须绑定目标：在所有管理函数入口断言 `cap.pool_id == object::id(pool)`（或使用 Move 的一次性能力/泛型 witness 绑定）。
- 收紧构造函数可见性：`create` 改为 `entry`/包内可见，或用 `AdminCap` 的 `Publisher`/模块初始化发放，禁止任意用户铸造管理能力。
- 算术安全：奖励计算全程使用 `u128` 中间值并在写回 `u64` 前做范围检查；对 APR 精度和最大金额做联合上限校验。
- 不变量测试：用极大 APR/精度、极长 duration、min/max 边界值构造属性测试，验证 `stake`/`unstake` 不会 abort。
- 监控：链上监测 `update_apr`/`update_duration` 的异常精度与数值，发现同一 AdminCap 被用于多个 pool 时告警。
