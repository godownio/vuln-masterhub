---
id: blockchain-solidity-vesting-wallet-address-collision-allocation-overwrite
title: 锁仓合约双钱包同地址：allocate() 对同一 allocations 槽位连续赋值，2.4 亿配额被 0.1 亿覆盖，解锁额与滞留资金错位
type: scenario
domain: blockchain
path: blockchain/solidity
technique: vesting-wallet-address-collision-allocation-overwrite
aliases:
- 锁仓合约地址重复
- allocations 覆盖
- teamReserveWallet == finalReserveWallet
- vesting 分配覆盖
- 解锁数量不符
- 锁仓合约需主动 claim
- token lockup overwrite
tags:
- blockchain
- solidity
- smart-contract
- vesting
- token-lockup
- mapping-overwrite
- logic-bug
- incident-response
- erc20
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V493
  verified_at: '2026-11-11T00:04:39+08:00'
  notes: 已对照原文与5张图核对：链上仅创建合约+allocate 两笔交易（图01/02）、2.5亿 MUSK 转入锁仓合约（图03）、MyCrypto 调 claimTeamReserve、转出375万（图04/05）；teamReserveWallet==finalReserveWallet==0xA 导致 allocations 同一槽位两次赋值、10M 覆盖 240M，3*10M/8=3.75M 与到账一致；recoverFailedLock 受 notLocked/notAllocated 限制、claimTokenReserve 与 team claim 共用 claimed[0xA]、240M 无出口的结论与原文"只能追回0.1亿"一致。未验证点：未在本地链复跑合约；原文仅摘录合约片段，"无其他 sweep/救援函数"依原文结论推断；原文无版本，未设 affected_versions；frontmatter 无 sources/source_url
---

## 一句话结论

锁仓/归属合约的 `allocate()` 先把 2.4 亿写入 `allocations[teamReserveWallet]`，再把 0.1 亿写入 `allocations[finalReserveWallet]`；当两个角色钱包被配置成同一个地址时，第二次赋值覆盖同一 mapping 槽位，合约实际记录的锁仓配额只有 0.1 亿。团队解锁按被覆盖后的配额计算（每次 0.1 亿 ÷ 8 × 段数），合约里另外 2.4 亿既没有对应配额也没有回收路径，永久滞留；链上表现为“转账 2.5 亿进入合约、首次 claim 只出 375 万”。

## 原理

- **mapping 以地址为键**：`allocations[address]` 是单槽映射，同一地址两次赋值是覆盖而不是累加。`allocate()` 依次执行 `allocations[teamReserveWallet] = 240M`、`allocations[finalReserveWallet] = 10M`；若两个钱包地址相同（部署时都填了同一个 0xA），最终该槽位只保留 10M。
- **余额校验不能发现配额错误**：`allocate()` 只 `require(token.balanceOf(address(this)) == totalAllocation)`（合约确实持有 2.5 亿），没有校验 `allocations` 之和是否等于 `totalAllocation`，也没有校验两个角色地址互不相同，因此覆盖后在链上“看起来锁仓成功”。
- **解锁金额由被覆盖的配额决定**：`claimTeamReserve()` 计算 `totalUnlocked = vestingStage * allocations[teamReserveWallet] / teamVestingStages`；配额 10M、8 段、每段约 91.25 天，3 段后应领 `3 * 10M / 8 = 3.75M`，与现场首次 claim 实际到账 375 万完全吻合，而不是预期的 `3 * 240M / 8 = 90M`。
- **claim 状态也被同一地址共享**：`claimed[address]` 只有一个槽位，团队领取会把 `claimed[0xA]` 置为非零；`claimTokenReserve()` 要求 `claimed[reserveWallet] == 0`，因此同一地址下团队领取与最终储备领取互斥，两条路径合计最多也只能领走 10M。
- **剩余 2.4 亿没有出口**：`recoverFailedLock()` 带 `notLocked`/`notAllocated` 修饰器，设计用于“锁仓失败时退回”，`allocate()`/`lock()` 成功后该路径不可用；合约又没有其他 sweep/救援函数，多转进去的 2.4 亿永远留在合约地址。
- **“没收到解锁款”的常见前置原因是未主动 claim**：这类锁仓合约不是按时间自动转账，需要持有对应角色钱包定期调用 `claimTeamReserve()`。链上只有“创建合约”和“allocate”两笔交易时，说明从未领取；先补调 claim，再核对到账数量，才能区分“没领”与“配额被覆盖”。

## 触发条件

- 部署时 `teamReserveWallet` 与 `finalReserveWallet`（或任何两个被分配配额的角色地址）填写为同一地址；且合约没有 setter 可在部署后修正。
- Owner 调用了 `allocate()`/`lock()`，合约已持有 `totalAllocation`，进入已锁仓状态。
- 解锁为主动 claim 模式：没有人调用 `claimTeamReserve()` 时余额不会自动变化；调用后按覆盖后的 `allocations` 计算金额。
- 合约没有独立的 emergency recover/sweep 路径，或该路径被 `notLocked`/`notAllocated` 等状态修饰器挡住。

## 利用步骤

> 本场景是合约逻辑/部署事故的应急排查路径，不是攻击者利用链。

1. **链上取证**：在区块浏览器查看锁仓合约的交易列表与 ERC20 转账记录，确认是否只有“创建合约 + allocate”两笔交易，以及合约实际收到的代币数量（示例 2.5 亿）。
2. **判断是否未领取**：核对 `claimed`/`lockedAt` 等状态与历史交易；若从未调用 claim，先按合约要求用角色钱包调用 `claimTeamReserve()`（注意调用者必须是 `teamReserveWallet`）。
3. **核对到账数量**：用 `vestingStage()` 与实际到账反推 `allocations`；若到账 = `stage * 预期配额 / 8` 明显不符（示例为 375 万而非 9000 万），转查源码。
4. **定位覆盖点**：比较 `teamReserveWallet` 与 `finalReserveWallet` 的赋值；若相同，确认 `allocate()` 中两次写同一 mapping 槽位，后写的较小配额覆盖前者。
5. **评估可追回资产**：计算合约余额与 `allocations` 之和的差额（示例 2.5 亿 - 0.1 亿 = 2.4 亿），检查 `recoverFailedLock()` 等函数的修饰器与状态，确认是否还有任何提取路径。
6. **处置**：已部署合约无法修改代码；只能按现有 claim 路径领取被记录的配额（示例 0.1 亿，分 8 段），其余资产需与项目方/交易所协商或通过合约预留的治理/救援机制处理（若存在）。

## PoC

最小复现（Solidity 语义，展示覆盖与解锁计算）：

```solidity
mapping(address => uint256) public allocations;
address teamReserveWallet = address(0xA);
address finalReserveWallet = address(0xA);   // 同一地址
uint256 teamReserveAllocation = 240 * 10**6 * 10**18;
uint256 finalReserveAllocation = 10 * 10**6 * 10**18;

function allocate() external {
    allocations[teamReserveWallet] = teamReserveAllocation;   // 240M
    allocations[finalReserveWallet] = finalReserveAllocation; // 同一槽位，覆盖为 10M
}

function unlockedAt(uint256 stage) public view returns (uint256) {
    return stage * allocations[teamReserveWallet] / 8; // stage=3 -> 3.75M
}
```

排查用不变量：

```text
require(teamReserveWallet != finalReserveWallet, "role address collision");
require(sum(allocations) == totalAllocation, "allocation invariant");
```

无独立链上 PoC；上述代码可在本地测试链复现覆盖行为。

## 变体与关联

- **角色地址碰撞**：owner/operator、team/final、treasury/reward 等任意两个被分配配额的角色地址重复，都会触发同类覆盖；也可能出现在白名单、额度、质押份额等 mapping。
- **累加语义错误**：把 `=` 写成 `+=` 可避免覆盖；反之把本应 `+=` 的分配写成 `=` 也会造成同类少记。
- **claim 模式差异**：自动线性释放（按时间可提取余额）与手动分段 claim 的排查方式不同；手动模式下“没有交易”本身就是未领取的证据。
- **回收路径缺陷**：`recoverFailedLock` 一类函数被状态修饰器永久锁死、或多签/治理缺失，会让超额资金无法退出；审计时应检查“资金多于配额”时的出口。
- **关联卡**：Solidity 存储/槽位碰撞类（代理 storage collision、delegatecall slot0）是“不同变量写同一存储”的另一类根因；本卡是同一 mapping 键的业务覆盖。

## 检测与防御

- **审计/开发**：角色地址在构造函数或 initialize 中断言互不相同；`allocate()` 增加 `sum(allocations) == totalAllocation` 不变量；团队与最终储备使用独立 mapping 或带类型/ID 的键，避免共享 `claimed` 槽位。
- **部署校验**：部署脚本与配置模板中禁止占位地址重复；上线前用测试网跑完整 allocate → 多段 claim → 最终 claim 流程，核对每段金额。
- **链上监控**：监控合约余额与 `allocations` 之和的差额；出现“余额远大于可领取总额”告警；监控角色地址是否与已知团队/储备地址一致。
- **应急响应**：先看交易历史判断是否未 claim，再按 claim 金额反推配额；保留链上交易与源码证据；评估合约是否有救援函数，必要时通过治理/多签升级或与交易所协作处理。
- **合约设计**：为锁仓合约预留受多签/时间锁约束的 emergency withdraw（仅限超额或误转资金），避免单点逻辑错误导致资产永久锁定。
