---
id: blockchain-solidity-proxy-selector-collision-setimplementation-hijack
title: 代理 setImplementation(address) 与实现合约业务函数选择器冲突（同为 0xd784d426）：调用“安全函数”实际改掉实现地址
type: scenario
domain: blockchain
path: blockchain/solidity
technique: proxy-function-selector-collision-admin-hijack
tags:
- blockchain
- solidity
- evm
- proxy
- selector
- function-collision
- setimplementation
- access-control
- delegatecall
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404
  verified_at: '2026-11-09T13:22:34+08:00'
  notes: 已对照原文第4节核对：Proxy.setImplementation(address) 带 onlyOwner(require msg.sender==owner)、fallback 转发实现；实现合约 superSafeFunction96508587(address)；两签名选择器均为 0xd784d426 已用 keccak 本地复算；testProxy_oops 中 owner 调用'业务函数'后 implementation 变为 0xb0ffed 与原文一致。4.2 UUPS 组合原文为 testFail（owner check 因自调用 delegatecall 的 msg.sender=代理而回滚），卡内仅作未打通变体/防御参考并已注明。未验证点：PoC 最小重写未运行；无受影响版本；无 sources/URL。dedup 候选均 new。
url: /docs/blockchain/solidity/blockchain-solidity-proxy-selector-collision-setimplementation-hijack/
draft: false
kb_aliases:
- Function Collision
- 函数选择器冲突
- selector clash
- 代理管理函数冲突
- setImplementation 选择器碰撞
- superSafeFunction96508587
- 4 字节选择器冲突
---

## 一句话结论

EVM 与 Solidity 用函数签名的 4 字节选择器（`keccak256("name(types)")` 前 4 字节）分派函数；如果代理合约的管理函数（如 `setImplementation(address)`）与实现合约的某个业务函数（如 `superSafeFunction96508587(address)`）选择器相同（两者都是 `0xd784d426`），那么调用者经代理调用这个“业务函数”时，真正执行的是代理自己的 `setImplementation(address)`——参数被当成新实现地址，实现合约被换成攻击者指定的地址。文章用带 `onlyOwner` 的代理演示了 owner 被诱导调用该函数后实现地址被改成任意地址。

## 原理

- **选择器分派发生在最外层合约**：调用代理时，EVM 先按 calldata 前 4 字节在代理的 ABI 中查找匹配函数；只有代理没有匹配函数时才进入 `fallback` 把调用转发给实现合约。因此代理的检查顺序是“代理自身函数优先于 fallback”。
- **冲突的产生**：Solidity、代理与实现合约由不同人/不同版本编译时，函数名不同但选择器可能相同（4 字节只有 32 位，天然存在碰撞空间）。原文示例中 `setImplementation(address)` 与实现合约的 `superSafeFunction96508587(address)` 都编译成 `0xd784d426`（本地用 keccak256 计算可复现）。
- **调用落点**：用户/owner 以为在调用实现合约里那个“安全”的函数（参数是一个地址），构造 calldata `0xd784d426 + address`；代理看到 4 字节匹配自己的 `setImplementation(address)`，直接执行代理代码：检查调用者（示例为 `msg.sender == owner`）后把 `implementation` 设为该地址。实现合约根本没被执行。
- **为什么危害大**：实现地址是代理最核心的信任根。换成攻击者合约后，后续所有业务调用都会执行攻击者代码（可任意转移代理资产、伪造余额、抽干授权）；示例中断言 `implementation()` 已变为攻击者指定的地址，说明调用成功且产生持久状态变更。
- **权限条件的差别**：若代理管理函数没有访问控制，任何用户调用冲突的业务函数都能直接接管；若带 `onlyOwner`，则需要 owner 被诱导/欺骗去调用这个“业务函数”（前端展示、文档或空投领取入口都可能成为诱导手段），或者 owner 本身是脚本/机器人自动调用实现合约函数时被利用。
- **UUPS 的差异**：UUPS 把升级逻辑放在实现合约里，代理自身函数少，冲突概率相对低；但如果实现合约里同时存在管理函数与业务函数，或存在 delegatecall 辅助函数，仍可能构造选择器碰撞链。样例中的 UUPS 尝试因 owner 检查与自调用 `msg.sender` 不满足而回滚，说明并非所有组合都能打通。

## 触发条件

- 代理合约自身存在带参数的管理函数（改实现、改 admin、改手续费等），实现合约存在选择器相同的业务函数，且该业务函数的调用者会经代理调用。
- 冲突函数参数类型兼容（例如同为 `address`），使 calldata 能被目标管理函数正常解码。
- 若管理函数有权限控制：调用者必须是 owner/admin，或能诱导其调用；若无权限控制：任何人均可触发。
- 代理的分派顺序是“自身函数优先于 fallback”（标准 Solidity 代理即如此）。

## 利用步骤

1. 取代理与实现合约的 ABI/字节码，枚举所有函数选择器（`bytes4(keccak256(signature))`）。
2. 求交集，找到代理管理函数与实现业务函数的同选择器对；重点看管理函数是否修改 implementation/admin 等关键状态。
3. 评估权限：管理函数是否有 `onlyOwner`；若无则直接调用；若有则构造诱导场景（前端按钮、空投/领取入口、自动化脚本调用的“安全函数”）。
4. 向代理地址发送 `0xd784d426 + attackerAddress`（即冲突选择器 + 攻击者合约地址）的 calldata。
5. 校验代理的 `implementation()` 已变为攻击者合约；后续业务调用落入攻击者实现。
6. 若升级后需要初始化，可再调用攻击者实现的初始化/后门函数完成接管（视实现逻辑而定）。

## PoC

选择器相等性（可离线复现）：

```python
from Crypto.Hash import keccak
def sel(sig):
    k = keccak.new(digest_bits=256); k.update(sig.encode()); return k.hexdigest()[:8]
assert sel("setImplementation(address)") == sel("superSafeFunction96508587(address)") == "d784d426"
```

Foundry 演示（最小重写）：代理有 `setImplementation(address)` 与 fallback，实现合约有同选择器的业务函数；owner 调用业务函数时，代理实际执行管理函数：

```solidity
contract Proxy {
    address public immutable owner;
    address public implementation;
    constructor(address impl, address o) { implementation = impl; owner = o; }
    function setImplementation(address impl) external { require(msg.sender == owner); implementation = impl; }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
    receive() external payable {}
}

contract Implementation {
    function superSafeFunction96508587(address a) external pure returns (address) { return a; }
}

// 测试：owner 以为在调用实现的 superSafeFunction96508587，
// 实际命中代理的 setImplementation(address)，实现地址变成 0xb0ffed
proxy.call(abi.encodeWithSignature("superSafeFunction96508587(address)", address(0xb0ffed)));
assertEq(proxy.implementation(), address(0xb0ffed));
```

要点：调用方看不到“选择器被代理截胡”，交易在链上不会报错，状态变更静默发生。

## 变体与关联

- **代理管理函数无权限控制**：如 `setImplementation` 漏写 `onlyOwner`，任何用户调用冲突的业务函数即可直接改实现，等价于完全接管。
- **实现合约内部函数冲突**：UUPS 或 Diamond 中管理函数也在实现侧时，两个实现函数选择器相同会导致其中一个永远无法被调用（被另一函数截胡），可能绕过原函数的权限/逻辑；攻击面取决于被截胡函数的功能。
- **任意 delegatecall 辅助函数**：实现合约若暴露 `delegatecallContract(address,bytes)` 之类入口，再配合同选择器函数，可在代理上下文中执行额外代码；原文的 UUPS 样例属于此类组合尝试，但因 `msg.sender`/owner 条件未满足而回滚（未打通），仅作防御参考。
- **代理存储槽冲突**：与选择器冲突同属代理攻击面，但根因是变量槽位错位而非函数分派，两者可叠加。
- **相关审计点**：升级代理时同时比对新旧实现与代理的选择器集合，避免管理函数与业务函数碰撞。

## 检测与防御

- **选择器碰撞扫描**：部署前对代理与实现合约（以及多实现/Diamond facet）做选择器集合求交，管理函数与任何业务函数同选择器即拒绝发布；用 `cast sig`/`ethers.id` 批量计算。
- **管理函数命名与签名固定**：使用 EIP-1967 风格的专用管理入口、独立管理员代理（Transparent Proxy 的 admin 只能调管理函数），或把管理函数移到实现合约并做严格权限与重入检查。
- **访问控制**：所有改实现/改 admin 的函数必须 `onlyOwner`/多签/时间锁；不要依赖“函数名看起来安全”作为保护。
- **前端与文档校验**：UI 展示的函数必须与实际 calldata 选择器一致；对 owner 操作增加二次确认和目标地址校验。
- **链上监控**：监听代理 `Upgraded(address)` 事件，对非预期实现的升级告警；比对升级前后实现合约的签名集合。
- **测试**：对代理 ABI 的每个函数选择器做 harness 测试，断言不会误触发实现合约或管理路径；使用 Foundry 的 `abi.encodeWithSelector` 精确控制选择器。
