---
id: blockchain-solidity-uninitialized-uups-proxy-initialize-frontrun
title: 未初始化 UUPS/ERC1967 代理：部署时 init data 为空，攻击者抢先 initialize 成为 owner 并 mint 或升级
type: scenario
domain: blockchain
path: blockchain/solidity
technique: uninitialized-uups-proxy-initialize-frontrun
tags:
- blockchain
- solidity
- evm
- proxy
- uups
- erc1967
- initializer
- access-control
- openzeppelin
- foundry
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404
  verified_at: '2026-11-09T13:22:30+08:00'
  notes: 已对照原文第2节核对：构造函数不写代理存储、ERC1967Proxy(impl,"") 空 init data、initialize public initializer 无调用者限制、抢先后 owner=攻击者并 mint 10 ether，均与原文 ProxyToken/UUPSProxy/Test 一致。未验证点：PoC 为最小重写未在链上运行；原文未给 OZ/Solidity 受影响版本，未设 versions；无 sources/source_url/文章ID/URL。dedup 候选均 new/related（与 delegatecall-library-slot0、storage-collision-multicall 根因不同）。dup-scan.json 早于建卡且不含本卡 pair。
url: /docs/blockchain/solidity/blockchain-solidity-uninitialized-uups-proxy-initialize-frontrun/
draft: false
kb_aliases:
- Uninitialized Proxy
- 未初始化代理
- UUPS initialize 抢占
- 初始化劫持
- initializer frontrun
- 未调用 initialize
- ERC1967Proxy 空初始化数据
---

## 一句话结论

代理合约的构造函数永远在实现合约的上下文中执行，无法把 `owner` 等初始化状态写进代理存储；因此可升级代理必须由代理 `delegatecall` 一次 `initialize()` 来初始化。如果部署脚本创建 ERC1967/UUPS 代理时传入空 `init data` 又忘了补调 `initialize()`，任何人都能在项目方之前直接调用代理的 `initialize()`，把 `owner` 写成自己，随后调用 `mint` 或借 UUPS 升级权限换掉实现合约，完成接管。

## 原理

- **构造函数不写代理存储**：`new Implementation()` 部署实现合约时构造函数只在实现合约自己的地址上执行一次；而代理通过 `delegatecall` 执行实现合约代码，读写的是代理的存储。若把 `owner = msg.sender` 放在构造函数里，代理永远拿不到 owner，所以 OpenZeppelin 等实现改用公开的 `initialize()`（带 `initializer` 修饰器）在代理上下文中初始化。
- **部署路径**：`ERC1967Proxy(implementation, data)` 构造函数内部把 `data` 作为 `delegatecall` 发给实现合约；正常的部署脚本会把 `initialize()` 的 calldata 传进去，使初始化与代理创建在同一笔交易里原子完成。如果 `data` 为空（`""`），代理部署后处于“未初始化”状态，任何人都可以补上这次 `delegatecall`。
- **为什么攻击者能抢先**：`initialize()` 是 `public` 且只由 `initializer` 修饰器限制“只能成功执行一次”，没有限制调用者。攻击者监听内存池或在代理部署后立即发交易调用代理的 `initialize()`，先于项目方完成初始化；`initializer` 一旦置位，项目方后续的初始化会 revert，攻击者成为唯一 owner。
- **授权后果**：示例实现合约中 `initialize()` 执行 `_transferOwnership(_msgSender())`，`mint(uint256)` 带 `onlyOwner`。攻击者成为 owner 后可无限 mint；在 UUPS 中 `_authorizeUpgrade(address)` 也常带 `onlyOwner`，攻击者还能把实现合约升级为恶意合约，进一步抽走代理持有的资产或接管全部业务逻辑。
- **为什么容易漏**：实现合约本身也可能被直接部署；在实现合约上调用 `initialize()` 只会写实现合约自己的存储，不影响代理。因此“实现合约已初始化”不能说明代理已初始化，判断标准是代理存储中的初始化状态/owner。

## 触发条件

- 使用 ERC1967Proxy/UUPSProxy 等可升级代理，部署交易中的 `data` 为空，且部署后没有在紧随其后的交易中原子地调用 `initialize()`。
- 实现合约的初始化函数为 `public`/`external`，仅依赖 `initializer` 修饰器防重复，不限制 `msg.sender`。
- 初始化函数会写入被 `onlyOwner` 等权限修饰器保护的状态（owner、admin 等），或代理存在 UUPS 升级入口。
- 攻击者能在代理部署后、项目方初始化前提交交易（抢先或普通顺序均可，只要窗口存在）。

## 利用步骤

1. 发现新部署的代理合约，确认 `implementation()` 指向的实现合约，并读取实现合约的 `initialize()` 函数。
2. 检查代理侧的初始化状态/owner：对 ERC20 示例可先调用 `owner()`，返回 `address(0)` 即未初始化。
3. 以攻击者地址直接向代理发送 `initialize()` 调用（calldata 为 `initialize()`，不带参数）。
4. 校验 `owner()` 已变为攻击者地址；若项目方尚未初始化，其初始化交易会因 `initializer` 已置位而失败。
5. 作为 owner 调用 `mint(任意数量)` 铸造代币，或（UUPS）调用 `upgradeToAndCall` 把实现合约换成恶意实现，接管代理。
6. 如果项目方抢先初始化，则本次失败；寻找其他未初始化实例或升级窗口。

## PoC

Foundry 测试（最小重写，展示“空 init data → 任何人 initialize 成为 owner”）：

```solidity
// 实现合约：OZ Initializable + Ownable + UUPSUpgradeable + ERC20
contract ProxyToken is Initializable, ERC20, UUPSUpgradeable, Ownable {
    constructor() ERC20("ProxyToken", "PTK") {}

    function initialize() public initializer {
        _transferOwnership(_msgSender());
    }

    function mint(uint256 q) external onlyOwner { _mint(_msgSender(), q); }
    function _authorizeUpgrade(address) internal override onlyOwner {}
}

contract ExploitTest is Test {
    function testFrontRunInitialize() public {
        ProxyToken impl = new ProxyToken();
        // 部署代理时 init data 为空：项目方漏掉了 initialize
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), "");

        address attacker = address(0xABCDEF);
        vm.prank(attacker);
        (bool ok,) = address(proxy).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok);

        assertEq(Ownable(address(proxy)).owner(), attacker);

        vm.prank(attacker);
        ProxyToken(address(proxy)).mint(10 ether);
        assertEq(ProxyToken(address(proxy)).balanceOf(attacker), 10 ether);
    }
}
```

要点：`initialize()` 必须经由代理地址调用才会写到代理存储；直接对实现合约调用无效。

## 变体与关联

- **透明代理**：若代理管理员函数在代理自身实现，初始化逻辑可能不同，但同样存在“部署后未初始化/未设置 admin”的窗口；需检查代理的 admin 槽位是否为零地址。
- **实现合约自身被初始化**：在实现合约地址上调用 `initialize()` 只影响实现合约，通常不能直接接管代理，但可影响依赖实现合约状态的逻辑（如 `selfdestruct`/升级入口）；OpenZeppelin 建议在实现合约构造函数里 `_disableInitializers()`。
- **同一交易内抢先**：项目方若在构造代理的同一笔交易里通过 `data` 或紧跟的 `multicall` 完成初始化，则无窗口；只有“先部署、后初始化”分两笔交易时才有机会。
- **相关场景**：代理存储槽位冲突（业务变量写进 admin 槽位）、函数选择器冲突（调用业务函数命中管理函数），与本卡同属代理攻击面，但根因和利用条件不同。

## 检测与防御

- **部署即初始化**：创建代理时把 `initialize()` calldata 作为构造参数传入，或使用部署脚本在代理创建后同一笔交易内调用；不要分两笔交易。
- **实现合约锁定初始化**：在实现合约构造函数中调用 `_disableInitializers()`，防止实现合约本身被初始化；代理侧使用 `initializer`/`reinitializer` 并严格版本控制。
- **链上检查**：部署后立即检查代理存储中的 `_initialized` 值与 `owner()`；对 `owner() == address(0)` 的代理告警。
- **监控**：监听 `Initialized(uint8)`/`OwnershipTransferred` 事件，特别关注部署后极短时间内由非部署者发起的初始化调用；对 `initialize` 选择器与部署交易的关联做 mempool 监控。
- **权限最小化**：初始化函数不要保留公开的 `initialize` 之外的重初始化入口；UUPS 的 `_authorizeUpgrade` 必须带 `onlyOwner`/多重签名。
- **审计工具**：Slither 的 `uninitialized-state`/代理相关检测、OpenZeppelin Upgrades 插件校验初始化调用；手工核对部署脚本的 `data` 参数是否为空。
