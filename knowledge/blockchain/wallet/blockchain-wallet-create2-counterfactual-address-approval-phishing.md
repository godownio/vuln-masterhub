---
id: blockchain-wallet-create2-counterfactual-address-approval-phishing
title: 以太坊 CREATE2 未来地址授权钓鱼：诱骗受害者 approve 尚未部署的合约，随后部署恶意合约 transferFrom 盗取代币
type: scenario
domain: blockchain
path: blockchain/wallet
technique: create2-counterfactual-address-approval-phishing
aliases:
- CREATE2 钓鱼
- 预部署合约授权
- 未来合约地址 approve
- allowance phishing
- counterfactual contract approval
- CREATE2 双刃剑
- 未部署合约授权
tags:
- blockchain
- ethereum
- create2
- wallet
- approval
- allowance
- phishing
- erc20
- transferfrom
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V336
  verified_at: '2026-11-08T18:44:37+08:00'
  notes: 已对照原文与全部 15 张截图核对：Etherscan 预计算 0xe41Ba1...（salt 123456）、未部署地址无交易、increaseAllowance spender=0xa01dee... 额度 max、CREATE2 反编译、multicall→SUPER.transferFrom(sender=0xc9f304..., recipient=0x8f9278...)、_msgSender()=0xa01dee... 均与卡一致；350 万美元案例与链上地址（SUPER 0xe53ec727...）核对无误。dedup 仅自匹配（草稿已在库中），无同链重复。原文未给合约/工具版本，非组件卡。
---

## 一句话结论

CREATE2 让合约地址可以在部署前由「部署者地址 + salt + 初始化代码」确定性地算出来。攻击者先算出未来地址，诱骗受害者对该地址执行 ERC20 `approve`/`increaseAllowance`（此时地址上没有代码，钱包安全产品没有合约历史可查），获得授权后再用相同 salt/初始化代码把恶意合约部署到该地址，合约调用 `transferFrom(victim, attacker, amount)` 即可转走受害者代币。

## 原理

- **CREATE2 地址是确定性的**：地址 = `keccak256(0xff ++ deployer_address ++ salt ++ keccak256(init_code))[12:]`。`salt` 是创建者选择的 32 字节值，`init_code` 是合约创建字节码（含构造函数参数）。只要 deployer、salt、init_code 不变，地址在部署前就完全确定。
- **approve 授权的是地址，不是代码**：ERC20 的 `approve(spender, amount)` 只记录 `allowance[owner][spender] = amount`，不要求 `spender` 是已部署合约，也不检查其代码。受害者签署的是一笔与代币合约交互的 approve 交易，交易本身不会调用未来合约，因此交易模拟/钱包安全扫描看不到恶意代码。
- **为什么能绕过钱包安全**：多数钱包/安全产品根据已有合约的字节码、历史交易、信誉标签判断 spender 是否恶意。未部署地址没有字节码、没有交易历史、没有验证源码，容易被当作“新地址/未来合约”；攻击者可以把它包装成空投、预售、NFT 铸造等需要先授权的场景。
- **部署后授权自动生效**：攻击者随后用相同 deployer/salt/init_code 在预计算地址部署合约；该地址从此有了代码，而受害者之前授予该地址的 allowance 仍然有效。恶意合约只需调用 `token.transferFrom(victim, attacker, amount)`，代币合约会按 allowance 放行。
- **在野案例**：原文引用一起约 350 万美元损失的事件——受害者在合约 `0xa01dee645e4dbaaa8aa2089cc4b1cc34d36fa71c` 尚未创建时，对 SUPER 代币执行了 `increaseAllowance`，spender 正是该未来地址、额度为最大值；随后攻击者通过 CREATE2 部署该地址并在 `multicall` 中调用 `SUPER.transferFrom`，把资金转往 `0x8f9278...`。链上交易 trace 显示 `multicall → transferFrom → _transfer`，调用者 `_msgSender()` 为 `0xa01dee...`。
- **本质**：这不是代币合约漏洞，而是 EVM 地址可预计算 + ERC20 授权模型 + 钱包“只检查已部署合约”三者叠加出的钓鱼面。CREATE2 只是让“未来地址”变得可精确预知、可提前授权。

## 触发条件

- 受害者持有可转出的 ERC20/ERC721 资产，并愿意对攻击者指定的 spender 执行 approve/increaseAllowance/setApprovalForAll（钓鱼页面、假空投、假预售等）。
- 代币使用标准 `approve`/`allowance`/`transferFrom` 语义，且授权额度足够（常见是无限额度）。
- 攻击者能控制 CREATE2 的 deployer、salt 与 init_code，从而在授权后把恶意合约部署到受害者已授权的确切地址；或使用通用 CREATE2 deployer 预先算好地址。
- 钱包/安全产品只根据已部署合约的代码与历史做 spender 风险判断，未把“无代码地址 + 大额授权”视为高危。
- 受害者的授权交易与攻击者的部署/盗取代币交易之间没有钱包侧的二次确认或限额拦截。

## 利用步骤

1. 选择目标代币与受害者，确认代币的 `approve`/`transferFrom` 行为标准。
2. 准备 CREATE2 工厂或通用 deployer，选定 `salt` 与恶意合约的 `init_code`（构造函数参数可包含 token、victim、recipient 等，也可部署后再初始化）。
3. 预计算地址：`keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:]`；在区块浏览器确认该地址当前无代码、无交易。
4. 通过钓鱼页面/话术诱导受害者对该地址执行 `approve(addr, MAX)` 或 `increaseAllowance(addr, MAX)`；授权交易只与代币合约交互，spender 地址上仍无代码。
5. 受害者授权上链后，用相同 deployer/salt/init_code 部署恶意合约到预计算地址。
6. 调用恶意合约的 `drain`/`multicall`，内部执行 `token.transferFrom(victim, attacker, amount)`，把代币转走。
7. 可选的后续：通过 DEX 换成 ETH/稳定币、跨链转移，或继续对同一受害者的其他代币重复授权钓鱼。

## PoC

原文的 Factory/Child 示例给出了 CREATE2 部署与地址预计算的核心代码（未在本机复现）：

```solidity
contract Factory {
    event ChildCreated(address childAddress);

    function deployChild(uint256 _salt, address _owner) public {
        address childAddress;
        bytes memory bytecode = type(Child).creationCode;
        bytecode = abi.encodePacked(bytecode, abi.encode(_owner));
        assembly {
            childAddress := CREATE2(0, add(bytecode, 0x20), mload(bytecode), _salt)
        }
        require(childAddress != address(0), "Failed to deploy child contract");
        emit ChildCreated(childAddress);
    }

    function computeChildAddress(uint256 _salt, address _owner) public view returns (address) {
        bytes memory bytecode = type(Child).creationCode;
        bytecode = abi.encodePacked(bytecode, abi.encode(_owner));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), _salt, keccak256(bytecode)));
        return address(uint160(uint256(hash)));
    }
}
```

恶意合约的最小盗取逻辑（示意）：

```solidity
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract Drainer {
    function drain(address token, address victim, address to, uint256 amount) external {
        IERC20(token).transferFrom(victim, to, amount);
    }
}
```

原文链上证据（节选）：受害者对 `0xa01dee...` 的 `increaseAllowance` 交易；攻击者合约在 `0xa01dee...` 上的 `multicall` → `SUPER.transferFrom(sender=0xc9f304..., recipient=0x8f9278...)` trace；SUPER 代币地址 `0xe53ec727...`。未在本机复现链上交易。

## 变体与关联

- **CREATE 版本**：用 `CREATE` 也能预计算地址（`keccak256(rlp([sender, nonce]))[12:]`），但 nonce 会随创建者交易变化，攻击者更难稳定地让受害者授权到未来地址；CREATE2 的 salt 让地址可任意 grind、可重复预测，因此更适合此钓鱼。
- **ERC721/1155**：`setApprovalForAll(operator, true)` 同样只认地址，未来地址授权后可转走全部 NFT；逻辑与本卡一致。
- **Permit 签名**：EIP-2612 `permit(owner, spender, value, deadline, v, r, s)` 也是对 spender 地址授权，攻击者可让受害者签署一个 spender 为未来地址的 permit，再部署合约使用该签名。
- **地址碰撞/伪装**：CREATE2 可 grind 出与知名合约相似的地址前缀/后缀，增强钓鱼可信度；也可部署与合法合约相同接口的恶意实现。
- **与 `blockchain-solidity-create-address-precompute-public-selfdestruct` 的区别**：那张卡用 CREATE 地址预计算找回/销毁已部署合约；本卡用 CREATE2 预计算未部署地址并骗取授权，攻击面在钱包授权而非合约权限。
- **与普通 approve 钓鱼的区别**：普通钓鱼的 spender 是已部署的恶意合约，钱包可按代码/信誉拦截；本卡的 spender 在授权时没有代码，专门绕过基于合约历史的检测。

## 检测与防御

- **钱包/安全产品**：对 `approve`/`increaseAllowance`/`setApprovalForAll` 的 spender 做代码检查；spender 无代码、无历史、且授权额度为无限时，标为高危并强提示；模拟授权后的资金流向；限制无限授权或要求二次确认。
- **用户**：不要对不认识的地址授权；避免无限额度；定期用 revoke.cash 等撤销 allowance；在硬件钱包上核对 spender 地址与额度；对“空投/预售要求先授权”保持警惕。
- **链上监控**：监控 `Approval` 事件中 spender 无代码且额度极大的交易；监控 CREATE2 部署地址与历史 Approval spender 的重合；对新部署合约立即调用 `transferFrom` 的模式告警。
- **项目方/代币方**：无法在 ERC20 标准层阻止，但可在前端/钱包 SDK 中集成 spender 风险提示；对高价值用户推广限额授权与多签。
- **取证**：保留授权交易、CREATE2 部署交易、`transferFrom` trace 与资金流向；通过 deployer/salt/init_code 还原预计算地址，证明授权与部署的对应关系。
