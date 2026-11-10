---
id: blockchain-solidity-fallback-delegatecall-storage-collision-owner-hijack
title: fallback 直接 delegatecall(msg.data) 直通库函数：调用 pwn() 选择器在代理上下文覆写 slot0 owner
type: scenario
domain: blockchain
path: blockchain/solidity
technique: fallback-delegatecall-msgdata-storage-collision-owner-hijack
aliases:
- HackMe Lib delegatecall
- delegatecall(msg.data)
- fallback delegatecall 存储碰撞
- SolidityByExample delegatecall
- pwn() 改 owner
- 委托调用劫持 owner
tags:
- blockchain
- solidity
- evm
- delegatecall
- storage-collision
- fallback
- owner-hijack
- library
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404
  verified_at: '2026-11-09T13:22:32+08:00'
  notes: 已对照原文 3.1 SolidityByExample 核对：HackMe(slot0 owner/slot1 lib) fallback 直接 address(lib).delegatecall(msg.data)，Lib.pwn() 写 owner=msg.sender，pwn() 选择器 dd365b8b 已本地 keccak 复算一致。--force 保留理由复核成立：既有 delegatecall-library-slot0-owner-hijack 是 slot0 存库地址+setTime 两步改写链，本卡为固定库 fallback 直通单步写 slot0 owner，触发条件与利用链不同，非重复。小瑕疵：标题'代理上下文'略宽（HackMe 实为库调用方合约），正文表述准确，保留。未验证点：PoC 未链上运行；无受影响版本；无 sources/URL。
---

## 一句话结论

合约把 fallback 写成 `lib.delegatecall(msg.data)`，把调用者给的任意选择器原样转发给库合约；只要库中某个公开函数会写存储，它写的其实是调用方合约的存储。当库的变量布局与调用方错位（库的 `owner` 在 slot0、调用方的 `owner` 也在 slot0）时，攻击者调用 `pwn()` 让库代码执行 `owner = msg.sender`，就把目标合约的 owner 改成了自己。

## 原理

- **delegatecall 的上下文语义**：`A.delegatecall(B 的字节码)` 在 A 的地址与存储上执行 B 的代码，`msg.sender`/`msg.value` 保持不变；B 中声明的状态变量按 slot 编号落到 A 的存储上，变量名没有任何保护作用。
- **示例布局**：`HackMe` 声明 `address public owner`（slot0）、`Lib public lib`（slot1）；`Lib` 声明 `address public owner`（slot0）与 `pwn()`（`owner = msg.sender`）。两者 slot0 都是 owner，所以 `Lib.pwn()` 在 HackMe 上下文执行时写的就是 HackMe 的 owner。
- **任意选择器转发**：HackMe 的 `fallback()` 执行 `address(lib).delegatecall(msg.data)`，没有选择器白名单；攻击者向 HackMe 发送选择器为 `pwn()` 的 calldata，fallback 被触发并把同样的 calldata 转发给 Lib，Lib 的 `pwn()` 命中，`msg.sender` 仍是攻击合约。
- **为什么合约“看不到”这个入口**：HackMe 自身没有 `pwn()` 函数，源码里也没有修改 owner 的函数；漏洞存在于“fallback 把未校验的 calldata 转给库”这条隐式路径，静态阅读容易被忽略。
- **与普通代理的区别**：这里的库地址在部署时固定、没有升级需求，本可以不用 delegatecall；一旦使用，就必须保证库的存储布局与主合约完全一致，否则任意库函数的写操作都会落到主合约的敏感槽位上。

## 触发条件

- 合约 fallback/receive 直接把 `msg.data`（或用户可控的 calldata）交给 `delegatecall`，没有选择器白名单/函数路由校验。
- 被调用的库/实现合约与调用方共享存储布局，且存在写敏感槽位（owner、admin、实现地址等）的公开函数。
- 攻击者能向目标合约发送任意 calldata（链上任何人都可以）。
- 目标合约在 slot0 等敏感位置存有权限变量，且该变量被 `onlyOwner` 类逻辑使用。

## 利用步骤

1. 读取目标合约的 ABI/字节码，确认存在 fallback 且其中对固定地址执行 `delegatecall(msg.data)`。
2. 找到被委托的库合约，枚举其公开函数与存储布局，寻找会写 slot0/敏感槽的函数（本例 `pwn()` 写 `owner = msg.sender`）。
3. 构造 calldata = `pwn()` 的 4 字节选择器（`0xdd365b8b`），直接发给目标合约。
4. 目标 fallback 触发 → `lib.delegatecall("0xdd365b8b")` → `pwn()` 在目标存储执行 → `owner = msg.sender`（攻击者）。
5. 校验 `owner()` 已变为攻击者地址，随后调用原 `onlyOwner` 函数（提款、改参数、升级等）。
6. 如目标合约还持有用户授权（approve），可进一步借 owner 权限转走资产。

## PoC

最小合约（按原文示例重写）与调用：

```solidity
contract Lib {
    address public owner;          // 与 HackMe 的 slot0 对齐
    function pwn() public { owner = msg.sender; }
}

contract HackMe {
    address public owner;          // slot0
    Lib public lib;                // slot1
    constructor(Lib l) { owner = msg.sender; lib = l; }
    fallback() external payable { address(lib).delegatecall(msg.data); }
}

// 攻击：直接向 HackMe 发送 pwn() 选择器
// cast send <HackMe> "0xdd365b8b" --private-key <attacker>
// 或合约内：address(hackMe).call(abi.encodeWithSignature("pwn()"));
```

结果：`HackMe.owner()` 变为攻击者地址。`pwn()` 选择器可现场用 `bytes4(keccak256("pwn()"))` 计算，无需知道源码函数签名（从库字节码/ABI 即可枚举）。

## 变体与关联

- **任意地址 delegatecall**：若 delegatecall 的目标由用户传入（而非固定库地址），攻击者可以部署恶意合约，让任意代码在目标合约上下文中执行；除改 owner 外，还能借目标合约已有的 `approve`/余额转走资金。这类“开放 delegatecall”比固定库更危险，审计时优先排查。
- **库地址可写**：若库地址本身存在状态变量中且能被写（例如 `delegatecall` 的参数被库函数写回 slot0），可先用一笔调用换成恶意库，再触发第二次 delegatecall（Preservation 式的两次调用链）。
- **代理实现合约布局错位**：代理/实现之间变量声明顺序不一致导致的存储碰撞，与本案同源（delegatecall + 槽位错位），但代理场景的敏感槽通常是 implementation/admin。
- **selfdestruct 组合**：被 delegatecall 的库函数若调用 `selfdestruct`，会在调用方上下文销毁调用方合约（见下节说明），属独立 DoS 面，不在本卡范围。

## 检测与防御

- **禁止裸转发**：不要写 `delegatecall(msg.data)`；必须按白名单校验选择器（`require(msg.sig == ...)`）或使用明确的函数路由表（Diamond 的 facet+selector 映射）。
- **布局审计**：使用 `delegatecall` 时，库与调用方的存储布局必须逐槽对齐；用 Solidity 的 `library`（且函数为 `internal`，编译期内联、不产生 delegatecall）可避免运行时存储耦合。
- **权限变量防护**：owner/admin 等敏感变量不要放在 slot0 这类容易被库代码命中的位置；可使用 EIP-1967 专用槽位（`keccak256("eip1967.proxy.admin") - 1`）降低碰撞概率。
- **静态检测**：Slither 的 delegatecall/存储布局检查、`solhint` 规则；人工核对 fallback/receive 与所有 `delegatecall` 目标。
- **链上监控**：关注 fallback 被非预期选择器触发的交易、`OwnershipTransferred` 事件由非部署者发起；对 owner 变更设置告警。
- **测试**：为 fallback 转发编写模糊测试，枚举库函数选择器并断言敏感槽位不被改写。
