---
id: blockchain-solidity-variable-shadowing-ambiguity
title: Solidity 变量歧义命名：命名返回变量遮蔽状态变量、继承中重复声明状态变量导致读取错误槽位
type: scenario
domain: blockchain
path: blockchain/solidity
technique: solidity-variable-shadowing-ambiguity
tags:
- solidity
- smart-contract
- shadowing
- variable-ambiguity
- inheritance
- storage-layout
- secure-coding
- evm
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V491
  verified_at: '2026-11-10T23:47:27+08:00'
  notes: 已对照原文全文与9/9图核对：ShadowingInFunctions(pragma 0.4.24) test1=0/test2=1/test3=4；Tokensale/Presale重复声明hardcap后两侧fetchCap均返回10000 ether(10^22)；修复版0.4.25删除重复声明+构造函数赋值后返回1000 ether(10^21)，均与Remix截图一致。与既有storage/delegatecall/array-underflow卡机制不同，非重复；无sources/文章ID/URL/长段摘录，路径blockchain/solidity合法；原文pragma仅为演示环境未声明受影响版本区间，versions保持为空。卡含遮蔽与继承双槽位两种同源表现，属同一『变量歧义命名』缺陷类，颗粒度可，不拆。
url: /docs/blockchain/solidity/blockchain-solidity-variable-shadowing-ambiguity/
draft: false
kb_aliases:
- Solidity 变量遮蔽
- Solidity 变量歧义命名
- 命名返回值遮蔽状态变量
- 继承重复声明状态变量
- hardcap 变量遮蔽
- state variable shadowing
- shadowing-state
- 合约变量同名
---

## 一句话结论

Solidity 允许局部变量与状态变量同名（编译器仅告警而不报错），也允许派生合约重复声明与基合约同名的状态变量：前者会让“命名返回值”这类未初始化局部变量遮蔽状态变量（读到默认值 0），后者会在存储中产生两个独立槽位、基合约函数始终读基合约的槽位，派生合约中重新赋值的同名变量看似生效却被忽略。两种歧义都会让安全判断（额度上限、管理员地址、白名单等）读到非预期值，是复杂合约中容易被忽视的隐蔽缺陷。

## 原理

- **作用域与遮蔽**：Solidity 的变量分为状态变量（存链上）、局部变量（函数执行期有效、存内存）和全局变量。函数签名 `function f() returns (uint n)` 中的 `n` 是一个已声明的局部变量（命名返回值），作用域覆盖整个函数体；当它与状态变量同名时，函数体内所有 `n` 都指向这个局部变量，状态变量被遮蔽。
- **未初始化局部变量的默认值**：局部变量不会自动从状态变量取值，未赋值时按类型默认值处理（`uint` 为 0）。因此 `uint n = 2; function test1() returns (uint n) { return n; }` 返回 0 而不是 2；`test2` 里 `n = 1` 只写局部返回值，返回 1；`test3` 的 `returns (uint x)` 又遮蔽了状态变量 `x = 3`，`uint n = 4; return n + x;` 实际是 `4 + 0 = 4`，而不是 `4 + 3`。这正是“同名变量在表达式里到底指谁”极易误判的地方。
- **继承中的存储槽位**：状态变量按声明顺序写入合约存储槽。基合约 `Tokensale` 的 `hardcap` 占一个槽；派生合约 `Presale is Tokensale` 再次 `uint hardcap = 1000 ether;` 会为派生合约**新分配一个槽位**，与基合约的 `hardcap` 是两个独立变量。`fetchCap()` 定义在基合约中，编译时按基合约的槽位索引取值，因此通过 `Presale` 调用继承来的 `fetchCap()` 仍然返回基合约的 10000 ether；派生合约的 1000 ether 只存在于另一个从未被读取的槽位。若该变量用于众筹上限、手续费、管理员/白名单等安全检查，实际生效的会是错误的那一份。
- **为什么允许**：早期 Solidity（文章示例使用 `pragma solidity 0.4.24`）对这类同名声明只给编译警告，不阻止部署；开发者若忽略 warning，缺陷就会进入链上。修复示例改用 0.4.25 并删除派生合约的重复声明，在派生构造函数中给基合约的 `hardcap` 赋值 `1000 ether`，`fetchCap()` 才返回 1000 ether。

## 触发条件

- 合约使用允许此类遮蔽/重复声明的 Solidity 版本（文章以 0.4.24 演示；新版本对部分情形会给出警告或错误，以目标编译器版本为准），且部署前未把警告当错误处理。
- 函数使用命名返回值，且返回变量名与状态变量同名；或函数参数/局部变量与状态变量同名后在表达式中直接使用该名字。
- 派生合约重复声明基合约已有的状态变量（同名不同类型/同类型都会产生新槽位），而读取该变量的函数定义在基合约中。
- 上述变量参与额度上限、权限判断、地址/开关等安全相关逻辑，且没有针对实际槽位的测试。

## 利用步骤

1. 审计合约的变量命名与作用域：查找函数命名返回值、函数参数、局部变量与状态变量同名的声明；查找派生合约与基合约之间的同名状态变量。
2. 对可疑函数在 Remix/本地链部署并逐一调用，观察返回值是否与状态变量初值一致（例如期望 2 却返回 0、期望 1000 ether 却返回 10000 ether）。
3. 对继承场景，分别通过基合约和派生合约调用同一继承函数，确认读取的是哪个槽位；必要时用 `vm.load`/存储槽读取工具核对槽位布局。
4. 评估影响：若被遮蔽/错位的是上限、费率、管理员、白名单等安全检查变量，构造边界条件验证检查是否被绕过或失效（例如上限检查读取了错误的高值）。
5. 修复后回归：删除派生合约的重复声明并在构造函数中给基合约变量赋值，或重命名消除歧义；重新部署验证返回值与预期一致。

## PoC

最小验证合约（示意，需用允许该写法的编译器版本编译）：

```solidity
pragma solidity 0.4.24;

contract ShadowingInFunctions {
    uint n = 2;
    uint x = 3;

    function test1() constant returns (uint n) { return n; }          // 返回 0（局部遮蔽状态变量 n）
    function test2() constant returns (uint n) { n = 1; return n; }   // 返回 1（只写局部）
    function test3() constant returns (uint x) { uint n = 4; return n + x; } // 返回 4（x 是未初始化的局部）
}

contract Tokensale {
    uint hardcap = 10000 ether;
    function fetchCap() public constant returns (uint) { return hardcap; }
}

contract Presale is Tokensale {
    uint hardcap = 1000 ether;   // 新槽位，基合约函数读不到
}
```

在 Remix 的 JavaScript VM 中部署后：`test1()` 返回 0、`test2()` 返回 1、`test3()` 返回 4；分别对 `Tokensale` 与 `Presale` 调用 `fetchCap()` 都返回 `10000000000000000000000`（10000 ether），`Presale` 的 1000 ether 被忽略。

修复版本（示意）：

```solidity
pragma solidity 0.4.25;

contract Tokensale {
    uint public hardcap = 10000 ether;
    function fetchCap() public constant returns (uint) { return hardcap; }
}

contract Presale is Tokensale {
    function Presale() Tokensale() {
        hardcap = 1000 ether;   // 直接改基合约的槽位
    }
}
```

修复后 `Presale.fetchCap()` 返回 `1000000000000000000000`（1000 ether）。

## 变体与关联

- 变体：命名返回值遮蔽、函数参数遮蔽、局部变量遮蔽状态变量；派生合约重复声明同类型/不同类型的同名状态变量；多重继承下同名状态变量产生多个槽位。
- 关联：[[blockchain-solidity-fallback-delegatecall-storage-collision-owner-hijack]]、[[blockchain-solidity-proxy-storage-collision-multicall-admin-hijack]]、[[blockchain-solidity-delegatecall-library-slot0-owner-hijack]]（代理/委托调用中的存储槽冲突，与本卡的“同名不同槽”同属存储布局问题但触发面不同）；[[blockchain-solidity-array-length-underflow-arbitrary-storage-owner]]（存储槽操纵导致 owner 篡改）。
- 边界：本卡展示的是变量解析/存储布局导致的错误取值，是否形成可利用的权限绕过或资金损失取决于具体合约把该变量用在何处；文章未给出真实合约的资金损失 PoC，实际风险评估需结合业务逻辑。

## 检测与防御

- **编译与静态分析**：把编译器 warning 当作 error（`-Werror`/CI 检查）；使用 Slither 的 `shadowing-state`、`shadowing-local`、`shadowing-builtin` 检测器，Solhint 的命名/遮蔽规则；对继承合约做存储布局 diff。
- **编码规范**：命名返回值、参数、局部变量避免与状态变量同名；派生合约不要重复声明基合约状态变量，改用构造函数赋值或重命名；安全相关变量使用明确前缀（如 `_cap`、`s_admin`）。
- **测试与审计**：对每个读取安全关键状态变量的函数断言其实际值；继承场景分别从基/派生合约入口调用验证；升级/多继承合约上线前核对存储槽布局；代码审计时把“同名变量”作为独立检查项。
