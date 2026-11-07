---
id: blockchain-solidity-private-state-storage-read
title: Solidity private 状态变量链上可读：eth_getStorageAt 按槽位还原动态字符串
type: scenario
domain: blockchain
path: blockchain/solidity
technique: solidity-private-storage-eth-getstorageat
tags:
- blockchain
- solidity
- evm
- storage-slot
- eth-getstorageat
- private-variable
- information-disclosure
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V201
  verified_at: '2026-11-07T02:10:21+08:00'
  notes: 已对照原文与全部61张图核对；未复跑PoC
url: /docs/blockchain/solidity/blockchain-solidity-private-state-storage-read/
draft: false
kb_aliases:
- private 变量读取
- eth_getStorageAt
- 合约存储槽
- Solidity storage slot
- keccak256(slot)
- 链上数据公开
---

## 一句话结论

Solidity 的 `private` 只限制合约代码内部的访问权限，不加密链上存储；任何人只要能拿到合约地址和部署时的存储布局，就能用 JSON-RPC 的 `eth_getStorageAt` 直接读取指定槽位，按动态字符串的规则拼接连续槽位并解码出明文，所谓“私有变量”并不具备机密性。

## 原理

- **EVM 存储是公开的键值空间**：每个合约账户都有 2^256 个 32 字节槽位，状态变量按声明顺序从槽 0 开始分配（常量、immutable、结构体/数组另有规则）。`eth_getStorageAt(address, slot, block)` 直接返回某个槽的 32 字节原始值，不需要调用合约函数，也不需要任何权限。
- **`private` 的语义**：`private` 只阻止其他合约和外部调用者通过 Solidity 接口访问变量；它不会加密数据，也不会阻止读取底层 storage。真正需要保密的数据必须加密后上链，或只把承诺/哈希放上链、明文留在链下。
- **动态字符串/字节数组的布局**：若 `string private flag` 位于槽 `p`，槽 `p` 本身通常存放 `length * 2 + 1`（长度标记与数据位置标志），实际数据从 `keccak256(p)` 开始，按 32 字节一个槽连续存放；长度超过 31 字节时跨多个槽。
- **本题的槽位**：flag 是槽 0 上的长字符串，数据起始槽为 `keccak256(32 字节全零)`，即 `0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563`。flag 长 79 字节，跨 3 个槽；读取 base、base+1、base+2 三个 32 字节字并拼接，截取前 79 字节，即为 flag 的 ASCII。
- **为什么能还原**：字符串数据在槽内是从低位地址开始、左对齐连续存放的；多个槽按 base 递增顺序拼接后就是原始字节流。只要知道字符串长度（可从槽 `p` 的低位读出，或按题目提示），截掉末尾填充即可。
- **常见误区**：`private` 变量在区块浏览器/Solidity 源码中看不到，但链上节点的 `eth_getStorageAt`、调试器 `debug_storageRangeAt`、以及任何归档节点都能读取；把 API key、口令、flag 直接写成 `private string` 是最常见的链上泄露。

## 触发条件

- 目标合约在链上部署，攻击者知道合约地址与所用网络（主网/Sepolia 等）。
- 目标把敏感数据（口令、flag、密钥材料）存进合约状态变量，且没有额外加密/承诺方案。
- 攻击者能访问支持 `eth_getStorageAt` 的 RPC 节点（公共 RPC、自建节点、归档节点均可）。
- 知道或能推断状态变量的声明顺序和槽位；对动态字符串还需知道数据起始槽与长度。
- 目标合约未把敏感数据放在 `immutable`/`constant` 之外的特殊结构里，或即使有结构也能按布局推导。

## 利用步骤

1. 获取合约地址、网络与 RPC URL；可在区块浏览器查看合约创建交易和已验证源码（若开源），确认状态变量声明顺序。
2. 确定目标变量所在槽 `p`（第一个状态变量为 0，依此类推）；若变量是动态字符串/数组，计算数据起始槽 `keccak256(p)`。
3. 用 `eth_getStorageAt` 读取 `base`、`base+1`、`base+2` 等连续槽；每个返回值是 0x 前缀的 32 字节十六进制。
4. 去掉 `0x` 后按读取顺序拼接；若知道字符串长度 L，取前 `2*L` 个十六进制字符，转字节后按 ASCII/UTF-8 解码。
5. 若不知道长度：读取槽 `p` 的原始值，`length = value // 2`（最低位为 1 表示长字符串）；或从拼接结果尾部去掉 `00` 填充后解码。
6. 对结构体/数组/映射：按 Solidity 存储布局递归计算槽位；映射槽为 `keccak256(key . slot)`，动态数组元素从 `keccak256(slot)` 开始。
7. 用 `eth_call` 调用公开 getter 交叉验证；若 getter 不存在，直接以原始 storage 为准。

## PoC

```python
import requests

CONTRACT = "0x88DC8f1de5Ff74d644C1a1defDc54869E5Ce3c08"
RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"
FLAG_LENGTH = 79

# 槽 0 是动态字符串，数据起始槽 = keccak256(32 字节零)
BASE_SLOT = "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"

def get_slot(slot: str) -> str:
    r = requests.post(RPC_URL, json={
        "jsonrpc": "2.0", "id": 1, "method": "eth_getStorageAt",
        "params": [CONTRACT, slot, "latest"],
    }, timeout=10)
    r.raise_for_status()
    return r.json()["result"][2:]

def read_string(length: int) -> str:
    raw = ""
    base = int(BASE_SLOT, 16)
    for i in range((length + 31) // 32):
        raw += get_slot(hex(base + i))
    return bytes.fromhex(raw[: length * 2]).decode("ascii")

print(read_string(FLAG_LENGTH))
```

通用槽位计算：

```python
from eth_utils import keccak

def data_slot(p: int) -> int:
    return int.from_bytes(keccak(p.to_bytes(32, "big")), "big")

# mapping(address => uint256) at slot p:
# slot = keccak(abi.encode(key, p))
```

## 变体与关联

- **固定长度 bytes32/uint256**：直接读槽 `p` 即可；`bytes32` 左对齐，`uint256` 右对齐，注意字节序。
- **短字符串（<=31 字节）**：数据与长度打包在槽 `p` 内，低字节为 `length*2`，高字节为字符串内容；直接按槽内字节解析。
- **动态数组**：槽 `p` 存长度，元素从 `keccak256(p)` 开始；结构体数组还要按元素步长跳槽。
- **映射**：`keccak256(abi.encode(key, p))`；嵌套映射逐层计算。
- **升级代理**：逻辑合约的 storage 布局由代理槽位决定，需按代理的存储布局读取；EIP-1967 实现槽本身也可读。
- **关联卡片**：[[blockchain-solidity-evm-guess-honeypot-detection]]（同样依赖 EVM storage 可见性识别合约状态）；[[blockchain-wallet-safe-delegatecall-slot0-mastercopy-hijack]]（存储槽覆盖型攻击）。

## 检测与防御

- **不要把秘密放在链上**：任何写入合约 storage 的数据都应视为公开；敏感数据使用链下存储 + 链上哈希/承诺，或使用经过审计的加密方案。
- **最小化上链数据**：只存必要状态；避免把口令、API key、私钥、flag、个人数据写入 `private` 变量。
- **审计存储布局**：检查合约是否有 `private`/`internal` 敏感字段、动态字符串跨槽、代理布局冲突；用 `eth_getStorageAt` 做一次只读自查。
- **权限与可观测性**：对 RPC 访问做限流与审计；监控大量连续 `eth_getStorageAt` 调用（尤其是同一合约相邻槽位），可能是自动化读取。
- **密钥管理**：链上合约不应持有长期密钥；必须使用时采用门限签名、HSM、链下签名等方案。
