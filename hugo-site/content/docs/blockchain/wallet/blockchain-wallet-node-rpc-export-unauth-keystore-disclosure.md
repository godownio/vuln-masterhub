---
id: blockchain-wallet-node-rpc-export-unauth-keystore-disclosure
title: 公链钱包节点 RPC /v1/wallets/export 未鉴权：仅凭 wallet_id 导出加密 keystore 并离线破解口令
type: scenario
domain: blockchain
path: blockchain/wallet
technique: wallet-rpc-export-unauth-keystore
tags:
- blockchain
- wallet
- rpc
- unauthorized
- keystore
- massnet
- lotus
- key-material
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V577
  verified_at: '2026-11-12T11:19:22+08:00'
  notes: 已对照原文与7张图核对：文章主体为Geth源码分析，风险示例两点——地址解析截断panic（图03，按DoS排除未成卡）与钱包备份RPC鉴权缺失（图04/06 handler仅取wallet_id、无token/passphrase；图05 API文档；图07 PoC 127.0.0.1:9688/v1/wallets/export返回keystore，ThreadPool(100)）。修正：截图证据显示该RPC案例为MassNet（s.massWallet、keystore remark=massnet.org），Lotus仅为CLI地址panic示例，已将aliases/tags/一句话结论中的Lotus/Filecoin改为MassNet并注明。原文无版本区间与CVE，affected_versions留空；未演示离线破解到私钥，confidence medium合理。dedup候选（miner coinbase地址校验、钱包Web UI未授权、Geth存储读取等）均非同链；dup-scan未涉及；库内无其他wallet export卡。证据链成立，verified。
url: /docs/blockchain/wallet/blockchain-wallet-node-rpc-export-unauth-keystore-disclosure/
draft: false
kb_aliases:
- wallet export 未鉴权
- wallet_id 导出 keystore
- MassNet wallet export
- MassNet 钱包备份接口
- 钱包 RPC 权限校验缺失
---

## 一句话结论

公链钱包节点的导出接口（示例为 MassNet 风格 `/v1/wallets/export`，返回 keystore 中 `remark` 为 `massnet.org`；文中同篇另含 Lotus CLI `wallet export` 的地址解析 panic 示例）只接收 `wallet_id` 就返回对应钱包的加密 keystore JSON，handler（`APIServer.ExportWallet` / `Server.ExportKeystore`）不校验调用者身份、也不要求钱包口令；RPC 一旦暴露，攻击者即可枚举/猜测 wallet_id 批量导出 keystore，再用弱口令离线破解得到私钥控制资产。

## 原理

- **导出 handler 无鉴权**：示例代码（MassNet 钱包服务，字段名为 `massWallet`）中 `func (s *APIServer) ExportWallet(ctx, in *pb.ExportWalletRequest)` 直接调用 `s.massWallet.ExportWallet(in.WalletId)` 并把 `keystoreJSON` 原样放进响应；`ExportKeystore` 同样只取 `in.WalletId`，没有任何 token、session、来源校验或 passphrase 校验。授权模型退化为"知道 wallet_id 即可导出"。
- **wallet_id 不是秘密**：API 文档给出的请求体仅 `{"wallet_id": "<字符串>"}`；钱包列表/创建/交易等接口通常也会返回 wallet_id，日志、前端、备份文件中也可能出现。攻击者拿到或枚举到 id 后即可调用导出。
- **keystore 是加密私钥包**：响应 `keystore` 字段包含加密后的私钥材料（示例 JSON 中有 `cipher: "Stream cipher"`、`masterHDPrivKeyEnc`、`cryptoKeyEnc` 等字段），并非明文私钥；但它是离线爆破口令的完整目标——口令弱时可被字典/掩码破解，解出私钥后即可签名转账。Geth 系的 keystore v3 则为 scrypt + AES-128-CTR + Keccak MAC 结构，同样可离线爆破。
- **本地 CLI 与远程 RPC 的边界被打破**：`wallet export <address>` 作为本地 CLI 不需要鉴权是合理的，但同一能力被暴露成节点 RPC 后仍不做身份校验，就把"本机操作"变成了"任何能访问 RPC 的人都能备份钱包"。
- **危害取决于口令强度**：导出本身已构成密钥材料泄露；弱口令→私钥→资产被盗是完整链。文中建议在导出 RPC 增加 `passphrase` 字段做二次验证。

## 触发条件

- 目标节点暴露钱包 RPC/HTTP API（如 `127.0.0.1:9688` 被映射到外网、SSRF 可达、或与不可信服务同主机）。
- 目标版本的钱包导出接口未鉴权（仅凭 wallet_id）。
- 攻击者能获得/枚举有效 wallet_id。
- 钱包口令较弱（否则只能得到加密 keystore，无法解出私钥）。

## 利用步骤

1. 识别钱包节点 API（路径如 `/v1/wallets/export`，端口示例 9688），确认无需认证即可访问。
2. 枚举 wallet_id：调用钱包列表接口、从创建钱包响应/日志/前端配置中收集，或按格式爆破。
3. POST `wallet_id` 到导出接口，保存返回的keystore JSON；可并发批量导出。
4. 对 keystore 做离线口令爆破（按具体格式选择 hashcat/john 模式或自写脚本校验 MAC），得到明文私钥/助记词。
5. 用私钥签名交易转移资产，或长期监控钱包余额。

## PoC

```python
import requests

url = "http://127.0.0.1:9688/v1/wallets/export"
resp = requests.post(url, json={"wallet_id": "ac10lgrmt37rdedc7ff5uy5kper3rcjlwspvd6gkyq"})
print(resp.json()["keystore"])   # 返回加密 keystore JSON
```

```json
// 请求（API 文档示例）
{"wallet_id": "<wallet id>"}
// 响应字段
{"keystore": "{\"remark\":...,\"crypto\":{\"cipher\":\"Stream cipher\",...}}"}
```

- 并发脚本可用线程池（文中示例 `ThreadPool(100)`）批量尝试 wallet_id。
- 若导出接口要求登录态，先测试其他未鉴权钱包接口（创建/列表/签名）是否泄露 id 或直接可用。

## 变体与关联

- **同节点其他 RPC**：钱包创建、列表、签名、删除等接口若同样只凭 id 无鉴权，可组合成"枚举 → 导出 → 签名"的完整盗币链；参见 `web-generic-auth-public-chain-wallet-ui-unauth-api-frontend-route-first` 类前端路由/接口鉴权缺陷。
- **Geth keystore v3**：拿到 keystore 文件后按 scrypt（n/r/p/salt）+ AES-128-CTR（iv/ciphertext）+ Keccak256(derivedKey[16:32] || ciphertext) MAC 校验候选口令，是通用离线破解路径。
- **其它泄露途径**：备份系统、磁盘镜像、云存储、浏览器扩展本地存储都可能直接给出 keystore，与未授权导出互为补充。
- **地址解析 panic（本文另一示例）**：非法/截断地址导致 `slice bounds out of range` panic，属崩溃/DoS 类，未单独成卡。

## 检测与防御

- **导出接口强制鉴权**：要求有效登录态/管理 token，并在导出时校验钱包口令（文中建议增加 `passphrase` 字段）；不要只凭 wallet_id。
- **RPC 面收敛**：钱包 RPC 默认仅绑定 127.0.0.1，禁止直接暴露公网；必须远程访问时加 TLS 双向认证、IP 白名单与限流。
- **审计与告警**：记录 `ExportWallet/ExportKeystore` 调用（来源 IP、wallet_id、频率），对批量导出、异常来源、并发枚举告警。
- **口令与资产保护**：钱包使用强口令；高价值资产使用多签/硬件钱包；怀疑泄露时立即转移资产并重新生成钱包。
- **输入校验**：对地址/ID 参数做长度与格式校验，避免非法输入触发 panic（防御性修复，非本卡主场景）。
