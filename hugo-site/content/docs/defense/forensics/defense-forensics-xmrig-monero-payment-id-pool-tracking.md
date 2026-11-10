---
id: defense-forensics-xmrig-monero-payment-id-pool-tracking
title: XMRig 配置提取与 Monero 支付 ID 追踪：矿池 worker/支付记录到区块链交易与收益归因
type: scenario
domain: defense
path: defense/forensics
technique: xmrig-monero-payment-id-pool-tracking
tags:
- forensics
- malware
- cryptominer
- xmrig
- monero
- payment-id
- blockchain
- attribution
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:22:59+08:00'
  notes: 已对照原文与图19-22核对 config.json 的 pool/url/user 字段、hashvault worker/支付面板 4 笔 0.1099/0.11/0.1101/0.11 XMR、交易 7c106041... 的 0.1099 XMR 输出与活跃 STREAM worker；卡内已按格式区分钱包地址与支付 ID。
url: /docs/defense/forensics/defense-forensics-xmrig-monero-payment-id-pool-tracking/
draft: false
kb_aliases:
- XMRig 配置提取
- Monero 支付ID
- payment ID 追踪
- 矿池 worker 统计
- 挖矿收益归因
- hashvault 矿池
- GHOSTENGINE 挖矿
---

## 一句话结论

挖矿木马（如 GHOSTENGINE 部署的 XMRig）的 `config.json` 里通常包含矿池 URL、`user`（Monero 钱包地址/支付 ID）、算法与 TLS 等字段；把该 `user` 值拿去矿池的 worker/支付页面查询，可得到在线 worker、算力与支付记录，再用支付交易哈希到 Monero 区块链浏览器核对金额与时间——这条「配置 → 矿池统计 → 链上交易」路径能把样本与真实收益/运营者关联起来，用于归因和影响评估。

## 原理

- **XMRig 配置结构**：`pools[]` 中 `algo`（如 `rx/0`）、`coin`（`monero`）、`url`（矿池地址:端口）、`user`（钱包地址或支付 ID）、`keepalive`、`tls`；GHOSTENGINE 的配置还设置 `background: true`、`donate-level: 0`、`user-agent` 伪装成 Chrome、`watch: true`、`pause-on-battery/active: false`，保证后台持续挖矿。
- **Monero 支付 ID**：64 位十六进制（或集成地址中的 8 字节）支付 ID 附加在交易上，用于把矿池付款归属到某个矿工/租户；矿池面板通常直接用该值查询 worker 与付款记录。
- **矿池面板**：以 `user` 值查询矿池（示例 `pool.supportxmr.com` / hashvault）的 worker 统计，可看到平均算力、总份额、确认余额、总支付、支付笔数与交易哈希。
- **链上核对**：把矿池给出的支付交易哈希输入 Monero 区块链浏览器，核对输出地址、金额、时间与确认数；示例为 0.1099 XMR 的支付，4 个月内 4 笔合计约 0.44 XMR（文中按当时汇率约 60.70 美元）。
- **归因价值**：同一支付 ID 下可能关联多个受害主机（worker 名称/在线记录），可据此估算规模；支付 ID/钱包地址可作为 IOC 与执法/平台投诉线索；活跃 worker 说明感染仍在进行。
- **边界**：矿池可能下线/更换域名；支付 ID 可能被轮换或多活动共用；链上金额是潜在收益而非实际到手；隐私币的归因仍受交易所/矿池 KYC 限制。

## 触发条件

- 取得挖矿样本或其 `config.json`（磁盘、内存、C2 下载配置）。
- 配置中的矿池仍在线且支持该查询方式；支付 ID/钱包地址有效。
- 能访问矿池网站/API 与 Monero 区块链浏览器（公开数据）。
- 交易已被打包确认，矿池保留历史记录。

## 利用步骤

1. 从样本/内存/落盘文件中提取 `config.json`，记录 `pools[].url`、`user`、`algo`、`coin`、`tls`、`user-agent` 等字段。
2. 判断 `user` 是钱包地址还是支付 ID（长度/格式；支付 ID 常为 64 位 hex）。
3. 访问对应矿池的 worker/支付查询页（或用其 API），输入 `user` 值，记录 worker 数、算力、总支付、支付笔数与交易哈希。
4. 把交易哈希输入 Monero 区块链浏览器，核对输出地址、金额与时间；必要时用 `prove` 功能验证支付归属。
5. 汇总支付总额、时间线、活跃 worker 与相关主机名，评估感染规模与收益；把支付 ID、钱包地址、矿池 URL 纳入 IOC。
6. 若矿池下线，尝试用其他区块浏览器/公开数据集按支付 ID 或交易哈希检索。

## PoC

```json
{
  "autosave": false,
  "background": true,
  "donate-level": 0,
  "pools": [{
    "algo": "rx/0",
    "coin": "monero",
    "url": "pool.supportxmr[.]com:443",
    "user": "<64-hex-payment-id-or-wallet>",
    "keepalive": true,
    "tls": true
  }],
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...",
  "watch": true,
  "pause-on-battery": false,
  "pause-on-active": false
}
```

```text
# 查询路径（示意）
矿池面板 -> 输入 user/payment ID -> worker 列表/算力/支付记录 -> 交易哈希
交易哈希 -> Monero 区块链浏览器 -> 输出地址/金额/时间/确认数
```

说明：配置字段取自文中样本；`<64-hex-payment-id-or-wallet>` 为占位，实际 IOC 见样本提取结果。

## 变体与关联

- [[code-analysis-dynamic-debugging-miner-pool-address-extraction-static-xmrig-config-dynamic-getaddrinfow-breakpoint]]：静态/动态提取 XMRig 矿池地址的方法，可与本卡的支付 ID 追踪衔接。
- [[code-analysis-reverse-windows-silentcryptominer-service-injection-winring0]]、[[code-analysis-reverse-windows-silentcryptominer-340-svchost-powercfg-winring0]]：其他挖矿家族的配置/驱动面分析。
- [[defense-incident-response-docker-tomcat-mining-triage]]、[[defense-incident-response-linux-ssh-bruteforce-sshd-backdoor-mining-kinsing]]：主机侧挖矿应急与矿池域名溯源。
- 变体：其他币种/矿池/算法（门罗以外的矿池 API 字段不同）；支付 ID 可换钱包地址直付；矿池面板可换第三方统计站（miningpoolstats 等）。
- 边界：矿池下线、支付 ID 轮换、隐私币链上归因限制、样本配置加密时需先解密/内存提取。

## 检测与防御

- 检测：主机/网络出现 XMRig 配置（`rx/0`、`pool.*`、`stratum+tcp`、`donate-level`、`WinRing0x64.sys`）；周期性连接矿池域名/端口；`user-agent` 伪装 Chrome 但进程为挖矿程序。
- 检测：矿池域名/IP 与支付 ID/钱包地址作为 IOC 下发；EDR 扫描 `config.json`、XMRig 哈希与矿池连接。
- 防御：封锁已知矿池域名/端口与 Stratum 协议；限制终端出网与 CPU 异常占用；部署应用白名单；对挖矿样本做配置提取并追踪支付 ID，评估是否需平台投诉/执法协作。
- 响应：隔离主机、清除挖矿程序与持久化、轮换凭据；用支付 ID 关联同批受害主机，评估横向与再度感染风险。
