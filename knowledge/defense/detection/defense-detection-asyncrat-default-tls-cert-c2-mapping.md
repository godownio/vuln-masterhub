---
id: defense-detection-asyncrat-default-tls-cert-c2-mapping
title: AsyncRAT C2 服务端证书测绘：默认自签名证书 CN 含 AsyncRAT，空间测绘 app 与 cert.issuer 等价、改证书名即规避被动搜索
type: scenario
domain: defense
path: defense/detection
technique: asyncrat-default-tls-cert-c2-mapping
aliases:
- AsyncRAT 证书测绘
- cert.issuer AsyncRAT
- AsyncRAT C2 发现
- RAT 默认证书指纹
- app=AsyncRAT
- AsyncRAT 服务端测绘
tags:
- defense
- detection
- c2
- asyncrat
- tls
- certificate
- fofa
- attack-surface
- threat-hunting
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:11:32+08:00'
  notes: 已对照原文与9张图核对：FOFA app/cert.issuer 1682条811IP、反向差集0条、自建4实例(4404/5505/8808/9909)默认证书收录与改名规避、证书CN HackerC2 Server均与图3图4一致；测绘结果滞后与主动验证分工属实。未验证点：FOFA 1682/220 计数未复测（时效性数据），未对任何第三方资产执行探测。
---

## 一句话结论

AsyncRAT 服务端默认使用安装时生成的本地自签名 TLS 证书，Issuer/Subject 的 CommonName 直接带 `AsyncRAT`（Hacker Server 变体为 `HackerC2 Server`）。在空间测绘平台上 `app="AsyncRAT"` 与 `cert.issuer="AsyncRAT"` 的数据集完全一致、反向差集为 0，说明平台对该家族的识别实质上依赖证书字段；攻击者只要改掉证书名，被动搜索即失效，必须补充主动探测验证，而且测绘结果里大量历史资产早已下线。

## 原理

- **默认证书从安装环境生成**：AsyncRAT 服务端安装时会在服务端目录生成 `ServerCertificate`/`BackupCertificate` 等 p12 证书文件。文章测试用 Win7 主机生成的 p12 提取证书和私钥——该 p12 没有密码保护可直接取私钥，规避证书格式问题；Win7 默认优先选择 `TLS_RSA_WITH_AES_128_CBC_SHA`（非前向安全套件，优先级可调整），这也会反映到 TLS/JARM 指纹上。
- **证书字段可检索**：默认证书为自签名，Issuer 与 Subject 的 `CommonName` 含 `AsyncRAT`；改版服务端（Hacker Server/HackerC2 Server）生成 `CommonName: HackerC2 Server` 的自签名证书。证书在 TLS 握手明文可见，且被 Shodan/Censys/FOFA 等测绘平台归一入库，可按 issuer/subject 字符串直接检索。
- **平台识别逻辑被证书支配**：文章在 FOFA 上验证 `app="AsyncRAT"` 与 `cert.issuer="AsyncRAT"` 均为 1,682 条 / 811 个 IP，且 `app="AsyncRAT" && cert.issuer!="AsyncRAT"` 为 0 条——即平台的 `app` 标签完全由证书字段决定，没有任何不依赖证书的协议识别。
- **改名即规避**：在自建实例对比中，使用默认证书名的版本被 FOFA 收录，而改证书名的 Hacker 版端口即使平台能看到其证书（CN 显示为 `HackerC2 Server`），也不会出现在 `app="AsyncRAT"` 结果里。有经验的组织部署前会先改证书名，因此证书测绘只能覆盖“默认/懒惰部署”。
- **历史数据大量失效**：文章对比测绘 1,682 条与主动验证 220 条，差额绝大部分是已下线服务（测绘更新时间久远，sslscan/nmap/openssl 均超时，本地客户端也连不上）。仅凭测绘命中就上报会大量误报，必须主动确认当前可达。
- **与主动验证的分工**：证书搜索负责“找候选”，代价低、命中默认部署；心跳包重放/JARM 负责“确认在线与家族/版本”，能覆盖改证书名的资产。

## 触发条件

- 可访问 FOFA/Shodan/Censys 等互联网测绘平台（文章以 FOFA 为验证对象）；
- 目标为使用默认或未改证书的 AsyncRAT 服务端（Issuer/Subject CN 含 `AsyncRAT`），或其变体证书有已知 CN（如 `HackerC2 Server`）；
- 需要区分“历史收录”与“当前在线”，具备对候选做主动连接/握手验证的条件；
- 仅限授权范围内的威胁情报研究与防御测绘。

## 利用步骤

1. 测绘查询默认证书：
   ```text
   app="AsyncRAT"
   cert.issuer="AsyncRAT"
   ```
   用 `app="AsyncRAT" && cert.issuer!="AsyncRAT"` 验证差集（应接近 0，说明识别依赖证书）。
2. 对命中资产的 IP:端口 取证书并核对字段：
   ```bash
   openssl s_client -connect <ip>:<port> -showcerts </dev/null 2>/dev/null \
     | openssl x509 -noout -issuer -subject -dates
   sslscan <ip>:<port>
   ```
   关注自签名、CN 为 `AsyncRAT`/`HackerC2 Server`、异常有效期。
3. 对已知变体 CN 单独检索（如 `cert.issuer="HackerC2 Server"`），覆盖改默认名的部署；未知改名需靠主动探测。
4. 对每个候选做主动验证（TLS 握手特征、心跳包重放、JARM），剔除已下线资产，确认当前在线。
5. 对确认资产提取 IP/证书指纹/JA3S 等 IOC，与流量侧、主机侧告警做时间线关联，用于组织拓线与封禁。

## PoC

```text
# FOFA 语法（文章验证时实测）
app="AsyncRAT"
cert.issuer="AsyncRAT"
app="AsyncRAT" && cert.issuer!="AsyncRAT"    # 0 条，说明 app 标签≈证书字段

# 读取可疑服务端证书
openssl s_client -connect 203.0.113.10:8443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates
# 关注: Issuer/Subject CN 含 AsyncRAT 或 HackerC2 Server、SelfSigned
```

文章在自建 4 个实例（默认证书与改证书名的 Hacker 版本各两套）上验证了“默认证书被收录、改名版本躲过收录”，未给出批量 PoC；以上语法与证书读取命令为按文中方法还原，未对第三方资产执行。

## 变体与关联

- 变体：`Hacker Server`/`HackerC2 Server` 定制版把 CN 改为 `HackerC2 Server`，只能按新 CN 检索，或转主动探测。
- 变体：证书搜索可换 Shodan/Censys 的 `ssl.cert.issuer.cn`/`ssl.cert.subject.cn` 字段；结论同样是“默认值可检索、改名即失效”。
- 关联：[[defense-detection-asyncrat-ping-heartbeat-replay-verify]]——本项目配套的主动验证手段，用于确认测绘候选在线并绕过证书改名。
- 关联：[[defense-detection-sliver-default-tls-jarm-31337]]——同为开源 C2/RAT 默认证书/JARM 测绘思路；[[defense-detection-asyncrat-download-chain-traffic-triage]]——已控主机流量侧的 AsyncRAT 研判。
- 边界：证书改名、使用合法 CA 证书、套 CDN 后本方法完全失效；测绘数据有时间滞后；平台 `app` 标签逻辑可能随平台更新变化。

## 检测与防御

- 检测（防御方/狩猎）：对出站 TLS 连接检查服务端证书 CN/Issuer 是否含 `AsyncRAT` 等 RAT 默认字符串；结合 JA3S、证书 hex 特征与主机行为交叉确认。
- 检测（情报侧）：定期用测绘平台复查默认证书资产并主动验证在线率，避免把历史收录当作现役 C2。
- 防御（攻击面治理）：红队/授权测试部署 AsyncRAT 等服务端时不要使用默认证书，避免被公开测绘直接定位；企业侧封禁已知 C2 证书指纹与 IP。
- 注意：对互联网第三方资产做主动扫描/探测需有授权，测绘仅用于防御与情报目的。
