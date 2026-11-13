---
id: defense-detection-ja4x-x509-cert-generation-fingerprint
title: JA4X X.509 证书生成方式指纹：Issuer/Subject RDN 字段名 + 扩展序三段哈希
type: scenario
domain: defense
path: defense/detection
technique: ja4x-x509-cert-generation-fingerprint
aliases:
- JA4X 指纹
- JA4-X.509
- 证书生成方式指纹
- Issuer RDNs 哈希
- Subject RDNs 哈希
tags:
- defense
- detection
- ja4
- x509
- certificate
- fingerprint
- c2
- threat-intel
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:39:01+08:00'
  notes: 已对照原文与图33/34核对：JA4X_a/b/c 分别为 Issuer RDN 字段名序、Subject RDN 字段名序、X.509v3 扩展序的 SHA256 前 12 位，不看具体值；工具样例 SoftEther/Metasploit/Qakbot/Async-Quasar-BitRAT/Sliver-Havoc 两组与幻灯片表格逐字节一致；示例值取自截图未本地复算。
---

## 一句话结论

JA4X 不哈希证书里的具体值（值随机且易变），而是哈希证书的**生成方式**：Issuer RDNs 字段名序列、Subject RDNs 字段名序列、X.509v3 扩展序列，三段各取 SHA256 前 12 位；同一工具/模板/CA 生成的证书会产生相同 JA4X，可用于聚类 C2/恶意软件默认证书、识别仿冒基础设施，并与 JA4/JARM/Issuer Org 组合降低误报。

## 原理

- X.509 证书的值（序列号、公钥、时间、域名）每个证书都不同，但**生成方式**（用哪套库/模板、RDN 字段的顺序与集合、扩展的种类与顺序）在同一工具或同一 CA 配置下高度稳定。
- **JA4X_a**：取 Issuer RDNs（颁发者相对专有名称）的字段名，按原始顺序用 `,` 连接（不包含具体值），SHA256 取小写前 12 位。自签证书的 Issuer=Subject；CA 证书的 Issuer 是上级机构信息。
- **JA4X_b**：取 Subject RDNs（主题相对专有名称）的字段名，按原始顺序，SHA256 取前 12 位。通常包含 CN、O、OU、C、ST、L、emailAddress 等字段，字段集合与顺序反映生成模板。
- **JA4X_c**：取 X.509v3 扩展（不是 TLS 握手的扩展）按原始顺序，SHA256 取前 12 位；扩展种类/顺序同样由生成工具决定。
- 例：`96a6439c8f5c_96a6439c8f5c_aae71e8db6d7`（Issuer/Subject 相同，说明自签）。
- 已知工具/家族样例：SoftEther VPN `d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae`；Metasploit `2bab15409345_2bab15409345_75f1b0fafedd`；Qakbot `2bab15409345_af684594efb4_e3b0c44298fc`；Async/Quasar/BitRAT `7022c563de38_7022c563de38_0147df7a0c11`；Sliver/Havoc C2 `000000000000_7c32fa18c13e_bf0f0589fc03`、`000000000000_4f24da86fad6_bf0f0589fc03`。
- 为什么有用：C2 框架/远控常使用固定证书模板或自签默认证书，JA4X 能在不解密、不看域名的情况下把同一工具生成的证书聚类；对伪造政府/银行站点，也能按生成方式发现同一批模板。
- 边界：同一工具可能被不同组织使用（误报）；证书模板可被修改；Let's Encrypt 等公共 CA 的证书会大量共享 JA4X；必须与 JA4、JARM、Issuer Org、证书内容等组合。

## 触发条件

- 能获取 X.509 证书（TLS 握手、证书透明日志、扫描引擎、样本配置中的证书）。
- 采集/分析工具支持 JA4X（Wireshark 4.2+/插件、FoxIO 脚本，或自行按 RDN/扩展顺序计算）。
- 有已知工具/家族的 JA4X 基线或情报库。

## 利用步骤

1. 从 TLS 握手/证书文件/CT 日志提取 DER/PEM 证书。
2. 解析 Issuer RDNs 与 Subject RDNs 的字段名序列（保持原始顺序，忽略值）。
3. 解析 X.509v3 扩展序列（保持原始顺序）。
4. 分别 SHA256 取前 12 位，拼成 `JA4X_a_JA4X_b_JA4X_c`。
5. 与已知工具/家族 JA4X 库比对；对命中项结合 JA4、JARM、Issuer Org、证书有效期/域名判断归属。
6. 对同一 JA4X 的证书集合做聚类，输出资产/基础设施清单；对自签且 JA4X 命中远控默认模板的证书优先排查。

## PoC

```text
# 结构
JA4X = SHA256(Issuer RDN field names, order)[:12]
     _ SHA256(Subject RDN field names, order)[:12]
     _ SHA256(X.509v3 Extensions, order)[:12]

# 示例（自签，Issuer=Subject）
JA4X = 96a6439c8f5c_96a6439c8f5c_aae71e8db6d7

# 已知模板（文章样例）
SoftEther VPN      = d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae
Metasploit         = 2bab15409345_2bab15409345_75f1b0fafedd
Qakbot             = 2bab15409345_af684594efb4_e3b0c44298fc
Async/Quasar/BitRAT= 7022c563de38_7022c563de38_0147df7a0c11
Sliver/Havoc C2    = 000000000000_7c32fa18c13e_bf0f0589fc03
```

说明：样例取自文章截图，未在本地复算；字段名哈希的具体序列化格式（分隔符、大小写）需与 FoxIO 实现保持一致。

## 变体与关联

- 变体：自签证书 Issuer=Subject，JA4X_a 与 JA4X_b 相同；公共 CA 证书的 Issuer 字段固定，JA4X_a 会大量重复。
- 变体：不同工具可能共享同一底层库（如 OpenSSL 默认模板），导致 JA4X 部分相同；需结合 JA4X_c 与证书内容。
- 关联：[[defense-detection-ja4-tls-client-fingerprint-modular]]（TLS 客户端 JA4）；[[defense-detection-ja4s-tls-server-fingerprint]]（服务端 JA4S）；[[defense-detection-cobaltstrike-default-jarm-cert-fofa]]（JARM/默认证书测绘）；[[defense-detection-asyncrat-default-tls-cert-c2-mapping]]（默认证书 CN 测绘）。
- 边界：模板可定制、公共 CA 证书共享 JA4X、证书值随机但不影响生成方式；JA4X 不能单独证明恶意。

## 检测与防御

- 检测：建立已知远控/C2 框架的 JA4X 库，对自签证书、异常 Issuer/Subject 字段顺序、空 RDN 的证书优先匹配；与 JA4/JARM/证书 CN 组合。
- 基线：对企业自有证书的 JA4X 做白名单，发现同 JA4X 但非企业签发的证书（仿冒/影子资产）告警。
- 对抗：攻击者可修改证书模板或使用公共 CA 证书规避；JA4X 只能作为组合特征。
- 取证：保存证书 DER 与 JA4X 计算结果，作为基础设施同源证据之一。
