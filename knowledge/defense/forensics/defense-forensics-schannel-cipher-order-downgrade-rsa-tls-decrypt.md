---
id: defense-forensics-schannel-cipher-order-downgrade-rsa-tls-decrypt
title: SChannel 套件顺序降级强制 RSA 密钥交换：用 p12 私钥解密原本 ECDHE 的 TLS 1.2 流量
type: scenario
domain: defense
path: defense/forensics
technique: schannel-cipher-order-rsa-key-exchange-tls-decrypt
aliases:
- SChannel 密码套件顺序
- SSL 密码套件顺序
- TLS RSA 密钥交换解密
- p12 私钥解密 C2 流量
- ECDHE 强制降级 RSA
- quasar.p12 提取私钥
tags:
- forensics
- traffic-analysis
- tls
- schannel
- cipher-suite
- rsa-key-exchange
- wireshark
- malware-analysis
- quasar-rat
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:15:58+08:00'
  notes: 已对照原文核对：quasar.p12 空口令 openssl 导出私钥、组策略/DISM/注册表 Functions 调整 SChannel 套件顺序并重启、降级后 ServerHello 为 TLS_RSA_WITH_AES_256_CBC_SHA(0x0035)、Wireshark RSA keys 解密均与原文及图 07/11-16 一致；图 16 显示降级后记录层版本为 TLS 1.0，卡内已提示以 ServerHello 实际套件/版本为准；原文未明说改的是客户端还是服务端，卡内按可控分析机表述并注明对端需支持静态 RSA；未实测。
---

## 一句话结论

TLS 1.2 协商 ECDHE 套件时，服务器证书私钥只用于签名，无法反推临时会话密钥，拿到 p12 私钥也解不开流量；在可控的 Windows 分析机上通过组策略或注册表把静态 RSA 密钥交换套件排到 SChannel 套件顺序最前并重启，让下一次握手改走 `TLS_RSA_WITH_*`，重新抓包后即可用 p12 私钥在 Wireshark 中解密整段 C2 会话。

## 原理

- TLS 1.2 的会话密钥由密钥交换算法决定。ECDHE 使用双方临时生成的椭圆曲线密钥对：私钥只在握手内存中存在，握手结束即丢弃，服务器证书私钥仅用于对 ServerKeyExchange 签名。因此即使拿到服务器证书私钥，也无法从流量反推出会话密钥——这正是前向保密的意义。
- 静态 RSA 密钥交换（`TLS_RSA_WITH_*`）不同：客户端生成 pre-master secret，用服务器证书公钥加密后放进 ClientKeyExchange；服务器用自己的私钥解密得到 pre-master，双方再用 ClientHello/ServerHello 随机数与 pre-master 派生会话密钥。因此只要掌握服务器私钥，就能离线解密整段会话。
- Windows 的 TLS 实现 SChannel 按「SSL 密码套件顺序」策略决定本端提供的套件优先级。把静态 RSA 套件写到策略列表最前并重启后，新的握手会优先协商它。对 Quasar 这类基于 .NET `SslStream` 的客户端，只需修改客户端所在 Windows 的策略即可改变协商结果，前提是服务端也启用了对应套件。
- 协议版本边界：TLS 1.3 已删除静态 RSA 密钥交换，只有 TLS 1.2 及以下可用；修改套件顺序还可能连带改变协商出的记录层版本，需在 ServerHello 中确认实际套件。
- Quasar 服务端项目根目录会生成 `quasar.p12`（PKCS#12，含证书与私钥），默认没有口令保护，用 `openssl pkcs12 -nodes` 可直接导出私钥，是该方法常见的前置条件。

## 触发条件

- 已有 TLS 1.2 会话的 pcap，且 ServerHello 显示 ECDHE 套件（`TLS_ECDHE_*`），单靠私钥无法解密。
- 拥有服务器证书私钥（如服务端目录中的 `quasar.p12`，口令可为空）。
- 可在客户端或服务端一侧的 Windows 上修改 SChannel 密码套件策略并重启，且两端至少有一方支持静态 RSA 套件、对端允许协商。
- 流量为 TLS 1.2 及以下；TLS 1.3 不适用。
- 仅用于授权取证与恶意样本分析环境。

## 利用步骤

1. 从服务器文件/镜像取得 p12，导出私钥（口令为空直接回车）：

   ```bash
   openssl pkcs12 -in quasar.p12 -out certificate.pem -nodes
   grep -A2 "BEGIN PRIVATE KEY" certificate.pem
   ```

2. 用 Wireshark 过滤 `tls.handshake.type == 2` 查看原 ServerHello 套件；若为 `TLS_ECDHE_*`，确认仅凭私钥不能解密。
3. 在 Windows 分析机启用组策略：部分版本（家庭版/单语言版）缺少组策略编辑器，可用 DISM 添加 GroupPolicy ClientExtensions/ClientTools 包；若策略不生效，改用注册表。
4. 组策略路径：计算机配置 → 管理模板 → 网络 → SSL 配置设置 → SSL 密码套件顺序，启用后按优先级填写套件列表，把静态 RSA 套件（如 `TLS_RSA_WITH_AES_128_CBC_SHA`、`TLS_RSA_WITH_AES_256_CBC_SHA`）放在最前。
5. 注册表路径：`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`，新建或编辑多字符串值 `Functions`，首行写静态 RSA 套件。
6. 重启系统使策略生效，重新运行样本/客户端并抓包；确认 ServerHello 的 Cipher Suite 已变为 `TLS_RSA_WITH_*`（示例为 `TLS_RSA_WITH_AES_256_CBC_SHA`，0x0035）。
7. Wireshark → 编辑 → 首选项 → Protocols → TLS → RSA keys list，添加服务器私钥（必要时附证书），重新打开 pcap，即可看到解密后的应用层数据。
8. 对解密后的载荷继续做序列化解析（如 Quasar 的 protobuf 消息）。

## PoC

```bash
# 从 PKCS#12 导出私钥（Quasar 默认为空口令）
openssl pkcs12 -in quasar.p12 -out certificate.pem -nodes
grep -A2 "BEGIN PRIVATE KEY" certificate.pem
```

```text
# 注册表策略（REG_MULTI_SZ，值名 Functions）
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002
Functions = TLS_RSA_WITH_AES_256_CBC_SHA
```

```text
# Wireshark 验证握手是否已降级为静态 RSA
tls.handshake.type == 2
# 查看 ServerHello -> Cipher Suite 是否为 TLS_RSA_WITH_*
```

Wireshark 的 RSA keys list 为 GUI 配置，菜单位置随版本略有差异；示例中的套件名可按需替换为其他 `TLS_RSA_WITH_*`。

## 变体与关联

- 变体：无法修改客户端策略时，可在可控的服务端一侧调整；或改用 `SSLKEYLOGFILE`/内存提取会话密钥，适用于 ECDHE 与 TLS 1.3。
- 变体：若服务端只启用 ECDHE 套件，强制客户端 RSA 套件会导致握手失败，需要在服务端策略中同时启用静态 RSA 套件或改用服务端密钥日志。
- 关联：[[defense-forensics-rdp-pfx-tls-decrypt-scancode-replay]]（同样用 pfx 私钥解 TLS，并说明 ECDHE 需 keylog）；[[defense-detection-quasar-rat-tls-traffic-fingerprint]]（Quasar 默认 ECDHE 套件与 TLS 流量特征）；[[code-analysis-reverse-windows-quasar-rat-aes256-config-decrypt]]（先从样本配置解出 C2 与证书）。
- 边界：TLS 1.3、服务端禁用静态 RSA、无法重启或改策略、p12 有未知口令时不可用；修改套件顺序会改变客户端 JA3 并可能引入兼容性问题，只能在隔离的分析环境中使用。

## 检测与防御

- 生产环境应禁用静态 RSA 密钥交换套件，优先 ECDHE/ECDH，保证前向保密：这样服务器私钥泄露时，历史流量仍不可解密。TLS 1.3 已默认不支持静态 RSA。
- 检测视角：现代客户端/服务器协商出 `TLS_RSA_WITH_*` 属于异常，可结合 JA3/JA3S 与资产基线告警——可能是老旧系统、中间盒或分析环境。
- 分析环境管理：修改过套件策略的机器应隔离、使用快照可回滚，不要将该策略带入生产；p12 私钥与解密结果按证据保管链保存。
- 取证交叉验证：解密出的 C2 地址与样本配置、服务器日志、主机侧网络记录互相印证。
