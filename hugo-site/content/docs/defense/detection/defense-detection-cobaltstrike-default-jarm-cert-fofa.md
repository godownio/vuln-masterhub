---
id: defense-detection-cobaltstrike-default-jarm-cert-fofa
title: CobaltStrike TeamServer 默认指纹测绘：默认证书 Major Cobalt Strike 与已知 JARM 在 FOFA 批量发现
type: scenario
domain: defense
path: defense/detection
technique: cobaltstrike-default-jarm-cert-space-mapping
tags:
- defense
- detection
- cobalt-strike
- c2
- jarm
- tls
- certificate
- fofa
- threat-hunting
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T02:40:46+08:00'
  notes: 已对照原文0x01节及图3核对:JARM值、FOFA语法、13条命中、默认证书Organization=cobaltstrike/CN=Major Cobalt Strike均与原文截图一致;JARM为特定版本时点特征,未重新采集验证。
url: /docs/defense/detection/defense-detection-cobaltstrike-default-jarm-cert-fofa/
draft: false
kb_aliases:
- CS 默认 JARM
- 07d14d16d21d21d07c42d41d00041d
- Major Cobalt Strike 证书
- COBALTSTRIKE-团队服务器
- C2 空间测绘反查
- FOFA jarm 语法
---

## 一句话结论

未修改 profile/证书的 Cobalt Strike TeamServer 会在 TLS 侧暴露一组稳定指纹：默认证书的 Issuer/Subject Organization 为 `cobaltstrike`、CommonName 为 `Major Cobalt Strike`，早期版本服务端还有固定 JARM（示例 `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1`）；把 JARM 与证书关键字组合进 FOFA/Shodan/Censys 查询（FOFA 中可再加 `category="其他安全产品" && product="COBALTSTRIKE-团队服务器"`），即可批量定位暴露在公网的 CS 团队服务器（原文截图查询命中 13 条，端口多为 50050）。

## 原理

- **JARM 是主动 TLS 指纹**：JARM 向服务端发送多组特制 ClientHello，根据 TLS 版本、密码套件、扩展顺序等响应计算 62 字符哈希。它由服务端 TLS 实现/配置决定，与域名、IP、证书内容无关，因此同一 CS 版本/配置的服务端会呈现相同 JARM，换 IP/域名后仍可能被关联。
- **默认证书是更直观的指纹**：CS TeamServer 默认自签证书的 Organization 为 `cobaltstrike`、CommonName 为 `Major Cobalt Strike`（原文截图中 Issuer 与 Subject 均如此，Validity 为 Untrust）。网络空间测绘平台会解析 TLS 证书字段，可直接检索证书主题。
- **平台侧产品标签放大命中**：FOFA 等平台会把匹配到的资产归类为“其他安全产品/黑客工具/COBALTSTRIKE-团队服务器”，组合 `jarm=... && category="其他安全产品" && product="COBALTSTRIKE-团队服务器"` 可压缩误报；原文截图显示该查询耗时 625ms 命中 13 条独立资产。
- **与默认端口的关联**：截图中资产多为 50050 端口（CS TeamServer 默认管理端口），也有 8443 等；端口不是必要条件，但可作为交叉验证。
- **为什么有效与边界**：这些指纹只在“未改默认配置”时成立；修改 Malleable C2 Profile、替换证书、用 Nginx/Apache/云函数中转、修改 JARM/JA3（如 uTLS/自定义 TLS 栈）后都会失效。JARM 还随 CS 版本与编译选项变化，原文也注明是“早期某版本”的值，使用前应重新采集验证，不能把单一指纹当作定性结论。

## 触发条件

- 目标 CS TeamServer 使用默认自签证书，或 TLS 指纹与已知 CS 版本一致。
- 资产暴露在公网并可被空间测绘平台扫描到（无 CDN/反连代理隐藏 Origin）。
- 使用支持 JARM 与证书字段检索的平台（FOFA/Shodan/Censys/Quake 等，语法各异）。
- 仅用于授权资产排查、威胁狩猎与攻防演练中的防守方自查。

## 利用步骤

1. 在 FOFA 输入组合查询：`jarm="07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1" && category="其他安全产品" && product="COBALTSTRIKE-团队服务器"`，必要时追加 `product="Major-Cobalt-Strike"`。
2. 对命中资产核对证书：Issuer/Subject 是否为 `Organization: cobaltstrike`、`CommonName: Major Cobalt Strike`；查看端口（50050/8443 等）与 JARM 值。
3. 用 `jarm.py` 等工具对可疑主机重新计算 JARM，与已知值比对；用 Shodan `ssl:"Major Cobalt Strike"` 或 Censys 证书检索交叉验证。
4. 对确认的资产做归属与处置：若属于本单位，立即修改 profile、替换证书、隐藏 Origin；若属于外部，录入情报并评估是否与已有攻击事件关联。
5. 定期重新采集本版本 CS 的 JARM 与证书特征，更新检测规则，避免旧指纹失效后漏报。

## PoC

FOFA 查询（原文截图）：

```text
jarm="07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1" && category="其他安全产品" && product="COBALTSTRIKE-团队服务器" && product="Major-Cobalt-Strike"
```

本地重算 JARM（示意）：

```bash
python3 jarm.py <suspected-host> -p 50050
```

证书查看（示意）：

```bash
openssl s_client -connect <suspected-host>:50050 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
# 期望看到 Organization=cobaltstrike / CommonName=Major Cobalt Strike（默认配置）
```

说明：JARM 值与证书字段来自原文及其截图，属特定版本/配置的时点特征；未在真实环境重算，使用前需自行验证。

## 变体与关联

- **同类 C2 指纹卡**：Sliver 的默认 31337/证书 CN/JARM 测绘见 [[defense-detection-sliver-default-tls-jarm-31337]]；CS 流量侧 JA3/checksum8 与 Beacon 配置提取见 [[defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract]]。
- **反制视角**：识别出 TeamServer 后的端口/证书指纹与弱口令爆破接管见 [[pentest-c2-cobaltstrike-teamserver-fingerprint-brute-takeover]]。
- **攻击方对抗**：自定义 Malleable Profile、替换证书、CDN 前置、JARM/JA3 修改会同时绕过本卡与流量侧指纹；对应伪装案例见 [[pentest-c2-cs-malleable-10086-traffic-masquerade]]。
- **边界**：JARM 是概率性指纹，可能随版本漂移或被他类服务偶然命中；证书字段可被伪造；必须与端口、HTTP 行为、证书链和主机侧证据联合判断。

## 检测与防御

- **资产自查**：定期用本卡的 FOFA/Shodan 查询检索本单位网段与云资产，发现默认证书/JARM 的 CS 服务端立即下线整改。
- **暴露面治理**：TeamServer 不直接暴露公网，使用重定向器/CDN/云函数中转；强制自定义证书与 Malleable Profile；修改 JARM/JA3 特征。
- **监测**：对内部出站到 50050 等异常端口的长连接、对已知 C2 证书/JARM 的 TLS 握手做告警；将 JARM/证书哈希纳入威胁情报。
- **注意**：空间测绘结果可能包含蜜罐与误报；处置前需确认资产归属，避免误伤。
