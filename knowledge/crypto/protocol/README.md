# 密码学协议

## 这层是什么

TLS、SSH、自定义协议的密码学缺陷。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [OpenTelemetry-Go 日志 gRPC 导出器忽略 env TLS 静默回退系统根（CVE-2026-81871）](crypto-protocol-otel-go-grpc-exporter-env-tls-ignored.md) | verified | high | 2026-11-05 |
| [协议中继与 nonce 哈希密钥：中间人观察双方 nonce 派生会话密钥](crypto-protocol-relay-nonce-hash-key.md) | verified | medium | 2026-11-06 |
| [协议公钥替换：服务端把敏感数据加密到消息中携带的攻击者公钥](crypto-protocol-public-key-substitution-unbound-cert.md) | verified | high | 2026-11-06 |
| [协议反射与中介攻击：证书和签名文本未绑定发送者导致双方互签](crypto-protocol-reflection-signature-confusion.md) | verified | medium | 2026-11-06 |
| [协议密钥替换：服务端使用攻击者提供的对称密钥与 nonce 加密敏感数据](crypto-protocol-attacker-controlled-symmetric-key-nonce.md) | verified | high | 2026-11-06 |
| [协议解密/重加密 oracle：把服务端当作双层解密机](crypto-protocol-decrypt-reencrypt-oracle.md) | verified | high | 2026-11-06 |
| [固件更新签名只覆盖 header：复用 sig/key_blob 重加密载荷，raw RSA 派生 AES key](crypto-protocol-update-signature-header-only-keyblob-unauthenticated.md) | verified | high | 2026-11-06 |
| [猜拳承诺可预测：3 值 dealer + 可验证掩码导致每轮必胜](crypto-protocol-three-way-commitment-mask-dealer-recovery.md) | verified | high | 2026-11-06 |
| [自定义协议身份字段伪造：只校验消息中的名字而不校验发送者](crypto-protocol-identity-field-spoofing-missing-sender-auth.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
