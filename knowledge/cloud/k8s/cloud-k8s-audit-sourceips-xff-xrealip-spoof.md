---
id: cloud-k8s-audit-sourceips-xff-xrealip-spoof
title: K8s 审计日志 sourceIPs 污染：X-Forwarded-For 批量伪造 + X-Real-IP 单 IP，真实来源仍在末尾
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-audit-sourceips-xff-xrealip-spoof
aliases:
- K8s 审计日志伪造来源 IP
- X-Forwarded-For 污染
- X-Real-IP 伪造
- sourceIPs 混淆
- k8s 溯源干扰
- 审计日志反溯源
tags:
- cloud
- k8s
- audit
- source-ip
- x-forwarded-for
- x-real-ip
- anti-forensics
- log-injection
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:15:28+08:00'
  notes: 已对照原文核对：XFF 192.168.49.1-254 与 X-Real-IP 两个 curl、审计日志 sourceIPs 数组截图（真实 IP 追加末尾）、原文『真实 IP 总在最后』的结论均一致。未验证点：原文仅在 minikube 环境实测，未覆盖经过 Ingress/代理覆盖头的场景（卡内已注明）。
---

## 一句话结论

Kubernetes apiserver 的审计日志会把请求中的 `X-Forwarded-For`、`X-Real-IP` 头内容汇总进 `sourceIPs` 数组；攻击者用带大量伪造 IP 的 `X-Forwarded-For`（或单个 `X-Real-IP`）发 API 请求，就能让审计日志出现一长串与攻击者无关的 IP，增加防守方按 IP 溯源的筛选/关联成本；但真实来源 IP 仍会被追加在数组末尾，防守方读取最后一个 IP 即可还原真实来源。

## 原理

- K8s 审计事件（`audit.k8s.io/v1`）的 `sourceIPs` 字段记录请求来源。apiserver 在填充该字段时会把代理头 `X-Forwarded-For`（逗号分隔的 IP 链）和 `X-Real-IP`（单个 IP）纳入，再追加实际连接的来源地址。
- `X-Forwarded-For` 是 HTTP 代理常用的客户端 IP 传递头，语义上允许一路追加；apiserver 不校验其内容是否可信，直接写入审计日志。因此攻击者可以写任意多个 IP（原文示例从 `192.168.49.1` 一直列到 `192.168.49.254`）。
- `X-Real-IP` 只能放一个 IP，同样会被记录，但伪造效果有限；实测审计日志 `sourceIPs` 为 `["192.168.49.2", "192.168.49.1"]`，其中 `192.168.49.1` 是真实来源。
- 真实来源 IP 总是被追加到 `sourceIPs` 末尾（原文实测修改 IP 顺序/内容不会改变这一行为），所以这不是“完全隐藏来源”，而是“用大量噪声淹没真实 IP”，让按 IP 频次、地理、威胁情报关联的溯源多花时间。
- 该技巧不绕过认证/授权，只影响审计数据的可读性；它适用于已经拿到合法凭据（或处于内网）的攻击者在 API 操作时持续投放噪声。

## 触发条件

- 目标 K8s 集群开启审计日志（`--audit-log-path` 或审计 webhook），且审计级别至少记录 `Metadata`/`Request`（`sourceIPs` 通常在这些级别出现）。
- 攻击者能向 apiserver（或经过的代理）发送请求，并能设置 `X-Forwarded-For`/`X-Real-IP` 头；若中间代理会覆盖这些头，效果会受限。
- 审计日志的消费方（SIEM/平台）按 `sourceIPs` 做溯源或告警，且没有优先取最后一个 IP。

## 利用步骤

1. 确认目标 apiserver 的审计日志会记录 `sourceIPs`，并观察默认请求的 `sourceIPs` 内容。
2. 构造带大量伪造 IP 的 `X-Forwarded-For` 请求（原文使用 192.168.49.1–254），正常访问一个会产生审计事件的 API（如 `GET /api/v1/pods`）。
3. 查看审计日志/平台，确认 `sourceIPs` 被写入伪造列表，真实 IP 在末尾。
4. 在后续操作中持续更换 IP 段/伪造头，制造大量看似来自不同来源的审计事件，干扰按 IP 聚合的告警与溯源。
5. 结合其他反取证手段（如伪造 webhook 事件，见 [[cloud-k8s-audit-webhook-forged-eventlist]]）进一步增加分析成本。

## PoC

```bash
# X-Forwarded-For：大量伪造 IP（原文示例为 192.168.49.1 ~ 192.168.49.254）
curl --cert /root/.minikube/profiles/minikube/client.crt \
     --key /root/.minikube/profiles/minikube/client.key \
     -X GET https://192.168.49.2:8443/api/v1/pods -k \
     -H 'User-Agent: ' \
     -H 'X-Forwarded-For: 192.168.49.1, 192.168.49.2, 192.168.49.3, ..., 192.168.49.254'

# X-Real-IP：只能伪造一个 IP
curl --cert /root/.minikube/profiles/minikube/client.crt \
     --key /root/.minikube/profiles/minikube/client.key \
     -X GET https://192.168.49.2:8443/api/v1/pods -k \
     -H 'User-Agent: ' \
     -H 'X-Real-IP: 192.168.49.2'
```

审计日志中可见：

```json
"sourceIPs": ["192.168.49.1", "192.168.49.2", "...", "192.168.49.254", "192.168.49.1"]
```

（最后一个 `192.168.49.1` 为真实来源；X-Real-IP 场景下为 `["192.168.49.2", "192.168.49.1"]`。）

## 变体与关联

- `X-Forwarded-For` 可写 IPv6、内网/公网混合、重复 IP、超长列表（注意代理/头长度限制）；`X-Real-IP` 只能单值，噪声效果弱。
- 若中间有 Ingress/代理，代理可能覆盖或追加这些头；需要先确认实际到达 apiserver 的头内容。
- 与 webhook 伪造事件组合：[[cloud-k8s-audit-webhook-forged-eventlist]]。
- 防守侧日志溯源方法见 [[defense-forensics-web-access-log-attacker-ip-triage]]（思路类似：按 IP 频次/敏感路径筛选，但那是 Web access.log，不是 K8s audit）。

## 检测与防御

- 审计消费方：解析 `sourceIPs` 时优先取最后一个 IP（真实来源），或把前面的条目标记为“代理/不可信”；不要只用第一个 IP 或对整串做频次统计。
- apiserver/网关：在可信边界（负载均衡/Ingress）清洗并覆盖 `X-Forwarded-For`/`X-Real-IP`，只保留可信代理链；对超长/异常 IP 列表做限制和告警。
- 检测：审计事件中 `sourceIPs` 长度异常、包含大量连续/同段 IP、与 `user.username`/`userAgent`/`requestURI` 行为不一致；同一用户在短时间内出现大量“不同来源 IP”的请求。
- 平台侧：对审计日志做签名/防篡改，限制写入通道；告警关联真实来源 IP 与行为基线，避免被噪声淹没。
