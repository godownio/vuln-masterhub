---
id: cloud-obs-bucket-policy-sourceip-xff-spoof-bypass
title: 华为云 OBS 桶策略 SourceIp 限制绕过：伪造 X-Forwarded-For 内网地址即可列对象
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: obs-bucket-policy-sourceip-xff-spoof-bypass
tags:
- cloud
- object-storage
- obs
- huawei-cloud
- bucket-policy
- x-forwarded-for
- access-control
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:09:19+08:00'
  notes: '对照原文 img46-50：桶策略 nginx代理 动作 Get*,List* + Condition IpAddress SourceIp 172.16.0.0/24（img46）；直接访问 seeeyon-center-public 桶根 403 AccessDenied（img47）；Burp 加 X-Forwarded-For: 172.16.0.1 后 200 返回 ListBucketResult，列出 assets_records/*、static_source.map、jar 等敏感对象（img48）；修复移除 List* 后策略仅余 Get*（img49），再带 XFF 请求仍 403（img50）。卡片 PoC 主机名、网段、修复验证步骤均与截图一致。原文未标版本，affected_versions 为空正确。与 k8s 审计日志 XFF、Web 应用 XFF 白名单、S3 VPC Endpoint 条件绕过等既有卡场景不同，dedup 报告 new，保留。'
url: /docs/cloud/cloud-iam/cloud-obs-bucket-policy-sourceip-xff-spoof-bypass/
draft: false
kb_aliases:
- OBS 桶策略 IP 限制绕过
- X-Forwarded-For 伪造
- SourceIp 条件绕过
- 华为云 OBS XFF
- 桶策略请求者地址伪造
---

## 一句话结论

当华为云 OBS 桶策略用 `IpAddress: SourceIp` 条件把 `Get*`/`List*` 限制在内网网段（如 `172.16.0.0/24`）时，直接访问桶域名会返回 `AccessDenied`；但 OBS 的“请求者地址”判定信任客户端 `X-Forwarded-For` 头，攻击者在请求中加 `X-Forwarded-For: 172.16.0.1` 即可让策略条件成立，匿名列举桶对象成功。修复方式是移除策略中的 `List*`（或改用不可伪造的来源判定）。

## 原理

- **策略条件**：OBS 桶策略支持 `Condition`，常见写法是 `"IpAddress": {"SourceIp": ["172.16.0.0/24"]}`，只允许来自内网网段的请求执行 `Get*`/`List*`；策略本意是“只在内网可读”。
- **请求者地址来源**：部分云服务/网关在计算 SourceIp 时会参考 `X-Forwarded-For`（代理链真实客户端 IP 的标准头），而该头完全由客户端控制；OBS 对匿名请求未剥离/校验 XFF，导致伪造的内网 IP 被当作请求者地址。
- **为什么成立**：策略评估发生在服务端，但输入（SourceIp）来自可伪造的 HTTP 头；策略逻辑本身没错，错在条件的取值不可信。直接请求 403，加 `X-Forwarded-For: 172.16.0.1` 后 200，说明条件被伪造绕过。
- **危害**：本应仅内网可见的对象（源码 map、构建产物 jar、日志、配置等）被公网匿名枚举/下载；文中真实环境即通过该方式列出了包含 `assets_records`、`source map` 的对象。
- **边界**：若网关已剥离客户端 XFF 并重写为真实来源，或策略改用不受 XFF 影响的条件（如 VPC 端点/账号），伪造无效；不同云厂商/产品对 XFF 的处理不同。

## 触发条件

- 桶策略对匿名或低权限主体授予 `Get*`/`List*`，并附加 `SourceIp` 条件限制网段。
- 实际来源不在该网段（公网攻击者）。
- OBS 对 `X-Forwarded-For` 未做可信代理校验，将其作为请求者地址。
- 桶未启用阻止公共访问等覆盖策略。

## 利用步骤

1. 直接请求桶根 `GET https://<bucket>.obs.<region>.myhuaweicloud.com/`，得到 403 `AccessDenied`。
2. 检查/猜测桶策略条件：常见为内网网段 `172.16.0.0/24`、`10.0.0.0/8`、`192.168.0.0/16`；可查看公开策略或从业务架构推断。
3. 在请求中加入 `X-Forwarded-For: <内网IP>`（如 `172.16.0.1`），重新发送。
4. 若返回 200 `ListBucketResult`，说明绕过成功；解析 `<Key>` 批量下载敏感对象。
5. 修复验证：管理员移除策略中的 `List*` 后，再次带 XFF 请求应返回 403。

## PoC

```http
GET / HTTP/1.1
Host: seeeyon-center-public.obs.cn-north-4.myhuaweicloud.com
```

```text
# 预期：403 Forbidden <Code>AccessDenied</Code>
```

```http
GET / HTTP/1.1
Host: seeeyon-center-public.obs.cn-north-4.myhuaweicloud.com
X-Forwarded-For: 172.16.0.1
```

```text
# 预期：200 OK <ListBucketResult>，可列出 bucket 内对象（源码 map、jar、日志等）
```

## 变体与关联

- 变体：策略条件用 `NotIpAddress` 做黑名单时，伪造 XFF 为黑名单外地址同样可绕过。
- 变体：`Referer`/`User-Agent` 等条件同理依赖客户端头，见 [[cloud-obs-hotlink-referer-whitelist-bypass]]。
- 关联：[[cloud-obs-bucket-policy-acl-conflict-anonymous-list]]（策略/ACL Allow 并集）、[[cloud-s3-presigned-url-vpce-bypass]]（同类“网络来源条件”绕过）、[[cloud-object-storage-bucket-acl-misconfig]]（公共读/列举）。
- 边界：可信代理剥离 XFF 或使用 VPC 端点/账号条件时失效。

## 检测与防御

- 检测：OBS 访问日志中同一对象请求出现 403 后带 XFF 的 200；请求头 `X-Forwarded-For` 出现在本不该有代理链的直连请求中；策略中 `SourceIp` 条件与匿名 Allow 组合。
- 防御：不要用 `SourceIp` + 客户端头作为唯一访问控制；敏感桶保持私有，用短期签名 URL/STS 鉴权；代理层剥离并重写 XFF；对匿名策略移除 `Get*`/`List*`，或改用 VPC 端点/账号条件。
