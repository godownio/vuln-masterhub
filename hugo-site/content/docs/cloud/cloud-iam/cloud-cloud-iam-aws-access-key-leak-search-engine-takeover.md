---
id: cloud-cloud-iam-aws-access-key-leak-search-engine-takeover
title: 搜索引擎批量发现泄露的 AWS AK/SK 并接管云权限
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: aws-access-key-leak-recon-takeover
tags:
- cloud
- aws
- iam
- credential
- recon
- search-engine
- quake
- leak
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:14:57+08:00'
  notes: 已通读原文并逐张核对61张图：图32 Quake body:"AWS_SECRET_ACCESS_KEY" and body:"phpinfo" 命中2,293条/977 IP，图33 宽泛查询39,059独立IP，图04/05/06/23/24/28 验证 aws configure、get-caller-identity、list-attached-user-policies、User-Agent 泄露 Kali 特征，均与卡内步骤一致。原文为研究记录，未对具体泄露目标实操；无产品版本/CVE。frontmatter 无 sources/source_url；PoC 未在本机复跑。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-aws-access-key-leak-search-engine-takeover/
draft: false
kb_aliases:
- AWS AK SK 泄露
- AWS_SECRET_ACCESS_KEY 测绘
- phpinfo 泄露 AWS 密钥
- 云凭据泄露接管
- 空间测绘找 AK
---

## 一句话结论

AWS 访问密钥（Access Key ID + Secret Access Key）常因前端 JS、源码仓库、CI 日志、二进制包、调试页（如 phpinfo）等泄露；用空间测绘引擎搜索 `AWS_SECRET_ACCESS_KEY` 等特征可批量定位，拿到有效密钥后即可用 AWS CLI/SDK 以该身份调用云 API，直接接管对应权限。

## 原理

- AWS CLI/SDK 的每次请求都用 AK/SK 计算签名（SigV4）并放入 Authorization 头；只要拿到这对长期凭据，攻击者无需进入目标网络，就能从公网直接调用 AWS API，等同于持有该 IAM 用户的身份。
- 密钥泄露面包括：前端 JS/SPA 配置、GitHub/GitLab 等代码托管、Web 与云交互功能的异常报错、Jenkins 等 CI/CD 日志、本机 `~/.aws/credentials`、桌面/移动安装包与小程序、phpinfo 等调试页面。
- 空间测绘引擎会索引页面正文，phpinfo 会输出环境变量；若应用把 AWS 密钥注入环境变量并暴露 phpinfo，`body:"AWS_SECRET_ACCESS_KEY"` 就能命中大量实例。
- 泄露的密钥往往直接是管理员权限（原文称约一半），即使不是，也能通过 IAM 权限配置缺陷继续提权；云 API 调用属于“合法权限”，不像传统渗透需要突破网络边界，因此利用链极短。
- 云侧审计（CloudTrail）有数分钟延迟，攻击者若自动化程度高，可能在防守方响应前完成凭据使用与资源操作；但所有 API 调用仍会留痕。

## 触发条件

- 目标页面的响应正文或静态资源中包含明文 `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`，且搜索引擎已索引。
- 密钥仍有效、未绑定 MFA/源 IP 限制/过期时间，且所属 IAM 用户有可用权限。
- 攻击者能从公网访问 AWS API（通常可以）。
- 目标不使用权限边界/SCP 严格限制，或限制仍允许关键动作。

## 利用步骤

1. 用测绘语法定位泄露页面，例如 phpinfo：`body:"AWS_SECRET_ACCESS_KEY" and body:"phpinfo"`；扩大范围可用 `body:"AWS_SECRET_ACCESS_KEY"`。
2. 打开命中页面，提取 `AWS_ACCESS_KEY_ID` 与 `AWS_SECRET_ACCESS_KEY`（phpinfo 的 Environment 区块常见）。
3. 本地配置：`aws configure` 填入 AK/SK 与区域（区域需与服务匹配）。
4. 验证身份：`aws sts get-caller-identity` 获取 Account、UserId、Arn。
5. 枚举权限：`aws iam list-attached-user-policies --user-name <user>`、`aws s3 ls`、`aws ec2 describe-instances` 等，判断可访问资源。
6. 按权限利用：读取/下载 S3 对象、创建实例、修改 IAM、调用 Lambda 等；权限不足时按 IAM 提权原语继续。
7. 注意清理与最小化操作，避免触发 GuardDuty/CloudTrail 告警。

## PoC

泄露检索（Quake/Fofa 等语法，原文示例）：

```text
body:"AWS_SECRET_ACCESS_KEY" and body:"phpinfo"
body:"AWS_SECRET_ACCESS_KEY"
```

拿到密钥后的验证：

```bash
aws configure   # 填入泄露的 AK/SK 与区域
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <user>
aws s3 ls
```

原文未给出针对具体目标的完整利用链；上述为密钥验证与权限侦察的最小步骤。

## 变体与关联

- 变体：GitHub/GitLab 代码搜索、前端 JS 中的硬编码、Jenkins 构建日志、Docker 镜像层、APK/IPA/小程序包、`~/.aws/credentials` 文件。
- 变体：泄露的是临时角色凭据（含 SessionToken），用法相同但会过期，需尽快使用。
- 关联：[[cloud-cloud-iam-workload-role-policy-selfcheck]]（拿到凭据后的权限枚举与价值判定）。
- 关联：[[cloud-cloud-iam-aws-dangerous-permission-privesc]]（权限不足时的 IAM 提权原语）。
- 边界：密钥已轮换/禁用、绑定 MFA 或源 IP 条件、仅有极小权限且无提权路径时，接管失败。

## 检测与防御

- 检测：CloudTrail 中出现来自异常 IP/User-Agent 的 `GetCallerIdentity`、`ListAttachedUserPolicies`、`ListBuckets` 等调用；GuardDuty 的 `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`、`PenTest:IAMUser/KaliLinux` 等告警。
- 防御：禁止把长期 AK/SK 写入代码、镜像、前端或环境变量；使用 IAM Role/临时凭据与最小权限；对密钥做 secret scanning 与定期轮换。
- 加固：给 IAM 用户加 MFA 与源 IP 条件；启用 SCP/permissions boundary；关闭生产环境 phpinfo 等调试页；监控公开仓库与测绘空间中的密钥特征。
