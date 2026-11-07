---
title: 云 IAM
weight: 1
---

# 云 IAM

## 这层是什么

权限提升、角色链、跨账号与策略缺陷。

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
| [AWS IAM 危险权限组合提权：CreateAccessKey、CreateLoginProfile、AttachUserPolicy 与 PassRole](cloud-cloud-iam-aws-dangerous-permission-privesc/) | verified | medium | 2026-11-05 |
| [Entra ID 动态组 Guest 自动入组：User.Invite.All 邀请外部账号继承组上的应用角色](cloud-cloud-iam-entra-dynamic-group-guest-invite-app-role/) | verified | high | 2026-11-06 |
| [Entra ID 管理员同意链：common 端点枚举租户 ID + Graph 查 redirect_uri + adminconsent 获取应用权限](cloud-cloud-iam-entra-tenant-id-redirect-uri-adminconsent/) | verified | high | 2026-11-06 |
| [S3 桶策略只校验 aws:SourceVpce 时，用泄露凭证预签名并经 VPC 内 SSRF 读取私有对象](cloud-s3-presigned-url-vpce-bypass/) | verified | high | 2026-11-05 |
| [STS Policy 注入黑名单绕过：字符串双写与 JSON Unicode 转义恢复被过滤的 Action/通配符](cloud-cloud-iam-sts-policy-injection-filter-bypass-unicode/) | verified | medium | 2026-11-05 |
| [STS Policy 注入：可控 Object Key 进入 AssumeRole 会话 Policy 导致临时凭据越权](cloud-cloud-iam-sts-policy-injection-object-key/) | verified | high | 2026-11-05 |
| [云工作负载凭据的 IAM 策略自助枚举与危险权限判定](cloud-cloud-iam-workload-role-policy-selfcheck/) | verified | high | 2026-11-05 |
| [搜索引擎批量发现泄露的 AWS AK/SK 并接管云权限](cloud-cloud-iam-aws-access-key-leak-search-engine-takeover/) | verified | high | 2026-11-05 |
| [未授权接口泄露阿里云 OSS AK/SK：oss2 验证、Bucket 枚举与生产报表 PII 取证](cloud-cloud-iam-oss-ak-sk-leak-bucket-pii-proof/) | verified | high | 2026-11-05 |
| [腾讯云临时凭据权限枚举与 CVM 强制重置 root 密码](cloud-cloud-iam-tencent-temp-credential-cvm-password-reset/) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
