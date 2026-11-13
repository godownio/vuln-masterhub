---
id: cloud-cicd-sast-config-soft-fail-bypass-checkov
title: SAST 配置投毒：提交 .checkov.yml soft-fail 与无效检查项绕过 IaC 扫描门禁
type: scenario
domain: cloud
path: cloud/ci-cd
technique: sast-config-soft-fail-bypass
tags:
- cicd
- sast
- checkov
- iac
- terraform
- policy-bypass
- security-gate
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:15+08:00'
  notes: 已对照原文核对 .checkov.yml 字段（soft-fail/check）与 main.tf ACL=public-read；checkov 配置语义为基于扫描器文档的机制说明，原文未展开。
url: /docs/cloud/ci-cd/cloud-cicd-sast-config-soft-fail-bypass-checkov/
draft: false
kb_aliases:
- checkov soft-fail
- SAST 配置投毒
- 扫描门禁绕过
- .checkov.yml
- IaC 扫描绕过
- CI 安全检查绕过
---

## 一句话结论

当 CI 使用 checkov 等 SAST/IaC 扫描器并把结果作为合并门禁时，攻击者可在仓库提交 `.checkov.yml`，设置 `soft-fail: true` 并只启用一个不存在的检查项，使扫描"无失败"直接通过；随后把 Terraform 中的 S3 ACL 改为 `public-read` 等不安全配置也能过门禁被合并/部署。

## 原理

- **扫描器读取仓库内配置**：checkov 默认在当前仓库查找 `.checkov.yml`，其中 `soft-fail: true` 表示即使发现失败项也返回成功退出码；`check: [某个不存在的ID]` 只运行指定检查（不存在则没有有效检查）。
- **门禁只看结果**：CI 通常只看 checkov 退出码/报告摘要；配置被投毒后，扫描器不再对真实问题报错，门禁失效。
- **攻击者控制仓库即可控制扫描行为**：配置文件与业务代码在同一 PR 中提交，二者一起被合并；安全团队若不审查扫描配置，就无法发现问题。
- **最终危害**：不安全 IaC（公开桶、开放安全组、明文密钥等）被合入并部署，形成真实云配置风险，同时绕过组织的合规门禁。

## 触发条件

- CI 在 PR 上运行 checkov（或同类 SAST/IaC 扫描器），且读取仓库内配置文件。
- 扫描结果作为合并/部署的必要条件，但未固定扫描器配置、未审查配置变更。
- 攻击者可提交配置与代码变更。

## 利用步骤

1. 在仓库根目录添加 `.checkov.yml`：
   ```yaml
   soft-fail: true
   check:
     - THIS_NOT_THE_CHECK_YOUR_ARE_LOOKING_FOR
   ```
2. 修改 `main.tf` 中 S3 bucket 的 ACL：
   ```hcl
   resource "aws_s3_bucket" "dodo" {
      bucket = var.bucket_name
      acl    = "public-read"
   ```
3. 提交并推送/提 PR，触发 CI；checkov 因配置不报失败，门禁通过，变更被合并/部署。

## PoC

```yaml
soft-fail: true
check:
  - THIS_NOT_THE_CHECK_YOUR_ARE_LOOKING_FOR
```

```hcl
resource "aws_s3_bucket" "dodo" {
   bucket        = var.bucket_name
   acl           = "public-read"
```

原文提交后在 build 中绕过检测并取得 flag；真实环境中等价于公开读的 S3 bucket 被部署。

## 变体与关联

- **扫描器变体**：`.semgrepignore`、`.gitleaks.toml`（allowlist）、`.trivyignore`、Sonar/ESLint 配置、SAST baseline 文件、severity 阈值调整；思路都是"让扫描器看不到/不报"。
- **关联**：[[cloud-cicd-jenkins-indirect-ppe-build-script-makefile]]（CI 执行面）、[[cloud-object-storage-bucket-acl-misconfig]]（最终的不安全配置）。
- **组合**：配置投毒 + 修改 IaC，把"扫描通过"与"实际风险"解耦。

## 检测与防御

- **固定扫描配置**：扫描器配置由 CI 侧统一提供（命令行参数/集中配置），禁止仓库内配置覆盖；忽略规则变更需安全团队审批。
- **双重扫描**：CI 内扫描 + 独立平台/基线扫描；对比两次结果，检测配置投毒导致的差异。
- **策略即代码**：用 OPA/Conftest 等独立校验 IaC 关键属性（如 bucket ACL、安全组），不依赖单一扫描器配置。
- **审查与保护**：CODEOWNERS 保护 `.checkov.yml` 等安全配置文件；保护分支强制审批；对 `soft-fail`/跳过规则告警。
- **结果校验**：CI 解析扫描 JSON 报告，强制要求关键检查项实际运行过，而不只看退出码。
