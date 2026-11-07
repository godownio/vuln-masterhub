---
id: cloud-cloud-iam-aws-dangerous-permission-privesc
title: AWS IAM 危险权限组合提权：CreateAccessKey、CreateLoginProfile、AttachUserPolicy 与 PassRole
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: aws-iam-dangerous-permission-privesc
tags:
- cloud
- aws
- iam
- privilege-escalation
- policy
- passrole
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:14:59+08:00'
  notes: 已通读全文并核对61张图：原文仅列举 iam:CreateAccessKey/CreateLoginProfile/AttachUserPolicy/PassRole+服务 四类错误 IAM 策略提权原语，未给命令；卡内四类原语与原文一致，AWS CLI 命令已明确标注为按标准动作补全的示意。原文无具体账号/版本/CVE，未做实操。frontmatter 无 sources/source_url；PoC 未在本机执行。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-aws-dangerous-permission-privesc/
draft: false
kb_aliases:
- AWS IAM 权限提升
- iam:CreateAccessKey 提权
- iam:CreateLoginProfile 提权
- iam:AttachUserPolicy 提权
- iam:PassRole 提权
- AWS 策略配置错误提权
---

## 一句话结论

在 AWS 中，若当前 IAM 身份被授予了本不该有的 `iam:CreateAccessKey`、`iam:CreateLoginProfile`、`iam:AttachUserPolicy`，或 `iam:PassRole` 配合某个可执行服务，攻击者即可直接创建管理员密钥、给管理员设密码、给自己附加管理员策略，或把高权限角色传给服务后执行，从而完成提权。

## 原理

- AWS IAM 权限由策略显式授予；很多策略为了“方便”授予了过宽的 IAM 动作，导致低权限身份可以操作其他身份或角色。
- 四个常见原语：
  - `iam:CreateAccessKey`：为任意（包括管理员）IAM 用户创建新的长期访问密钥；攻击者拿到后即可用该用户权限调用 API。
  - `iam:CreateLoginProfile`：为没有控制台密码的用户创建登录配置，设置攻击者已知的密码，随后登录控制台；若目标已有 profile，可用 `UpdateLoginProfile`。
  - `iam:AttachUserPolicy`：把 `AdministratorAccess` 等策略直接附加到自己或同权限边界内的用户上，立即获得管理员权限。
  - `iam:PassRole` + 特定服务执行权限：把高权限角色传递给 Lambda、EC2、Glue、CloudFormation 等服务，再由这些服务以该角色身份执行代码/资源操作，等于借用角色权限。
- 这些动作本身是合法 API 调用，不需要漏洞；是否成功取决于策略、permissions boundary、SCP 以及目标资源是否存在。
- 原文强调：如果没有 AWS 0day，IAM 提权基本只有“错误的 IAM 权限策略配置”这一条路。

## 触发条件

- 当前凭据具备上述危险动作之一，且未被 permissions boundary/SCP 拦截。
- 存在可操作的目标用户/角色（如管理员用户、可传递的高权限角色）。
- 对于 `PassRole` 路线，还需具备创建/更新相应服务资源的权限（如 `lambda:CreateFunction`、`ec2:RunInstances`）。
- 目标账号未对这些敏感 IAM 动作做审批或强告警。

## 利用步骤

1. 权限侦察：`aws iam list-attached-user-policies`、`aws iam list-user-policies`、`aws iam get-user`，或按 API 成功/失败推断可用动作。
2. 选择路线：
   - `CreateAccessKey`：为管理员用户创建密钥并切换。
   - `CreateLoginProfile`：为管理员用户设置控制台密码并登录。
   - `AttachUserPolicy`：给自己附加 `AdministratorAccess`。
   - `PassRole`：创建 Lambda/EC2 等资源，绑定高权限角色并执行命令。
3. 验证新权限：`aws sts get-caller-identity`、`aws iam list-users`。
4. 清理或维持访问（按授权范围）。

## PoC

原文未给出可直接执行的命令，以下为对应 AWS CLI 动作的最小示意：

```bash
# 1) 为管理员用户创建访问密钥
aws iam create-access-key --user-name admin

# 2) 为管理员用户创建控制台登录配置
aws iam create-login-profile --user-name admin --password 'P@ssw0rd!'

# 3) 给自己附加管理员策略
aws iam attach-user-policy --user-name <self> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 4a) PassRole + Lambda：创建函数并传入高权限角色
aws lambda create-function --function-name x --runtime python3.12 \
  --role arn:aws:iam::<acct>:role/AdminRole --handler x.h --zip-file fileb://x.zip

# 4b) PassRole + EC2：启动实例并绑定高权限实例角色
aws ec2 run-instances --image-id <ami> --instance-type t3.micro \
  --iam-instance-profile Name=AdminProfile
```

实际使用时需按目标账号、区域与权限边界调整；任一动作被拒绝即说明策略或边界阻止。

## 变体与关联

- 变体：`iam:UpdateLoginProfile`、`iam:PutUserPolicy`、`iam:CreatePolicyVersion`、`iam:SetDefaultPolicyVersion` 等也可用于提权。
- 变体：`iam:PassRole` 可与 CloudFormation、Glue、SageMaker、CodeBuild 等服务组合，具体取决于可执行权限。
- 关联：[[cloud-cloud-iam-workload-role-policy-selfcheck]]（先枚举策略判断是否具备这些动作）。
- 关联：[[cloud-cloud-iam-aws-access-key-leak-search-engine-takeover]]（拿到初始低权限凭据后进入本提权流程）。
- 边界：permissions boundary、SCP、服务控制策略或目标用户已有登录配置/密钥上限时，对应原语可能失败。

## 检测与防御

- 检测：CloudTrail 监控 `CreateAccessKey`、`CreateLoginProfile`、`AttachUserPolicy`、`PutUserPolicy`、`PassRole` 等敏感事件，尤其是对管理员用户/角色的操作和非预期来源。
- 防御：IAM 最小权限，禁止给普通身份授予 `iam:*`、`iam:PassRole` 等高危动作；使用 permissions boundary 与 SCP。
- 加固：开启 MFA、限制访问密钥数量与轮换；对 `PassRole` 加 `iam:PassedToService` 条件；对敏感 IAM 变更做人工审批与实时告警。
