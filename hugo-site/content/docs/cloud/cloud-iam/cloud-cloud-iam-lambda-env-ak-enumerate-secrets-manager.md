---
id: cloud-cloud-iam-lambda-env-ak-enumerate-secrets-manager
title: Lambda 环境变量泄漏长期 AWS AK：enumerate-iam 枚举权限后从 Secrets Manager 读取敏感值
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: lambda-env-ak-enumerate-iam-secretsmanager
tags:
- cloud
- aws
- iam
- lambda
- credential
- enumeration
- secrets-manager
- serverless
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V574
  verified_at: '2026-11-12T11:04:24+08:00'
  notes: 已对照12921原文216行与全部8图核对（图片8/8读取成功，无失败）：图05 Lambda参数注入返回{"error":"aaa is not defined"}（JS求值信号）、图06 sts get-caller-identity 返回 user/secret-user(AIDAX473H4JBSTLT6LMVX,账号543303393859)、图07 secretsmanager list-secrets 出现 prod/TetCTF/Flag(ap-southeast-2)、图08 get-secret-value 返回SecretString含TetCTF flag；原文另写明运行时Credential老三样无权限、环境变量中另有ENV_ACCESS_KEY/ENV_SECRET_ACCESS_KEY、enumerate-iam.py --access-key AKIAX473H4JB76WRTYPI ... 命中 secretsmanager.list_secrets()，卡片技术点、步骤与PoC命令均一致。原文未标注版本(AWS服务无版本字段)，affected_versions空缺正确；原文未给出process.env注入完整payload，卡片如实注明。dedup：首位为自身；与cloud-cloud-iam-aws-access-key-leak-search-engine-takeover(泄漏来源/通用接管)、workload-role-policy-selfcheck(list-attached-role-policies自查)、cloud-cicd-accesskey-tools-typosquat-sdk-endpoint-hijack(恶意工具回传)均非同链，库内无enumerate-iam+Secrets Manager取明文卡，保留合理。内部链接均存在；frontmatter无sources与库内规范一致。PoC未复跑。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-lambda-env-ak-enumerate-secrets-manager/
draft: false
kb_aliases:
- Lambda 环境变量 AK
- ENV_ACCESS_KEY
- enumerate-iam
- Secrets Manager 取 secret
- list-secrets get-secret-value
- 未知权限 AK 枚举
---

## 一句话结论

Lambda 函数若把用户输入当作 JavaScript 代码求值（`?vulnerable=aaa` 返回 `aaa is not defined` 即为信号），可用 `process.env` 读出函数环境变量中的长期 AWS AK/SK（如 `ENV_ACCESS_KEY`/`ENV_SECRET_ACCESS_KEY`）；即使执行角色凭据本身无权限，这对 AK 也可能属于另一个 IAM 用户，用 `enumerate-iam` 批量探测其可用 API 后发现 `secretsmanager:ListSecrets`，再 `aws secretsmanager list-secrets`/`get-secret-value` 即可直接读出明文敏感值（CTF 中即 flag）。

## 原理

- AWS Lambda 的环境变量在函数运行时即 `process.env`；若函数把请求参数拼接进 `eval`/`new Function` 等动态执行点，或错误信息回显了变量值，攻击者就能读取全部环境变量。错误 `aaa is not defined` 说明参数被当作 JS 表达式求值，直接传 `process.env` 即可回显环境变量 JSON。
- 常见的两种凭据并存：Lambda 执行角色通过运行时自动注入的临时凭据（`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`），以及开发者为方便在环境变量里手工配置的长期 AK/SK（`ENV_ACCESS_KEY`/`ENV_SECRET_ACCESS_KEY`）。两者权限相互独立，角色凭据无权限不代表环境变量里的 AK 无权限。
- AWS API 授权按 action 粒度判定。攻击者没有 `iam:GetPolicy`/`iam:ListAttachedUserPolicies` 权限时，仍可逐个调用业务/管理 API，以「成功或 AccessDenied」作为权限预言机；`enumerate-iam` 把大量只读 API（含 `secretsmanager:ListSecrets`、`s3:ListAllMyBuckets`、`ec2:Describe*` 等）批量调用并输出成功项，快速勾勒凭据权限面。
- Secrets Manager 把口令、API key、flag 等以 SecretString/SecretBinary 形式按版本存储：`ListSecrets` 只需 `secretsmanager:ListSecrets` 就能枚举 secret 名称与 ARN，`GetSecretValue` 需要 `secretsmanager:GetSecretValue` 并返回 `SecretString` 明文；两者都不要求 IAM 读权限。
- 该链的根因是「长期凭据写在函数环境变量」+「函数存在代码注入/调试回显」+「凭据权限过宽且无资源级限制」。

## 触发条件

- 目标 Lambda/Serverless 函数存在参数注入或回显缺陷，可读取 `process.env`（如参数被 eval、模板渲染或错误堆栈回显）。
- 函数环境变量中配置了长期 AK/SK（或可达的第三方凭据），且该 AK 仍有效。
- 凭据至少具备 `sts:GetCallerIdentity`（通常默认允许）与可枚举的部分 API 权限。
- 攻击者能访问 AWS API 并能运行 aws cli 与 enumerate-iam。

## 利用步骤

1. 在注入点读取环境变量，例如把 `process.env` 作为参数值传入；从响应/错误中提取 `ENV_ACCESS_KEY`、`ENV_SECRET_ACCESS_KEY`（以及区域、桶名等配置）。
2. 配置凭据并确认身份：`aws sts get-caller-identity`，得到 ARN（如 `user/secret-user`）。
3. 用 enumerate-iam 批量枚举权限：
   `python3 enumerate-iam.py --access-key <AK> --secret-key <SK> --region <region>`。
4. 在输出中查找成功项，本例命中 `secretsmanager.list_secrets()`。
5. 列举并读取 secret：
   `aws secretsmanager list-secrets`，从 `Name`/`ARN` 中筛选可疑目标；
   `aws secretsmanager get-secret-value --secret-id <ARN>` 读取 `SecretString`。
6. 若 secret 为 JSON（如 `{"Flag":"..."}`），直接解析得到敏感值；按需继续横向到其他云资源。

## PoC

```bash
# 1) 配置从 Lambda 环境变量泄漏的长期凭据
export AWS_ACCESS_KEY_ID=<ENV_ACCESS_KEY>
export AWS_SECRET_ACCESS_KEY=<ENV_SECRET_ACCESS_KEY>
export AWS_DEFAULT_REGION=<region>

# 2) 确认身份
aws sts get-caller-identity

# 3) 枚举该凭据可用的 API（只读探测，生产环境噪声大）
python3 enumerate-iam.py --access-key "$AWS_ACCESS_KEY_ID" \
  --secret-key "$AWS_SECRET_ACCESS_KEY" --region "$AWS_DEFAULT_REGION"

# 4) 命中 secretsmanager:ListSecrets 后枚举并读取 secret
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <ARN或名称>
```

```text
# 返回示例（结构）
{"ARN":"arn:aws:secretsmanager:<region>:<account>:secret:<name>",
 "Name":"prod/.../Flag",
 "SecretString":"{\"Flag\":\"...\"}",
 "VersionStages":["AWSCURRENT"]}
```

说明：原文在 Lambda 注入点读取 `process.env` 获得 `ENV_ACCESS_KEY`/`ENV_SECRET_ACCESS_KEY`，`sts get-caller-identity` 确认身份为独立 IAM 用户；enumerate-iam 命中 `secretsmanager.list_secrets()`，随后 `list-secrets` 与 `get-secret-value` 成功取到 flag。原文未给出注入参数的完整 payload 细节，本库未复跑。

## 变体与关联

- 变体：入口换成前端 JS/APK/CI 日志/代码仓库泄漏 AK，后续 enumerate-iam → Secrets Manager 步骤相同。
- 变体：权限枚举也可手工用 `aws s3 ls`、`aws ec2 describe-instances`、`aws lambda list-functions` 等 API 成功/失败推断（见关联卡）。
- 变体：Secrets Manager 之外，SSM Parameter Store（`aws ssm get-parameters --with-decryption`）、KMS 解密、S3 配置桶同样常存敏感值。
- 关联：[[cloud-cloud-iam-aws-access-key-leak-search-engine-takeover]]（AK 泄漏来源与接管）、[[cloud-cloud-iam-workload-role-policy-selfcheck]]（不依赖外部工具的权限自查）、[[cloud-metadata-ssrf-imdsv2-token-credential]]（EC2 侧凭据获取）。
- 边界：环境变量未存放长期凭据、AK 已轮换/禁用、凭据仅有 `sts:GetCallerIdentity`、或 Secrets Manager 有资源策略限制时，链不成立。

## 检测与防御

- 检测：CloudTrail 中出现 `GetCallerIdentity` 后紧跟大量只读 API（`ListSecrets`、`GetSecretValue`、`Describe*`）的异常序列；来自非预期 IP/User-Agent 的 `ListSecrets`/`GetSecretValue`；GuardDuty 的 `UnauthorizedAccess:IAMUser/*` 与凭据异常使用告警。
- 防御：Lambda 不存放长期 AK，统一使用执行角色 + 最小权限；禁止把用户输入传入 `eval`/动态代码执行；生产关闭详细错误回显；Secrets Manager 用资源策略限制 `GetSecretValue` 的调用者；定期轮换并扫描环境变量/代码中的密钥。
- 加固：对敏感 API 做审批与告警；给 IAM 用户加 MFA/源 IP 条件；使用 permissions boundary 限制凭据权限面。
