---
id: defense-forensics-cloudtrail-raw-jq-useragent-ip-timeline
title: CloudTrail 原始日志 jq 溯源：User-Agent/IP 指纹定位攻击者 → 事件时间线 → IAM 提权与持久化动作还原
type: scenario
domain: defense
path: defense/forensics
technique: cloudtrail-raw-json-jq-useragent-ip-timeline-trace
tags:
- forensics
- incident-response
- cloud
- aws
- cloudtrail
- log-analysis
- jq
- user-agent
- iam
- s3
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V351
  verified_at: '2026-11-09T00:33:45+08:00'
  notes: 已对照原文与图02/05/06/07/08核对：jq -s 合并 2390 个 JSON、UA 去重发现 aws-cli Kali 指纹、sourceIP+UA 得到 54.242.59.197、按 eventTime 定位首个匿名 GetObject（_restricted/Priv-Keys/prod-EC2-readonly_accessKeys.csv）、errorMessage 42 条失败统计、PutUserPolicy(sbhyy79zky/*:*)、CreateAccessKey(forela-admin)、PutObject(README2DECRYPT.txt)、kms:Decrypt 拒绝均与原文一致。未在真实 AWS 环境复现；原文为 HTB Sherlocks 题、无组件版本/CVE，affected_versions 已 clear。
url: /docs/defense/forensics/defense-forensics-cloudtrail-raw-jq-useragent-ip-timeline/
draft: false
kb_aliases:
- CloudTrail 日志分析
- jq 分析 CloudTrail
- User-Agent 指纹溯源
- AWS 攻击者 IP 定位
- CloudTrail 事件时间线
- AWS 入侵取证
---

## 一句话结论

拿到大量原始 CloudTrail JSON 后，用 `jq` 先合并全部日志，抽取并去重 `userAgent` 找出攻击工具指纹（如带 Kali 内核版本与 `command/s3.cp` 的 aws-cli），再按 `sourceIPAddress` 过滤并按 `eventTime` 排序，即可把攻击者从 S3 读取、实例枚举、失败探测到 `PutUserPolicy`/`CreateAccessKey` 提权持久化的完整时间线还原出来。

## 原理

- **CloudTrail 记录每个 API 调用的五要素**：`userIdentity`（谁）、`sourceIPAddress`（从哪来）、`userAgent`（用什么工具/环境）、`eventName` + `requestParameters`（做了什么）、`errorMessage`（是否失败）。管理事件覆盖 IAM/EC2 等控制面动作，S3 数据事件（需单独开启）覆盖 `GetObject`/`PutObject` 等对象访问。
- **User-Agent 是最省力的攻击者指纹**：aws-cli 的 UA 由运行环境动态生成，包含 CLI 版本、Python 版本、操作系统与内核（如 `aws-cli/2.12.0 Python/3.11.4 Linux/6.3.0-kali1-cloud-amd64 source/x86_64.kali.2023 prompt/off command/s3.cp`），甚至带具体子命令；`Boto3/1.10.2 ... exec-env/AWS_Lambda_python3.8` 指向 Lambda 运行环境；`Terraform`、`S3Console`、`curl`、`python-requests` 各有特征。自动化云渗透工具（Pacu、ScoutSuite 等）在不改特征时 UA 更突兀。
- **IP + UA 联合过滤**：先用 UA 去重列表锁定可疑工具，再提取 `sourceIPAddress + userAgent` 的二元组，按 UA 关键字（如 kali）筛出攻击 IP；之后所有查询都以该 IP 为主键收窄。
- **时间线排序**：把该 IP 的事件按 `eventTime` 升序排列，第一条 `GetObject` 通常是初始访问（如匿名读取公开桶中的凭据文件），后续 `Describe*`/`List*` 是侦察，`PutUserPolicy`/`CreateAccessKey` 是提权与持久化。
- **失败也是情报**：`errorMessage` 非空的记录代表尝试但被拒的动作（如 `iam:ListGroupsForUser`、`iam:ListUserPolicies`、`iam:CreateAccessKey`、`kms:Decrypt`）；统计其数量、查看资源与动作，可推断攻击者拥有/缺失的权限与下一步意图。
- **从 requestParameters 还原命令**：`DescribeInstances` 的 `filterSet` 可还原为 `aws ec2 describe-instances --filters "Name=instance-state-name,Values=running"`；`PutUserPolicy` 的 `userName/policyName/policyDocument` 直接还原出提权命令；`CreateAccessKey` 的 `userName` 指出被加持久化密钥的账号；`PutObject` 的 `key`/ARN 给出上传文件名。
- **S3 事件名速查**：读取 `GetObject`、上传 `PutObject`、列对象 `ListObjects`、改桶策略 `PutBucketPolicy`、取策略 `GetBucketPolicy`、删除 `DeleteObject`；按事件名过滤即可定位数据面动作。

## 触发条件

- 目标 AWS 账号已启用 CloudTrail（管理事件），并在需要时启用了 S3 数据事件；日志保留期覆盖事件时间窗口。
- 已获取原始日志（题目附件、S3 日志桶导出或 SIEM 导出），字段未被裁剪（至少保留 `userIdentity`、`sourceIPAddress`、`userAgent`、`eventName`、`requestParameters`、`errorMessage`）。
- 分析人员可用 `jq`/命令行环境，能对多文件 JSON 做合并与查询。
- 攻击者未刻意伪造 UA/IP（或伪造不彻底），否则 UA 指纹与 IP 关联会失效，需要转向身份/密钥维度。

## 利用步骤

1. 合并全部日志：`jq -s '.' **/*.json > merged.json`（`-s` 把每个文件读入数组，便于统一查询）。
2. 提取并去重 UA：
   `jq '.[] | .Records | .[] | .userAgent' merged.json | sort | uniq > useragent.txt`
   人工浏览列表，标记可疑工具（如带 kali 内核版本的 aws-cli、curl、python-requests）。
3. 提取 IP+UA 并筛可疑 UA：
   `jq -r '.[] | .Records | .[] | "\(.sourceIPAddress) \(.userAgent)"' merged.json | grep -i kali`
   得到攻击者 IP。
4. 以 IP 过滤事件并按时间排序：
   `jq '.Records | .[] | select(.sourceIPAddress=="<TA_IP>")' merged.json | jq -s 'sort_by(.eventTime)' > activities.json`
5. 按 `eventName` 逐类分析：先看 `GetObject` 找初始访问对象（ARN 中常含 `keys`/`credentials` 等关键词），再看 `DescribeInstances`/`List*` 侦察、`PutUserPolicy` 提权、`CreateAccessKey` 持久化、`PutObject` 上传。
6. 统计失败动作：`jq '.[] | .errorMessage' activities.json | grep -v null | nl`，从 AccessDenied 文本反推被拒权限与资源。
7. 从 `requestParameters` 还原攻击者命令，形成「时间 → 身份/密钥 → 源 IP → 动作 → 结果」的时间线报告。

## PoC

```bash
# 合并 2390 个区域/账户目录下的 CloudTrail JSON
jq -s '.' **/*.json > merged.json

# UA 指纹
jq '.[] | .Records | .[] | .userAgent' merged.json | sort | uniq > useragent.out

# 可疑 UA → 攻击 IP
jq -r '.[] | .Records | .[] | "\(.sourceIPAddress) \(.userAgent)"' merged.json | grep -i kali

# 攻击 IP 的事件时间线
jq '.Records | .[] | select(.sourceIPAddress=="<TA_IP>")' merged.json \
  | jq -s 'sort_by(.eventTime)' > activities.json

# 初始 S3 读取
jq 'select(.eventName == "GetObject")' activities.json \
  | jq -s 'sort_by(.eventTime)' | head

# 失败动作统计
jq '.[] | .errorMessage' activities.json | grep -v null | nl

# 提权事件
jq '.[] | select(.eventName == "PutUserPolicy")' activities.json

# 持久化事件
jq '.[] | select(.eventName == "CreateAccessKey")' activities.json
```

## 变体与关联

- **集中日志查询**：若 CloudTrail 已进入数据湖/Athena/CloudTrail Lake，可改用 SQL 按 `eventname`/`useridentity_ARN`/`sourceIPAddress` 联表，效率更高（见 [[defense-forensics-cloudtrail-s3-exfil-identity-trace]] 的 S3 数据事件 + AssumeRole 追踪思路）。
- **UA 规避与反规避**：攻击者可修改 aws-cli 源码/使用自定义 UA、经代理跳板或改用容器统一环境；防御方则应把「UA 与环境/身份/行为不一致」作为关联特征，而非只依赖单一 UA 关键字。
- **身份维度分析**：当 UA 被伪造时，改按 `userIdentity.accessKeyId`/`arn` 追踪密钥使用轨迹，结合 `CreateAccessKey`、`UpdateLoginProfile`、`AssumeRole` 等事件定位失陷身份。
- **关联卡片**：[[cloud-cloud-iam-putuserpolicy-inline-admin-self-escalation]]（本类日志中常见的提权动作）、[[defense-forensics-cloudtrail-s3-exfil-identity-trace]]、[[cloud-cloud-iam-aws-access-key-leak-search-engine-takeover]]（凭据泄露来源）。

## 检测与防御

- **日志完整性**：CloudTrail 开启多区域与日志文件完整性校验，日志桶启用版本控制/对象锁/MFA delete，防止攻击者删除或篡改证据；S3 数据事件按需开启并集中归档。
- **实时检测规则**：对 `PutUserPolicy`/`AttachUserPolicy`/`CreateAccessKey` 等敏感 IAM 事件、异常 `sourceIPAddress`（境外/云厂商 IP/与身份常用地不符）、陌生 UA（aws-cli 非运维镜像、curl、python-requests）建立告警。
- **UA 基线**：统计组织内正常 UA 分布，对带 Kali/黑帽工具特征、或同一 UA 在多个账号/IP 间跳变的调用重点排查。
- **响应**：按时间线隔离失陷 AccessKey、回滚 IAM 策略、轮换密钥并检查 S3 桶策略/公开访问块（Public Access Block）；对 `GetObject` 的敏感对象评估泄露范围。
