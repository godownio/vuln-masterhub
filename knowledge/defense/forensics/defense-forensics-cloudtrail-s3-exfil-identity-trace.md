---
id: defense-forensics-cloudtrail-s3-exfil-identity-trace
title: 用 S3 数据事件与 CloudTrail 追踪外泄角色、AssumeRole 与横向主机
type: scenario
domain: defense
path: defense/forensics
technique: cloudtrail-s3-exfil-identity-trace
aliases:
- CloudTrail 溯源
- S3 数据事件外泄追踪
- AssumeRole 身份追踪
- UpdateFunctionCode 溯源
- 云上攻击链时间线
tags:
- forensics
- incident-response
- cloud
- aws
- cloudtrail
- s3
- assume-role
- iam
- log-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:38:58+08:00'
  notes: 已对照原文与14张图核对：s3_data_events GetObject 锁定 S3Reader/drinks、UserAgent 为 Boto3；cloudtrail AssumeRole 定位 Moe.Jito；Update% 查到 lambdaWorker/i-0a44002eec2f16c25；主机 auth.log 见 postgresql-user。查询与字段均与卡片一致。未验证点：未在真实AWS账户执行查询；字段名依赖原文CTF表结构。无版本区间，未设versions。
---

## 一句话结论

当 S3 数据事件与 CloudTrail 被集中收集时，可按“数据面 GetObject → 角色会话 ARN → AssumeRole 调用者 → 控制面 Update* 事件 → 实例角色 → 主机日志”的顺序逐跳查询，还原从初始入口到数据外泄的完整云上攻击链。

## 原理

- S3 数据事件表记录每次对象访问的 `EventTime`、`EventName`、`UserAgent`、来源 `IP`、`useridentity_ARN`、`requestParameters`、`path` 等字段。`GetObject` 事件能直接指出“谁在何时读了哪个对象”。
- `useridentity_ARN` 若是 `arn:aws:sts::<account>:assumed-role/<Role>/<SessionName>`，说明调用者不是该角色本身，而是通过 STS `AssumeRole` 临时扮演。下一跳应去 CloudTrail 查 `AssumeRole`，其 `userIdentity_ARN` 是原始调用者，`requestParameters` 包含目标 `roleArn` 与 `roleSessionName`。
- CloudTrail 管理事件记录控制面 API。把 `eventName` 过滤为 `Update%`（如 `UpdateFunctionCode`、`UpdateFunctionConfiguration`）可快速发现攻击者是否修改 Lambda/配置；事件中的 `userIdentity_ARN` 常带实例 ID（如 `assumed-role/lambdaWorker/i-...`），指向被攻陷的 EC2。
- 主机层日志（`/var/log/auth.log`）可补上最后一段：服务账户（如 `postgresql-user`）通常 `nologin`，若出现 `Accepted publickey` 的 SSH 登录，往往是被用作横向/入口的异常行为。攻击者可能用挂载覆盖隐藏日志，需先解除覆盖（见关联卡片）。
- 这条链的价值在于“每跳都有独立日志字段可验证”：数据面看对象访问，身份面看 AssumeRole，控制面看资源修改，主机面看登录；不依赖攻击者自述或单一告警。

## 触发条件

- 已启用 S3 数据事件（或 S3 server access logs）与 CloudTrail 管理事件，并集中到可查询的日志库/数据湖。
- 日志保留期覆盖事件时间窗口，字段未被裁剪（至少保留 `useridentity_ARN`、`requestParameters`、`UserAgent`、`IP`）。
- 应急人员有日志查询权限，且能获取相关主机/实例的 root 或取证镜像。
- 主机日志未被彻底删除；若被挂载覆盖，可先恢复原视图。

## 利用步骤

1. 先看表结构，确认字段：
   `SELECT * FROM s3_data_events LIMIT 5;`
2. 按业务关键词（如秘密文件/配方名）查 `GetObject`，列出角色：
   `SELECT useridentity_ARN FROM s3_data_events WHERE (path LIKE '%<keyword>%' OR requestParameters LIKE '%<keyword>%') AND eventname='GetObject';`
3. 对比 `UserAgent` 与来源 IP，排除正常浏览器/CLI，锁定异常客户端（如 `Boto3`）。
4. 用角色名与 session 名查 `AssumeRole`，找原始调用者：
   `SELECT useridentity_ARN,eventName,requestParameters FROM cloudtrail WHERE eventName='AssumeRole' AND requestParameters LIKE '%<role>%' AND requestParameters LIKE '%<session>%';`
5. 查控制面修改事件，定位被攻陷实例：
   `SELECT eventTime,eventName,useridentity_ARN FROM cloudtrail WHERE eventname LIKE 'Update%';`
   关注 `UpdateFunctionCode`/`UpdateFunctionConfiguration` 等及其 `assumed-role/.../i-...`。
6. 进入对应主机，检查 `/var/log` 是否被挂载覆盖；恢复后查 `auth.log` 的 SSH 记录，寻找异常服务账户登录与来源 IP。
7. 按时间线串起“初始入口 → 凭据/角色 → 数据外泄 → 控制面修改 → 横向”，标注每跳证据来源。

## PoC

```sql
-- 1. 数据面：谁读取了敏感对象
SELECT useridentity_ARN, UserAgent, IP, EventTime, path
FROM s3_data_events
WHERE eventname = 'GetObject'
  AND (path LIKE '%secret%' OR requestParameters LIKE '%secret%');

-- 2. 身份面：谁扮演了该角色
SELECT useridentity_ARN, eventName, requestParameters, eventTime
FROM cloudtrail
WHERE eventName = 'AssumeRole'
  AND requestParameters LIKE '%S3Reader%'
  AND requestParameters LIKE '%<session-name>%';

-- 3. 控制面：哪些资源被修改
SELECT eventTime, eventName, useridentity_ARN
FROM cloudtrail
WHERE eventname LIKE 'Update%';
```

```bash
# 4. 主机面：恢复被覆盖的日志并查 SSH
findmnt /var/log
umount /var/log 2>/dev/null
grep sshd /var/log/auth.log | grep -E 'Accepted|session opened'
```

## 变体与关联

- 变体：数据源换成 CloudTrail Lake、Athena、Splunk/Elastic；字段名可能不同，但“数据面→身份面→控制面→主机面”的枢纽一致。
- 变体：若没有 S3 数据事件，可用 S3 server access logs、VPC Flow Logs、GuardDuty 发现外泄；若没有 CloudTrail，可用 IAM Access Analyzer/服务日志补位。
- 变体：攻击者用 `AssumeRole` 链式跳板（角色 A 扮演角色 B）时，需沿每条 `AssumeRole` 的 `userIdentity_ARN` 继续回溯。
- 关联：[[defense-forensics-overlayfs-mount-shadowing-log-hide]]（主机日志被挂载覆盖时的恢复）；[[defense-incident-response-same-entry-multi-stage-infra-rotation]]（多阶段基础设施切换的关联分析）；[[cloud-k8s-k8s-rbac-secret-read]]（云凭据读取后的横向）。
- 边界：日志未开启、保留期不足、字段被裁剪或攻击者已删除/覆盖日志时，链条会断；需要结合主机取证、网络流量和云厂商审计补证。案例是 CTF 靶场，真实环境还需处理时区、日志延迟与多账号。

## 检测与防御

- 检测：对敏感桶的 `GetObject` 建立基线，告警异常 `UserAgent`/来源 IP/访问量；监控 `AssumeRole` 的目标角色与调用者组合；对 `UpdateFunctionCode`、`UpdateFunctionConfiguration`、`PutBucketPolicy` 等控制面高危 API 告警；监控服务账户的 SSH 登录。
- 修复/加固：开启 S3 数据事件与 CloudTrail 全区域日志，集中到不可篡改的存储；对日志设置保留期与完整性校验；最小化角色权限，限制 `AssumeRole` 的目标。
- 缓解：敏感数据加密与访问审批；对服务账户禁用交互式登录；定期演练从数据面到主机面的溯源查询。
