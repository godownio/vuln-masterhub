---
id: cloud-cloud-iam-tencent-temp-credential-cvm-password-reset
title: 腾讯云临时凭据权限枚举与 CVM 强制重置 root 密码
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: tencent-cloud-temp-credential-cvm-reset-password
aliases:
- 腾讯云临时凭据利用
- CVM ResetInstancesPassword
- ForceStop 重置密码
- 云 AK/SK 权限枚举
- STS 临时凭据提权
- 云主机接管
tags:
- cloud
- tencent-cloud
- iam
- sts
- temporary-credentials
- cvm
- privilege-escalation
- cos
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:46:38+08:00'
  notes: 已对照原文与图01核对：解密脚本输出 AK/SK/Token（图01 [18]-[20]），凭据用于 tccli sts GetCallerIdentity 与 cvm DescribeInstances；StopInstances 返回 UnauthorizedOperation 后改用 Python SDK ResetInstancesPassword + ForceStop:true；原文未展示重置成功响应/SSH 登录，且 PutBucketACL 因环境到期未完成，卡已标 confidence=medium 并注明边界。未使用文中真实凭据、未调用云 API。原文无受影响版本概念；frontmatter 无 sources/source_url。
---

## 一句话结论

拿到腾讯云临时凭据（SecretId/SecretKey/Token）后，先用 STS/CVM API 枚举账号与实例，寻找“未设置密码、未绑定密钥、默认登录用户 root”的 CVM；即使没有 `cvm:StopInstances` 权限，也可调用 `ResetInstancesPassword` 并带 `ForceStop: true` 强制停止并重置 root 密码，进而接管主机；后续还可结合该主机的公网 IP 满足 COS 策略的 IP 条件。

## 原理

- 腾讯云 API 使用 AK/SK + 临时 Token 签名。临时凭据通常来自 STS（角色扮演、联邦用户、实例角色、CI/CD 泄露等），其权限由绑定的 CAM 策略决定。
- `tccli sts GetCallerIdentity` 可确认凭据对应的账号、用户/角色与身份类型；`tccli cvm DescribeInstances` 可列出权限范围内的实例。
- 关键点在实例元数据：`LoginSettings.Password = null` 且 `KeyIds = null` 表示实例创建时没有设置密码、也没有绑定 SSH 密钥，`DefaultLoginUser = root`；这类实例一旦被重置密码，攻击者可直接以 root 登录。
- `ResetInstancesPassword` 是 CVM 的密码重置 API，支持 `ForceStop: true`：在重置前强制停止实例。因此攻击者不一定需要单独的 `cvm:StopInstances` 权限——只要 CAM 策略允许 `cvm:ResetInstancesPassword`，就可能完成“停止 + 重置”。
- 权限枚举的价值在于找到“最小可用权限集”：`DescribeInstances` 用于发现目标，`ResetInstancesPassword` 用于接管；`StopInstances` 被拒绝并不代表无法重置。
- 云上横向：接管一台位于特定 IP 的 CVM 后，可利用其公网/内网 IP 满足 COS Bucket Policy 的 `ip_not_equal`/IP 白名单条件，再调用 `PutBucketACL` 等 API，形成“先拿主机、再用主机 IP 过策略”的链。
- 临时凭据通常有时效；需要在有效期内完成枚举与利用。

## 触发条件

- 获取到有效的腾讯云临时凭据（SecretId、SecretKey、Token），且未被权限边界完全限制。
- 凭据至少拥有 `cvm:DescribeInstances` 与 `cvm:ResetInstancesPassword`（或等价权限）；`ForceStop` 未被策略禁止。
- 目标账号下存在可重置密码的 CVM，最好是 `Password=null`、`KeyIds=null`、`DefaultLoginUser=root` 的实例。
- 攻击者可访问腾讯云 API 端点（`cvm.tencentcloudapi.com` 等），且凭据未绑定源 IP/设备限制。
- 若要走 COS 链，还需目标 Bucket Policy 的 IP 条件可被已接管主机的 IP 满足。

## 利用步骤

1. 配置临时凭据（`tccli configure` 或 `~/.tccli/default.credential`，包含 `secretId`、`secretKey`、`token`）。
2. `tccli sts GetCallerIdentity` 确认账号、用户/角色、身份类型。
3. `tccli cvm DescribeInstances` 枚举实例，记录 `InstanceId`、公网/内网 IP、`LoginSettings`、`DefaultLoginUser`、`InstanceState`。
4. 筛选 `Password=null`、`KeyIds=null`、`DefaultLoginUser=root` 的实例；记录其公网 IP。
5. 尝试 `tccli cvm StopInstances --InstanceIds '["ins-xxx"]'`；若返回 `UnauthorizedOperation`，改用 Python SDK 调 `ResetInstancesPassword` 并带 `ForceStop: true`。
6. 若重置成功，用新密码 SSH 登录 `root@<public_ip>`，确认权限。
7. 以该主机为跳板，访问同账号的 COS/CAM/其它 CVM；若 Bucket Policy 限制源 IP，从满足条件的主机发起请求再调用 `PutBucketACL` 等。
8. 清理/维持访问（视授权范围），并检查凭据有效期。

## PoC

Python SDK 重置密码（占位凭据，实际使用泄露的 AK/SK/Token）：

```python
import json
from tencentcloud.common.common_client import CommonClient
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile

cred = credential.Credential(
    "AKIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  # 临时 Token
)
http_profile = HttpProfile()
http_profile.endpoint = "cvm.tencentcloudapi.com"
client_profile = ClientProfile()
client_profile.httpProfile = http_profile

params = {
    "InstanceIds": ["ins-xxxxxxxx"],
    "Password": "Aa112211.",   # 满足复杂度要求的新密码
    "UserName": "root",
    "ForceStop": True,          # 关键：无需单独的 StopInstances 权限
}
client = CommonClient("cvm", "2017-03-12", cred, "ap-guangzhou", profile=client_profile)
print(client.call_json("ResetInstancesPassword", params))
```

CLI 对照：

```bash
tccli sts GetCallerIdentity
tccli cvm DescribeInstances
tccli cvm StopInstances --InstanceIds '["ins-xxxxxxxx"]'   # 可能 UnauthorizedOperation
```

```bash
# 重置成功后
ssh root@<public_ip>
```

说明：

- 原文的挑战环境里 `StopInstances` 返回 `UnauthorizedOperation`，作者改用 Python SDK 的 `ResetInstancesPassword` + `ForceStop: true`；文章未展示重置成功响应与 SSH 登录，最终接管未完全验证，因此本卡 confidence 记为 medium。
- 实例 ID、账号、IP、AK/SK/Token 均为环境相关，复现时需替换；不要在真实环境使用非授权凭据。
- 临时 Token 必须与 AK/SK 同时使用，否则签名失败。

## 变体与关联

- 变体：若 `ResetInstancesPassword` 也被拒绝，继续枚举其它 CVM/CAM/COS API（`RunInstances`、`CreateImage`、`ModifyInstancesAttribute`、`AttachKeyPair` 等），寻找可接管或可横向的权限。
- 变体：通过 `PutBucketACL` 把 Bucket 改为公共读写；若策略限制源 IP，先用已接管主机（或同 VPC 主机）的 IP 发起请求，满足 `ip_not_equal`/白名单条件。
- 变体：临时凭据来自实例角色/SSRF 元数据时，先确认角色策略再枚举；参见 [[cloud-metadata-ssrf-imdsv2-token-credential]]。
- 关联：[[cloud-cloud-iam-workload-role-policy-selfcheck]]（拿到角色后自查权限边界）。
- 关联：[[cloud-s3-presigned-url-vpce-bypass]]（对象存储访问控制的另一类绕过）。
- 边界：凭据过期、CAM 权限边界/MFA、`ForceStop` 被显式拒绝、实例已有密码或绑定密钥、源 IP 限制、操作审计告警都会使链路中断。

## 检测与防御

- 检测：`GetCallerIdentity`、`DescribeInstances`、`ResetInstancesPassword`、`StopInstances` 等 API 来自异常 IP/地域/UA；`ResetInstancesPassword` 带 `ForceStop=true`；短时间内在多个实例上枚举；随后出现 root SSH 登录。
- 检测：CAM 策略中出现 `cvm:ResetInstancesPassword` 授予非运维角色；临时凭据被用于与其绑定角色无关的服务；COS `PutBucketACL` 等敏感操作来自新 IP。
- 防御：最小权限，禁止普通角色拥有 `cvm:ResetInstancesPassword`；使用权限边界、MFA、源 IP 限制；临时凭据短时效并绑定角色/会话；开启 CloudAudit/操作审计与告警。
- 防御：为目标实例设置强密码或绑定 SSH 密钥，避免 `Password=null` + `KeyIds=null` + `DefaultLoginUser=root` 的组合；对关键实例开启操作保护。
- 响应：立即轮换/禁用泄露的 AK/SK/Token，排查同账号内所有 CVM/COS/CAM 的异常操作，检查是否有新密码、密钥、后门账号或 ACL 变更。
